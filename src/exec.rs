use std::io;
use std::os::fd::AsRawFd;
use std::process::ExitCode;

use anyhow::{Context, Result};
use nix::libc;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::{self, ForkResult, Pid};

use crate::cli::Cli;
use crate::enforce;
use crate::policy::Policy;
use crate::pty::PtyPair;
use crate::report;
use crate::signal;
use crate::tracer;

/// Execute the given command, transparently proxying all I/O.
///
/// Automatically selects PTY mode (interactive) or pipe mode (non-interactive)
/// based on whether stdin is a terminal.
pub fn run(cli: &Cli) -> Result<ExitCode> {
    if !cli.audit && !cli.enforce {
        anyhow::bail!("You must specify either --audit or --enforce mode.");
    }

    let policy = if cli.audit || cli.enforce {
        Some(Policy::load(cli.policy.as_ref())?)
    } else {
        None
    };

    if unistd::isatty(io::stdin().as_raw_fd()).unwrap_or(false) {
        run_pty(cli, policy)
    } else {
        run_pipe(cli, policy)
    }
}

/// Pipe mode: spawn the child with inherited stdio. Used when stdin is not a TTY
/// (e.g., piped input, CI environments).
fn run_pipe(cli: &Cli, policy: Option<Policy>) -> Result<ExitCode> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let program = &cli.command[0];
    let args = &cli.command[1..];

    signal::install_forwarding_handlers()?;

    let mut cmd = Command::new(program);
    cmd.args(args);

    let audit = cli.audit;
    let enforce = cli.enforce;
    let policy_for_child = policy.clone();

    unsafe {
        cmd.pre_exec(move || {
            // Fix Problem 7: Put child in its own process group so kill(-pid) works
            libc::setpgid(0, 0);

            if enforce {
                if let Some(ref p) = policy_for_child {
                    enforce::apply_sandbox(p)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    enforce::apply_seccomp_filter()
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }
            }
            if audit {
                tracer::setup_child()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            }
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                eprintln!("bulx: command not found: {}", program);
                return Ok(ExitCode::from(127));
            } else {
                return Err(anyhow::anyhow!("failed to execute '{}': {}", program, e));
            }
        }
    };

    let child_pid = Pid::from_raw(child.id() as i32);
    signal::set_child_pid(child_pid);

    if audit {
        let (tx, rx) = std::sync::mpsc::sync_channel(1000);
        let format = cli.format.clone();
        let policy = policy.unwrap();
        let verbose = cli.verbose;

        let report_thread = std::thread::spawn(move || {
            report::print_report(rx, format, policy, verbose);
        });

        tracer::trace_loop(child_pid, tx)?;
        let _ = report_thread.join();

        // Return 0 because waitpid is consumed by trace_loop
        Ok(ExitCode::from(0))
    } else {
        let status = child
            .wait()
            .with_context(|| format!("failed to wait for '{program}'"))?;
        Ok(exit_code_from_status(status))
    }
}

/// PTY mode: allocate a pseudo-terminal, fork, and relay I/O.
/// Used when stdin is a TTY so interactive programs (vim, htop, etc.) work correctly.
fn run_pty(cli: &Cli, policy: Option<Policy>) -> Result<ExitCode> {
    let program = &cli.command[0];
    let args = &cli.command[1..];

    let mut pty = PtyPair::open()?;

    signal::install_forwarding_handlers()?;

    // Fork the process.
    // SAFETY: We are single-threaded at this point (before any thread spawning),
    // and the child immediately calls exec. This satisfies the POSIX requirements
    // for fork safety.
    let fork_result = unsafe { unistd::fork() }.context("fork failed")?;

    match fork_result {
        ForkResult::Child => {
            // Child process: set up the slave PTY as stdin/stdout/stderr, then exec.
            if cli.enforce {
                if let Some(ref p) = policy {
                    let _ = enforce::apply_sandbox(p);
                    let _ = enforce::apply_seccomp_filter();
                }
            }
            if cli.audit {
                let _ = tracer::setup_child();
            }
            child_exec(&pty, program, args);
        }
        ForkResult::Parent { child } => {
            // Parent process: close slave side, relay I/O through master.
            // take_slave() drops the OwnedFd, closing the fd.
            let _ = pty.take_slave();

            signal::set_child_pid(child);

            // Sync initial window size.
            pty.sync_window_size()?;

            // Put terminal into raw mode so keystrokes pass through.
            pty.set_raw_mode()?;

            let audit = cli.audit;
            let format = cli.format.clone();
            let verbose = cli.verbose;

            if audit {
                let (tx, rx) = std::sync::mpsc::sync_channel(1000);
                let policy = policy.unwrap();

                let report_thread = std::thread::spawn(move || {
                    report::print_report(rx, format, policy, verbose);
                });

                // CRITICAL FIX: The thread that calls fork() MUST be the one handling ptrace.
                // We offload the PTY I/O relay loop to a secondary thread so the main thread
                // can safely trace the child process.
                let relay_thread = std::thread::spawn(move || {
                    pty.relay_io()
                });

                // Main thread acts as the tracer
                let trace_res = tracer::trace_loop(child, tx);
                
                let _ = report_thread.join();
                let relay_res = relay_thread.join().unwrap(); // safe, thread doesn't panic

                trace_res?;
                relay_res?;

                Ok(ExitCode::from(0))
            } else {
                // Relay I/O until child exits.
                let _ = pty.relay_io();

                // Wait for child to finish.
                let status = wait::waitpid(child, None)
                    .with_context(|| format!("failed to wait for '{program}'"))?;

                // PtyPair's Drop will restore terminal settings.
                Ok(exit_code_from_wait(status))
            }
        }
    }
}

/// Child side after fork: set up PTY slave as controlling terminal and exec.
///
/// This function does not return — it either execs or exits.
fn child_exec(pty: &PtyPair, program: &str, args: &[String]) -> ! {
    use std::ffi::CString;

    // Create a new session so the child gets its own process group and
    // controlling terminal.
    let _ = unistd::setsid();

    let slave_fd = pty.slave_fd().as_raw_fd();

    // Set the slave PTY as the controlling terminal.
    unsafe {
        libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0);
    }

    // Redirect stdio to the slave PTY.
    let _ = unistd::dup2(slave_fd, 0); // stdin
    let _ = unistd::dup2(slave_fd, 1); // stdout
    let _ = unistd::dup2(slave_fd, 2); // stderr

    // Close the original FDs (master and slave) — they're now duplicated.
    let master_fd = pty.master.as_raw_fd();
    unsafe {
        libc::close(master_fd);
        if slave_fd > 2 {
            libc::close(slave_fd);
        }
    }

    // Build the exec arguments.
    let c_program = CString::new(program.as_bytes()).unwrap_or_else(|_| {
        eprintln!("bulx: invalid command name");
        std::process::exit(127);
    });

    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(c_program.clone());
    for arg in args {
        c_args.push(CString::new(arg.as_bytes()).unwrap_or_else(|_| {
            eprintln!("bulx: invalid argument");
            std::process::exit(127);
        }));
    }

    // Exec — this does not return on success.
    let _ = unistd::execvp(&c_program, &c_args);

    // If exec failed, print an error and exit.
    let err = std::io::Error::last_os_error();
    eprintln!("bulx: failed to execute '{program}': {err}");
    std::process::exit(127);
}

/// Convert a std::process::ExitStatus to an ExitCode.
fn exit_code_from_status(status: std::process::ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;

    if let Some(code) = status.code() {
        ExitCode::from(code as u8)
    } else if let Some(sig) = status.signal() {
        if sig == 31 {
            eprintln!(
                "\n[bulx] 🚨 Sandbox violation detected! Process attempted a blocked syscall and was killed by the kernel."
            );
        }
        ExitCode::from((128 + sig) as u8)
    } else {
        ExitCode::from(1)
    }
}

/// Convert a nix WaitStatus to an ExitCode.
fn exit_code_from_wait(status: WaitStatus) -> ExitCode {
    match status {
        WaitStatus::Exited(_, code) => ExitCode::from(code as u8),
        WaitStatus::Signaled(_, sig, _) => {
            if sig as i32 == 31 {
                eprintln!(
                    "\n[bulx] 🚨 Sandbox violation detected! Process attempted a blocked syscall and was killed by the kernel."
                );
            }
            ExitCode::from((128 + sig as i32) as u8)
        }
        _ => ExitCode::from(1),
    }
}
