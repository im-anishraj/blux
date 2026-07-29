use anyhow::{Context, Result};
use std::sync::mpsc::SyncSender;

use crate::events::Event;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::libc;
    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::Pid;
    use std::collections::HashMap;

    pub fn setup_child() -> Result<()> {
        ptrace::traceme().context("failed to set PTRACE_TRACEME")?;
        // SIGSTOP to let parent attach
        nix::sys::signal::kill(nix::unistd::getpid(), Signal::SIGSTOP)?;
        Ok(())
    }

    pub fn trace_loop(child: Pid, sender: SyncSender<Event>) -> Result<()> {
        // Wait for the initial SIGSTOP from the child
        waitpid(child, None).context("failed to wait for initial child stop")?;

        // Set ptrace options: TRACESYSGOOD distinguishes normal traps from syscall traps.
        // TRACEFORK, TRACEVFORK, TRACECLONE allows following child processes.
        ptrace::setoptions(
            child,
            ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACECLONE,
        )
        .context("failed to set ptrace options")?;

        let mut in_syscall: HashMap<Pid, bool> = HashMap::new();

        // Start tracing
        ptrace::syscall(child, None).context("failed to resume child")?;

        loop {
            let status = waitpid(None, None).unwrap_or(WaitStatus::StillAlive);

            match status {
                WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
                    in_syscall.remove(&pid);
                    if pid == child {
                        break;
                    }
                }
                WaitStatus::PtraceSyscall(pid) => {
                    let is_entry = !in_syscall.get(&pid).copied().unwrap_or(false);
                    in_syscall.insert(pid, is_entry);

                    if is_entry {
                        if let Ok(regs) = ptrace::getregs(pid) {
                            handle_syscall_entry(pid, &regs, &sender);
                        }
                    }

                    // Resume process to next syscall
                    let _ = ptrace::syscall(pid, None);
                }
                WaitStatus::PtraceEvent(pid, _sig, event) => {
                    // E.g., fork/clone event
                    if event == libc::PTRACE_EVENT_FORK
                        || event == libc::PTRACE_EVENT_CLONE
                        || event == libc::PTRACE_EVENT_VFORK
                    {
                        if let Ok(new_pid_raw) = ptrace::getevent(pid) {
                            let new_pid = Pid::from_raw(new_pid_raw as i32);
                            let _ = sender.send(Event::ProcessSpawn {
                                binary: format!("<pid:{}>", new_pid),
                                args: vec![],
                            });
                        }
                    }
                    let _ = ptrace::syscall(pid, None);
                }
                WaitStatus::Stopped(pid, sig) => {
                    // Forward signal and resume
                    let _ = ptrace::syscall(pid, sig);
                }
                _ => {
                    // Do nothing for other events, just resume if possible, though we might not have a pid.
                    // waitpid(-1) returns specific pids anyway.
                }
            }
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn handle_syscall_entry(pid: Pid, regs: &libc::user_regs_struct, sender: &SyncSender<Event>) {
        let sys_no = regs.orig_rax as i64;

        match sys_no {
            libc::SYS_openat => {
                // int dirfd = regs.rdi, const char *pathname = regs.rsi, int flags = regs.rdx
                if let Ok(path) = read_string_from_memory(pid, regs.rsi as *mut libc::c_void) {
                    let _ = sender.send(Event::FileOpen {
                        path,
                        mode: "read/write".to_string(),
                    });
                }
            }
            libc::SYS_execve | libc::SYS_execveat => {
                // execve: rdi = filename. execveat: rsi = filename.
                let ptr = if sys_no == libc::SYS_execve {
                    regs.rdi
                } else {
                    regs.rsi
                };
                if let Ok(path) = read_string_from_memory(pid, ptr as *mut libc::c_void) {
                    let _ = sender.send(Event::ProcessExec { binary: path });
                }
            }
            _ => {}
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn handle_syscall_entry(
        _pid: Pid,
        _regs: &libc::user_regs_struct,
        _sender: &SyncSender<Event>,
    ) {
        // Not implemented for non-x86_64 yet
    }

    fn read_string_from_memory(pid: Pid, addr: *mut libc::c_void) -> Result<String> {
        let mut res = Vec::new();
        let mut current_addr = addr as usize;

        loop {
            // ptrace::read reads a word (8 bytes on 64-bit)
            let word = ptrace::read(pid, current_addr as *mut libc::c_void)?;
            let bytes = word.to_ne_bytes();

            for &b in &bytes {
                if b == 0 {
                    return String::from_utf8(res).context("invalid utf8");
                }
                res.push(b);
            }

            current_addr += std::mem::size_of::<libc::c_long>();
            if res.len() > 4096 {
                // Max path length safeguard
                break;
            }
        }

        String::from_utf8(res).context("invalid utf8")
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use super::*;
    use nix::unistd::Pid;

    pub fn setup_child() -> Result<()> {
        anyhow::bail!("Audit mode is only supported on Linux")
    }

    pub fn trace_loop(_child: Pid, _sender: SyncSender<Event>) -> Result<()> {
        anyhow::bail!("Audit mode is only supported on Linux")
    }
}

pub use linux::{setup_child, trace_loop};
