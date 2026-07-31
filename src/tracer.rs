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
        Ok(())
    }

    pub fn trace_loop(child: Pid, sender: SyncSender<Event>) -> Result<()> {
        // Wait for the initial stop (e.g. SIGTRAP from execve) from the child
        let status = waitpid(child, None).context("failed to wait for initial child stop")?;

        if let WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) = status {
            return Ok(());
        }

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
            let status_res = waitpid(None, None);
            if let Err(nix::errno::Errno::ECHILD) = status_res {
                break; // No more children to trace
            }
            let status = status_res.unwrap_or(WaitStatus::StillAlive);

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
                        match ptrace::getregs(pid) {
                            Ok(regs) => {
                                handle_syscall_entry(pid, &regs, &sender);
                            }
                            Err(_) => break,
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
                if let Ok(path) = resolve_at_path(pid, regs.rdi as i32, regs.rsi as *mut libc::c_void) {
                    let _ = sender.send(Event::FileOpen {
                        path,
                        mode: "read/write".to_string(),
                    });
                }
            }
            libc::SYS_unlinkat => {
                if let Ok(path) = resolve_at_path(pid, regs.rdi as i32, regs.rsi as *mut libc::c_void) {
                    let _ = sender.send(Event::FileDelete { path });
                }
            }
            libc::SYS_connect | libc::SYS_bind => {
                let ptr = regs.rsi as *mut libc::c_void;
                if let Some((ip, port)) = read_sockaddr_from_memory(pid, ptr) {
                    let _ = sender.send(Event::NetConnect { addr: ip, port });
                }
            }
            libc::SYS_execve | libc::SYS_execveat => {
                // execve: rdi = filename. execveat: rsi = filename, rdi = dirfd
                let (dirfd, ptr) = if sys_no == libc::SYS_execve {
                    (libc::AT_FDCWD, regs.rdi)
                } else {
                    (regs.rdi as i32, regs.rsi)
                };
                if let Ok(path) = resolve_at_path(pid, dirfd, ptr as *mut libc::c_void) {
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
        use nix::sys::uio::{process_vm_readv, RemoteIoVec};
        use std::io::IoSliceMut;

        let mut buf = vec![0u8; 4096];
        let remote_iov = RemoteIoVec {
            base: addr as usize,
            len: 4096,
        };
        
        let mut local_iov = [IoSliceMut::new(&mut buf)];
        let read_bytes = process_vm_readv(pid, &mut local_iov, &[remote_iov])
            .context("process_vm_readv failed")?;
        
        let end = buf[..read_bytes].iter().position(|&b| b == 0).unwrap_or(read_bytes);
        String::from_utf8(buf[..end].to_vec()).context("invalid utf8")
    }

    fn resolve_at_path(pid: Pid, dirfd: i32, ptr: *mut libc::c_void) -> Result<String> {
        let raw_path = read_string_from_memory(pid, ptr)?;
        if raw_path.starts_with('/') {
            return Ok(raw_path);
        }

        let base_path = if dirfd == libc::AT_FDCWD {
            std::fs::read_link(format!("/proc/{}/cwd", pid))
                .unwrap_or_else(|_| std::path::PathBuf::from("/"))
        } else {
            std::fs::read_link(format!("/proc/{}/fd/{}", pid, dirfd))
                .unwrap_or_else(|_| std::path::PathBuf::from("/"))
        };

        let full_path = base_path.join(raw_path);
        Ok(full_path.to_string_lossy().into_owned())
    }

    fn read_sockaddr_from_memory(pid: Pid, addr: *mut libc::c_void) -> Option<(String, u16)> {
        let word1 = ptrace::read(pid, addr as *mut libc::c_void).ok()?;
        let word2 = ptrace::read(pid, (addr as usize + 8) as *mut libc::c_void).ok()?;

        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&word1.to_ne_bytes());
        bytes[8..16].copy_from_slice(&word2.to_ne_bytes());

        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);

        if family == libc::AF_INET as u16 {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            return Some((ip.to_string(), port));
        } else if family == libc::AF_INET6 as u16 {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let word3 = ptrace::read(pid, (addr as usize + 16) as *mut libc::c_void).ok()?;
            
            let mut ipv6_bytes = [0u8; 16];
            ipv6_bytes[0..8].copy_from_slice(&word2.to_ne_bytes());
            ipv6_bytes[8..16].copy_from_slice(&word3.to_ne_bytes());
            
            let ip = std::net::Ipv6Addr::from(ipv6_bytes);
            return Some((ip.to_string(), port));
        }

        None
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
