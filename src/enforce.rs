use crate::policy::Policy;
use anyhow::Result;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use enumflags2::BitFlags;
    use landlock::{
        ABI, Access, AccessFs, AccessNet, NetPort, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus,
    };
    use std::path::Path;

    pub fn apply_sandbox(policy: &Policy) -> Result<()> {
        let abi = ABI::V4; // V4 supports network

        // 1. Map Filesystem Policy
        let mut fs_read_rights = AccessFs::from_all(abi);
        fs_read_rights.remove(AccessFs::WriteFile);
        fs_read_rights.remove(AccessFs::RemoveDir);
        fs_read_rights.remove(AccessFs::RemoveFile);
        fs_read_rights.remove(AccessFs::MakeChar);
        fs_read_rights.remove(AccessFs::MakeDir);
        fs_read_rights.remove(AccessFs::MakeReg);
        fs_read_rights.remove(AccessFs::MakeSock);
        fs_read_rights.remove(AccessFs::MakeFifo);
        fs_read_rights.remove(AccessFs::MakeBlock);
        fs_read_rights.remove(AccessFs::MakeSym);

        let mut fs_write_rights: BitFlags<AccessFs> = BitFlags::EMPTY;
        fs_write_rights |= AccessFs::WriteFile;
        fs_write_rights |= AccessFs::RemoveDir;
        fs_write_rights |= AccessFs::RemoveFile;
        fs_write_rights |= AccessFs::MakeChar;
        fs_write_rights |= AccessFs::MakeDir;
        fs_write_rights |= AccessFs::MakeReg;
        fs_write_rights |= AccessFs::MakeSock;
        fs_write_rights |= AccessFs::MakeFifo;
        fs_write_rights |= AccessFs::MakeBlock;
        fs_write_rights |= AccessFs::MakeSym;

        let fs_handled = AccessFs::from_all(abi);

        // Network Policy
        let net_handled = AccessNet::from_all(abi);

        let mut ruleset = Ruleset::default().handle_access(fs_handled)?;

        // We MUST handle network access to enforce fail-closed security, unless the user explicitly requested allow-all (port 0)
        if !policy.net.allow_ports.contains(&0) {
            ruleset = ruleset.handle_access(net_handled)?;
        }

        let mut ruleset = ruleset.create()?;

        // Apply read rules
        if policy.fs.allow_read.contains(&"*".to_string()) {
            // Allow all root
            ruleset = ruleset.add_rules(landlock::path_beneath_rules(
                [Path::new("/")],
                fs_read_rights,
            ))?;
        } else {
            for path in &policy.fs.allow_read {
                let p = Path::new(path);
                if p.exists() {
                    ruleset =
                        ruleset.add_rules(landlock::path_beneath_rules([p], fs_read_rights))?;
                }
            }
        }

        // Apply write rules
        if policy.fs.allow_write.contains(&"*".to_string()) {
            ruleset = ruleset.add_rules(landlock::path_beneath_rules(
                [Path::new("/")],
                fs_write_rights,
            ))?;
        } else {
            for path in &policy.fs.allow_write {
                let p = Path::new(path);
                if p.exists() {
                    ruleset =
                        ruleset.add_rules(landlock::path_beneath_rules([p], fs_write_rights))?;
                }
            }
        }

        // Network rules (TCP Connect)
        if !policy.net.allow_ports.is_empty() && !policy.net.allow_ports.contains(&0) {
            for &port in &policy.net.allow_ports {
                ruleset = ruleset.add_rule(NetPort::new(port, AccessNet::ConnectTcp))?;
                ruleset = ruleset.add_rule(NetPort::new(port, AccessNet::BindTcp))?;
            }
        }

        // Apply the ruleset to the current thread
        let status = ruleset
            .restrict_self()
            .context("failed to restrict self with Landlock")?;

        match status.ruleset {
            RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => Ok(()),
            RulesetStatus::NotEnforced => {
                anyhow::bail!(
                    "Landlock is not supported by your kernel. Sandbox enforcement failed."
                );
            }
        }
    }

    pub fn apply_seccomp_filter() -> Result<()> {
        use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
        use std::convert::TryInto;

        // An explicit allow-list of standard POSIX syscalls required for typical execution.
        // This is much safer than a block-list (deny-by-default architecture).
        // Dangerous syscalls like ptrace, bpf, unshare, mount, and process_vm_writev are omitted.
        let allow_list = vec![
            libc::SYS_read, libc::SYS_write, libc::SYS_open, libc::SYS_close,
            libc::SYS_stat, libc::SYS_fstat, libc::SYS_lstat, libc::SYS_poll,
            libc::SYS_lseek, libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_munmap,
            libc::SYS_brk, libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn, libc::SYS_ioctl, libc::SYS_pread64,
            libc::SYS_pwrite64, libc::SYS_readv, libc::SYS_writev, libc::SYS_access,
            libc::SYS_pipe, libc::SYS_select, libc::SYS_sched_yield,
            libc::SYS_mremap, libc::SYS_msync, libc::SYS_mincore, libc::SYS_madvise,
            libc::SYS_dup, libc::SYS_dup2, libc::SYS_nanosleep, libc::SYS_getpid,
            libc::SYS_socket, libc::SYS_connect, libc::SYS_accept, libc::SYS_sendto,
            libc::SYS_recvfrom, libc::SYS_sendmsg, libc::SYS_recvmsg, libc::SYS_shutdown,
            libc::SYS_bind, libc::SYS_listen, libc::SYS_getsockname, libc::SYS_getpeername,
            libc::SYS_socketpair, libc::SYS_setsockopt, libc::SYS_getsockopt,
            libc::SYS_clone, libc::SYS_fork, libc::SYS_vfork, libc::SYS_execve, libc::SYS_execveat,
            libc::SYS_exit, libc::SYS_exit_group, libc::SYS_wait4, libc::SYS_kill, libc::SYS_uname,
            libc::SYS_fcntl, libc::SYS_flock, libc::SYS_fsync, libc::SYS_fdatasync,
            libc::SYS_truncate, libc::SYS_ftruncate, libc::SYS_getdents, libc::SYS_getdents64,
            libc::SYS_getcwd, libc::SYS_chdir, libc::SYS_fchdir, libc::SYS_rename,
            libc::SYS_mkdir, libc::SYS_rmdir, libc::SYS_creat, libc::SYS_link,
            libc::SYS_unlink, libc::SYS_symlink, libc::SYS_readlink, libc::SYS_chmod,
            libc::SYS_fchmod, libc::SYS_chown, libc::SYS_fchown, libc::SYS_lchown,
            libc::SYS_umask, libc::SYS_gettimeofday, libc::SYS_getrlimit,
            libc::SYS_getrusage, libc::SYS_sysinfo, libc::SYS_times,
            libc::SYS_getuid, libc::SYS_getgid, libc::SYS_setuid,
            libc::SYS_setgid, libc::SYS_geteuid, libc::SYS_getegid, libc::SYS_setpgid,
            libc::SYS_getppid, libc::SYS_getpgrp, libc::SYS_setsid,
            libc::SYS_rt_sigpending, libc::SYS_rt_sigtimedwait, libc::SYS_rt_sigqueueinfo,
            libc::SYS_sigsuspend, libc::SYS_sigaltstack, libc::SYS_utime,
            libc::SYS_prctl, libc::SYS_arch_prctl, libc::SYS_getrandom,
            libc::SYS_futex, libc::SYS_set_robust_list, libc::SYS_get_robust_list,
            libc::SYS_epoll_create, libc::SYS_epoll_ctl, libc::SYS_epoll_wait,
            libc::SYS_epoll_create1, libc::SYS_epoll_pwait,
            libc::SYS_eventfd2, libc::SYS_pipe2, libc::SYS_dup3,
            libc::SYS_openat, libc::SYS_mkdirat, libc::SYS_mknodat, libc::SYS_fchownat,
            libc::SYS_futimesat, libc::SYS_newfstatat, libc::SYS_unlinkat, libc::SYS_renameat,
            libc::SYS_linkat, libc::SYS_symlinkat, libc::SYS_readlinkat,
            libc::SYS_fchmodat, libc::SYS_faccessat, libc::SYS_set_tid_address,
            libc::SYS_timerfd_create, libc::SYS_timerfd_settime, libc::SYS_timerfd_gettime,
            libc::SYS_statx, libc::SYS_syslog
        ];

        let rules: std::collections::BTreeMap<i64, Vec<seccompiler::SeccompRule>> = allow_list
            .into_iter()
            .map(|sys_no| (sys_no, vec![]))
            .collect();

        let filter: BpfProgram = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32), // Default action: Block and return EPERM
            SeccompAction::Allow,                     // Action on match: Allow
            std::env::consts::ARCH
                .try_into()
                .context("failed to parse arch for seccomp")?,
        )
        .context("failed to create seccomp filter")?
        .try_into()
        .context("failed to compile seccomp filter to BPF")?;

        seccompiler::apply_filter(&filter).context("failed to apply seccomp filter")?;

        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use super::*;

    pub fn apply_sandbox(_policy: &Policy) -> Result<()> {
        anyhow::bail!("Enforce mode is only supported on Linux")
    }

    pub fn apply_seccomp_filter() -> Result<()> {
        anyhow::bail!("Seccomp is only supported on Linux")
    }
}

pub use linux::{apply_sandbox, apply_seccomp_filter};
