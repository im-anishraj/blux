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

        // Only handle network access if we actually want to restrict it
        if !policy.net.allow_ports.is_empty() && !policy.net.allow_ports.contains(&0) {
            ruleset = ruleset.handle_access(net_handled)?;
        }

        let mut ruleset = ruleset.create()?;

        // Apply read rules
        if policy.fs.allow_read.is_empty() || policy.fs.allow_read.contains(&"*".to_string()) {
            // Allow all root (not strictly safe, but handles empty/allow-all case)
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
        if policy.fs.allow_write.is_empty() || policy.fs.allow_write.contains(&"*".to_string()) {
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
                // Kernel doesn't support the required Landlock ABI
                // We should probably log a warning but proceed
                Ok(())
            }
        }
    }

    pub fn apply_seccomp_filter() -> Result<()> {
        use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
        use std::convert::TryInto;

        // Define dangerous syscalls that could be used for sandbox escapes.
        let rules = vec![
            (libc::SYS_ptrace, vec![]),
            (libc::SYS_bpf, vec![]),
            (libc::SYS_unshare, vec![]),
            (libc::SYS_kcmp, vec![]),
            (libc::SYS_process_vm_readv, vec![]),
            (libc::SYS_process_vm_writev, vec![]),
        ];

        let filter: BpfProgram = SeccompFilter::new(
            rules.into_iter().collect(),
            SeccompAction::Allow,       // Default: Allow everything else
            SeccompAction::KillProcess, // Action on match: Kill
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
