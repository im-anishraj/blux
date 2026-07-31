use crate::events::Event;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// The `Policy` module handles the parsing and evaluation of security policies.
///
/// It determines whether system calls intercepted during execution are allowed
/// based on the provided configuration.

#[derive(Debug, Deserialize, Default, Clone)]
/// Represents the root configuration of a Blux sandbox policy.
pub struct Policy {
    /// File system access rules
    #[serde(default)]
    pub fs: FsPolicy,
    /// Network connection rules
    #[serde(default)]
    pub net: NetPolicy,
    /// Process spawning and execution rules
    #[serde(default)]
    pub process: ProcessPolicy,
    /// Environment variable access rules
    #[serde(default)]
    pub env: EnvPolicy,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct FsPolicy {
    #[serde(default)]
    pub allow_read: Vec<String>,
    #[serde(default)]
    pub allow_write: Vec<String>,
    #[serde(default)]
    pub allow_execute: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct NetPolicy {
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub allow_ports: Vec<u16>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ProcessPolicy {
    #[serde(default)]
    pub allow_spawn: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct EnvPolicy {
    #[serde(default)]
    pub allow_read: Vec<String>,
}

impl Policy {
    /// Load policy from the given path, or fallback to default bulx.toml if it exists.
    /// If no file exists, returns an allow-all mock policy (for MVP).
    pub fn load(path_opt: Option<&String>) -> Result<Self> {
        let path = match path_opt {
            Some(p) => Path::new(p),
            None => Path::new("bulx.toml"),
        };

        if path.exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read policy file: {}", path.display()))?;
            let policy: Policy = toml::from_str(&content)
                .with_context(|| format!("failed to parse policy file: {}", path.display()))?;
            Ok(policy)
        } else if path_opt.is_some() {
            // Explicit path was provided but doesn't exist
            anyhow::bail!("policy file not found at {}", path.display());
        } else {
            // No explicit path, and default bulx.toml doesn't exist.
            // Secure by default: Return an empty policy (deny-all).
            Ok(Policy::default())
        }
    }

    /// Evaluates an event against the policy. Returns true if allowed, false if it's a violation.
    pub fn evaluate(&self, event: &Event) -> bool {
        match event {
            Event::FileOpen { path, mode } => {
                let check_list = if mode.contains("write") {
                    &self.fs.allow_write
                } else {
                    &self.fs.allow_read
                };
                Self::match_prefix_list(path, check_list)
            }
            Event::FileWrite { path } | Event::FileDelete { path } => {
                Self::match_prefix_list(path, &self.fs.allow_write)
            }
            Event::NetConnect { addr, port } => {
                let host_allowed = Self::match_prefix_list(addr, &self.net.allow_hosts);
                let port_allowed = self.net.allow_ports.contains(&0) // 0 means all
                    || self.net.allow_ports.contains(port);
                host_allowed && port_allowed
            }
            Event::DnsLookup { domain } => Self::match_prefix_list(domain, &self.net.allow_hosts),
            Event::ProcessSpawn { binary, .. } | Event::ProcessExec { binary } => {
                Self::match_prefix_list(binary, &self.process.allow_spawn)
            }
            Event::EnvRead { key } => Self::match_prefix_list(key, &self.env.allow_read),
        }
    }

    fn match_prefix_list(target: &str, list: &[String]) -> bool {
        let target_path = Path::new(target);
        if list.is_empty() {
            return false;
        }
        for allowed in list {
            if allowed == "*" {
                return true;
            }
            let allowed_path = Path::new(allowed);
            if target_path.starts_with(allowed_path) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_prefix_list() {
        let list = vec!["/etc".to_string(), "/usr/lib".to_string()];

        // Exact match
        assert!(Policy::match_prefix_list("/etc", &list));
        // Prefix match
        assert!(Policy::match_prefix_list("/etc/passwd", &list));
        assert!(Policy::match_prefix_list("/usr/lib/libc.so", &list));

        // No match
        assert!(!Policy::match_prefix_list("/var/log", &list));
        assert!(!Policy::match_prefix_list("/usr/bin", &list));
        // Ensure semantic matching, not string prefix matching
        assert!(!Policy::match_prefix_list("/etc_hacked/shadow", &list));
    }

    #[test]
    fn test_evaluate_event() {
        let mut policy = Policy::default();
        policy.fs.allow_read = vec!["/etc".to_string()];
        policy.net.allow_hosts = vec!["1.1.1.1".to_string()];

        let ok_event = Event::FileOpen {
            path: "/etc/passwd".to_string(),
            mode: "read".to_string(),
        };
        let bad_event = Event::FileOpen {
            path: "/root/secret".to_string(),
            mode: "read".to_string(),
        };
        let ok_net = Event::NetConnect {
            addr: "1.1.1.1".to_string(),
            port: 443,
        };
        let bad_net = Event::NetConnect {
            addr: "8.8.8.8".to_string(),
            port: 443,
        };

        assert!(policy.evaluate(&ok_event));
        assert!(!policy.evaluate(&bad_event));
        assert!(policy.evaluate(&ok_net));
        assert!(!policy.evaluate(&bad_net));
    }
}
