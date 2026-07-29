use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum Event {
    FileOpen { path: String, mode: String },
    FileWrite { path: String },
    FileDelete { path: String },
    NetConnect { addr: String, port: u16 },
    DnsLookup { domain: String },
    ProcessSpawn { binary: String, args: Vec<String> },
    ProcessExec { binary: String },
    EnvRead { key: String },
}
