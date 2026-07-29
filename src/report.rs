use crate::cli::Format;
use crate::events::Event;
use crate::policy::Policy;
use std::sync::mpsc::Receiver;

pub fn print_report(receiver: Receiver<Event>, format: Format, policy: Policy, verbose: u8) {
    let mut events = Vec::new();
    let mut violations = 0;

    // Consume all events until the channel is closed (parent tracer drops sender)
    while let Ok(event) = receiver.recv() {
        events.push(event);
    }

    match format {
        Format::Json => {
            // For JSON, we might want to attach "is_violation: bool" to each event,
            // but for simplicity we'll just output the raw events for now or wrap them.
            #[derive(serde::Serialize)]
            struct JsonReport<'a> {
                policy_loaded: bool,
                violations: usize,
                events: Vec<JsonEvent<'a>>,
            }
            #[derive(serde::Serialize)]
            struct JsonEvent<'a> {
                is_violation: bool,
                #[serde(flatten)]
                event: &'a Event,
            }

            let mut json_events = Vec::new();
            for event in &events {
                let allowed = policy.evaluate(event);
                if !allowed {
                    violations += 1;
                }
                json_events.push(JsonEvent {
                    is_violation: !allowed,
                    event,
                });
            }

            let report = JsonReport {
                policy_loaded: true,
                violations,
                events: json_events,
            };

            if let Ok(json) = serde_json::to_string_pretty(&report) {
                println!("{}", json);
            }
        }
        Format::Human => {
            println!("\n=== Bulx Audit Report ===");
            if events.is_empty() {
                println!("No significant events recorded.");
                return;
            }

            for event in &events {
                let allowed = policy.evaluate(event);

                if allowed && verbose == 0 {
                    // Hide allowed events unless verbose mode is enabled
                    continue;
                }

                if !allowed {
                    violations += 1;
                }

                let status_label = if allowed { "[OK]      " } else { "[VIOLATION]" };

                match event {
                    Event::FileOpen { path, mode } => {
                        println!("  {} [FILE OPEN]  {} ({})", status_label, path, mode);
                    }
                    Event::FileWrite { path } => {
                        println!("  {} [FILE WRITE] {}", status_label, path);
                    }
                    Event::FileDelete { path } => {
                        println!("  {} [FILE DEL]   {}", status_label, path);
                    }
                    Event::NetConnect { addr, port } => {
                        println!("  {} [NET CONN]   {}:{}", status_label, addr, port);
                    }
                    Event::DnsLookup { domain } => {
                        println!("  {} [DNS]        {}", status_label, domain);
                    }
                    Event::ProcessSpawn { binary, args } => {
                        println!("  {} [PROC SPAWN] {} {:?}", status_label, binary, args);
                    }
                    Event::ProcessExec { binary } => {
                        println!("  {} [PROC EXEC]  {}", status_label, binary);
                    }
                    Event::EnvRead { key } => {
                        println!("  {} [ENV READ]   {}", status_label, key);
                    }
                }
            }

            if violations > 0 {
                println!("-------------------------");
                println!("!! Found {} policy violations !!", violations);
            } else {
                println!("-------------------------");
                println!("No policy violations detected.");
            }

            println!("=========================");
        }
    }
}
