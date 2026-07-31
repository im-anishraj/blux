use crate::cli::Format;
use crate::events::Event;
use crate::policy::Policy;
use std::sync::mpsc::Receiver;

#[derive(serde::Serialize)]
struct JsonEvent<'a> {
    is_violation: bool,
    #[serde(flatten)]
    event: &'a Event,
}

/// Consumes and prints events from the tracer.
/// Streams events immediately to avoid unbounded memory growth.
pub fn print_report(receiver: Receiver<Event>, format: Format, policy: Policy, verbose: u8) {
    let mut violations = 0;
    let mut total_events = 0;

    if format == Format::Human {
        eprintln!("\n=== Bulx Audit Report ===");
    }

    let mut json_events = Vec::new();

    // Process each event immediately as it arrives
    while let Ok(event) = receiver.recv() {
        total_events += 1;
        let allowed = policy.evaluate(&event);
        if !allowed {
            violations += 1;
        }

        match format {
            Format::Json => {
                // To preserve exact JSON schema compatibility (including key order and formatting),
                // we must buffer events in memory. This trades bounded memory for backward compatibility.
                json_events.push((event, allowed));
            }
            Format::Human => {
                if allowed && verbose == 0 {
                    continue;
                }

                let status_label = if allowed { "[OK]      " } else { "[VIOLATION]" };

                match &event {
                    Event::FileOpen { path, mode } => {
                        eprintln!("  {} [FILE OPEN]  {} ({})", status_label, path, mode);
                    }
                    Event::FileWrite { path } => {
                        eprintln!("  {} [FILE WRITE] {}", status_label, path);
                    }
                    Event::FileDelete { path } => {
                        eprintln!("  {} [FILE DEL]   {}", status_label, path);
                    }
                    Event::NetConnect { addr, port } => {
                        eprintln!("  {} [NET CONN]   {}:{}", status_label, addr, port);
                    }
                    Event::DnsLookup { domain } => {
                        eprintln!("  {} [DNS]        {}", status_label, domain);
                    }
                    Event::ProcessSpawn { binary, args } => {
                        eprintln!("  {} [PROC SPAWN] {} {:?}", status_label, binary, args);
                    }
                    Event::ProcessExec { binary } => {
                        eprintln!("  {} [PROC EXEC]  {}", status_label, binary);
                    }
                    Event::EnvRead { key } => {
                        eprintln!("  {} [ENV READ]   {}", status_label, key);
                    }
                }
            }
        }
    }

    // Final summary
    if format == Format::Json {
        #[derive(serde::Serialize)]
        struct JsonReport<'a> {
            policy_loaded: bool,
            violations: usize,
            events: Vec<JsonEvent<'a>>,
        }

        let serialized_events: Vec<JsonEvent> = json_events
            .iter()
            .map(|(e, allowed)| JsonEvent {
                is_violation: !allowed,
                event: e,
            })
            .collect();

        let report = JsonReport {
            policy_loaded: true,
            violations,
            events: serialized_events,
        };

        if let Ok(json) = serde_json::to_string_pretty(&report) {
            eprintln!("{}", json);
        }
    } else if format == Format::Human {
        if total_events == 0 {
            eprintln!("No significant events recorded.");
            eprintln!("=========================");
            return;
        }

        if violations > 0 {
            eprintln!("-------------------------");
            eprintln!("!! Found {} policy violations !!", violations);
        } else {
            eprintln!("-------------------------");
            eprintln!("No policy violations detected.");
        }
        eprintln!("=========================");
    }
}
