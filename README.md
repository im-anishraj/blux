# Bulx

> Execute any command safely.

Bulx is a universal runtime security layer that sits between you and the commands you execute. Instead of scanning packages or looking for known CVEs, Bulx observes, restricts, and analyses runtime behaviour *while* a command is executing.

## Quick Start

```bash
# Run a command in audit mode to see exactly what it's doing
bulx --audit npm install express

# Run a command in enforce mode to block malicious behavior via Landlock & Seccomp
bulx --enforce node index.js
```

## How It Works

Bulx uses a `bulx.toml` file to define what a process is allowed to do.

```toml
[fs]
# Only allow reading from the current directory and system libraries
allow_read = ["./", "/usr/lib", "/lib", "/etc/ld.so.cache"]
# Only allow writing to a local temp folder
allow_write = ["./tmp"]

[net]
# Block all network access except standard HTTPS
allow_ports = [443]

[process]
# Allow spawning common compilers
allow_spawn = ["rustc", "gcc", "clang"]
```

## Testing Malware

Bulx includes mock malware examples to demonstrate its capabilities.

### Node.js Mock Malware
Navigate to `examples/node_malware` and run it without Bulx to see it attempt malicious actions:
```bash
npm start
```

Now, run it with Bulx in enforce mode to see the kernel block the actions:
```bash
bulx --enforce npm start
```

### Python Ransomware Mock
Navigate to `examples/python_ransomware` and run it with Bulx:
```bash
bulx --enforce python malware.py
```

## Installation

```bash
cargo install bulx
```

## Status

🚧 **Early development** — Phase 5 (Landlock enforcement, Seccomp-BPF filtering, and execution tracing).

### Known Limitations (v0.0.1)
- **Linux Only**: Bulx requires a modern Linux kernel with `landlock`, `seccomp`, and `ptrace` support.
- **Single-Threaded Tracer Bottleneck**: Heavy concurrent or multi-threaded workloads will currently serialize at the `waitpid` ptrace loop, reducing concurrency and execution speed.
- **JSON Mode Memory Growth**: When using `--format json`, the audit pipeline buffers events in unbounded memory. Extremely long-running sessions or syscall floods may trigger OOM.
- **Audit TOCTOU Limitations**: Ptrace path extraction relies on reading tracee memory, making audit logging susceptible to Time-Of-Check to Time-Of-Use (TOCTOU) races. *Note: Kernel enforcement via Landlock/Seccomp remains strictly secure against these races.*

## License

Licensed under either of Apache License, Version 2.0 or MIT License.
