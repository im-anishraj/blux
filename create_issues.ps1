Remove-Item Env:\GITHUB_TOKEN -ErrorAction SilentlyContinue

gh issue create --title "[CRITICAL] Landlock Sandbox Fails Open for Network Access" --body "**Category:** Security / Architecture`n**Location:** src/enforce.rs:50-53`n**Problem:** If a user defines a policy with an empty allow_ports list, handle_access(net_handled) is skipped.`n**Impact:** Sandbox allows 100% unrestricted network access, defeating security." --label "bug,security"

gh issue create --title "[CRITICAL] Path Traversal and Policy Bypass via String Matching" --body "**Category:** Security`n**Location:** src/policy.rs:101-114 (match_prefix_list)`n**Problem:** Path evaluation uses basic string prefix matching (target.starts_with(allowed)).`n**Impact:** Allows reading /etc_password if /etc is allowed. Also permits path traversal using .." --label "bug,security"

gh issue create --title "[HIGH] Implicit Execution Permissions Granted" --body "**Category:** Security`n**Location:** src/enforce.rs:19`n**Problem:** fs_read_rights removes write and creation permissions, but leaves AccessFs::Execute intact.`n**Impact:** Any directory granted read access automatically grants execute access, allowing malware to run binaries." --label "bug,security"

gh issue create --title "[HIGH] Corrupted IPv6 Address Parsing in Tracer" --body "**Category:** Bug / Observability`n**Location:** src/tracer.rs:209-220 (read_sockaddr_from_memory)`n**Problem:** The bitwise math and memory slicing for parsing sockaddr_in6 is mathematically incorrect.`n**Impact:** Any IPv6 connection caught by --audit logs a corrupted, completely incorrect IP address." --label "bug"

gh issue create --title "[HIGH] Time-of-Check to Time-of-Use (TOCTOU) Evasion" --body "**Category:** Security`n**Location:** src/tracer.rs:151-174 (read_string_from_memory)`n**Problem:** The tracer reads syscall arguments from memory after intercepting the syscall.`n**Impact:** A malicious multi-threaded tracee can alter the memory before the kernel processes it, logging a benign path while opening a malicious one." --label "bug,security"

gh issue create --title "[HIGH] Missing Absolute Path Context for execveat" --body "**Category:** Bug / Observability`n**Location:** src/tracer.rs:127-136`n**Problem:** The tracer ignores the dirfd argument in SYS_execveat.`n**Impact:** The audit log misses the directory context, hiding the true location of the executed binary." --label "bug"

gh issue create --title "[MEDIUM] Inefficient Memory Reading (ptrace::read)" --body "**Category:** Performance`n**Location:** src/tracer.rs:157`n**Problem:** Strings are read out of memory 8 bytes at a time.`n**Impact:** Significant context switching overhead degrades performance of I/O heavy apps. Use process_vm_readv instead." --label "enhancement"

gh issue create --title "[MEDIUM] Thread Leaking in PTY Relay" --body "**Category:** Architecture / Maintainability`n**Location:** src/pty.rs:88`n**Problem:** The relay_io function spawns a detached thread that blocks indefinitely on read(stdin_fd).`n**Impact:** Prevents clean resource teardown and makes the codebase unusable as an embeddable library." --label "bug"

gh issue create --title "[MEDIUM] Missing Error Propagation causes Abrupt Panics" --body "**Category:** Error Handling`n**Location:** src/exec.rs:183`n**Problem:** relay_thread.join().unwrap() panics if the thread panics.`n**Impact:** No cleanup of the child process occurs, leaving zombie processes or a broken terminal state." --label "bug"

gh issue create --title "[MEDIUM] Symlink Evasion in Enforce Mode" --body "**Category:** Security`n**Location:** src/enforce.rs:65-71`n**Problem:** The Landlock ruleset adds raw paths from the policy config.`n**Impact:** An attacker could replace an allowed directory with a symlink to /root, bypassing restrictions." --label "bug,security"
