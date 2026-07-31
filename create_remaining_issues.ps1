Remove-Item Env:\GITHUB_TOKEN -ErrorAction SilentlyContinue

gh issue create --title "[CRITICAL] Landlock Sandbox Fails Open for Network Access" --body "**Category:** Security / Architecture`n**Location:** src/enforce.rs:50-53`n**Problem:** If a user defines a policy with an empty allow_ports list, handle_access(net_handled) is skipped.`n**Impact:** Sandbox allows 100% unrestricted network access, defeating security." --label "bug"

gh issue create --title "[CRITICAL] Path Traversal and Policy Bypass via String Matching" --body "**Category:** Security`n**Location:** src/policy.rs:101-114 (match_prefix_list)`n**Problem:** Path evaluation uses basic string prefix matching (target.starts_with(allowed)).`n**Impact:** Allows reading /etc_password if /etc is allowed. Also permits path traversal using .." --label "bug"

gh issue create --title "[HIGH] Implicit Execution Permissions Granted" --body "**Category:** Security`n**Location:** src/enforce.rs:19`n**Problem:** fs_read_rights removes write and creation permissions, but leaves AccessFs::Execute intact.`n**Impact:** Any directory granted read access automatically grants execute access, allowing malware to run binaries." --label "bug"

gh issue create --title "[HIGH] Time-of-Check to Time-of-Use (TOCTOU) Evasion" --body "**Category:** Security`n**Location:** src/tracer.rs:151-174 (read_string_from_memory)`n**Problem:** The tracer reads syscall arguments from memory after intercepting the syscall.`n**Impact:** A malicious multi-threaded tracee can alter the memory before the kernel processes it, logging a benign path while opening a malicious one." --label "bug"

gh issue create --title "[MEDIUM] Symlink Evasion in Enforce Mode" --body "**Category:** Security`n**Location:** src/enforce.rs:65-71`n**Problem:** The Landlock ruleset adds raw paths from the policy config.`n**Impact:** An attacker could replace an allowed directory with a symlink to /root, bypassing restrictions." --label "bug"
