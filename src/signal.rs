use std::sync::atomic::{AtomicI32, Ordering};

use nix::libc;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::Pid;

/// Stores the child PID for signal forwarding from the handler.
/// -1 means no child is registered yet.
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);

/// Register the child PID so signal handlers can forward signals to it.
pub fn set_child_pid(pid: Pid) {
    CHILD_PID.store(pid.as_raw(), Ordering::SeqCst);
}

/// Install signal handlers that forward termination signals to the child process.
///
/// We forward: SIGINT, SIGTERM, SIGHUP, SIGQUIT.
/// SIGWINCH is handled separately by the PTY module.
///
/// # Safety
/// This installs process-wide signal handlers. Must be called before spawning
/// the child, and only from the main thread.
pub fn install_forwarding_handlers() -> anyhow::Result<()> {
    let action = SigAction::new(
        SigHandler::Handler(forward_signal_handler),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );

    // SAFETY: forward_signal_handler is async-signal-safe (only calls kill()).
    unsafe {
        signal::sigaction(Signal::SIGINT, &action)?;
        signal::sigaction(Signal::SIGTERM, &action)?;
        signal::sigaction(Signal::SIGHUP, &action)?;
        signal::sigaction(Signal::SIGQUIT, &action)?;
    }

    Ok(())
}

/// Async-signal-safe handler: forward the received signal to the child process group.
extern "C" fn forward_signal_handler(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // Send to process group (negative PID) so grandchildren also receive it.
        unsafe {
            libc::kill(-pid, sig);
        }
    }
}
