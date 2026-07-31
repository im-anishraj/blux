use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::libc;
use nix::pty::{self, OpenptyResult};
use nix::sys::termios::{self, SetArg, Termios};
use nix::unistd;

/// Result of PTY allocation: the master/slave pair and the original terminal settings.
pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: Option<OwnedFd>,
    original_termios: Option<Termios>,
}

impl PtyPair {
    /// Allocate a new PTY pair.
    ///
    /// If stdin is a terminal, saves the current terminal settings so they
    /// can be restored on drop.
    pub fn open() -> Result<Self> {
        let OpenptyResult { master, slave } =
            pty::openpty(None, None).context("failed to allocate PTY")?;

        // Securely set O_CLOEXEC to prevent FD leaks across fork/exec boundaries
        fcntl(master.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .context("failed to set O_CLOEXEC on PTY master")?;
        fcntl(slave.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .context("failed to set O_CLOEXEC on PTY slave")?;

        let original_termios = if unistd::isatty(io::stdin().as_raw_fd()).unwrap_or(false) {
            Some(termios::tcgetattr(io::stdin()).context("failed to get terminal attributes")?)
        } else {
            None
        };

        Ok(Self {
            master,
            slave: Some(slave),
            original_termios,
        })
    }

    /// Take ownership of the slave fd. Returns None if already taken.
    pub fn take_slave(&mut self) -> Option<OwnedFd> {
        self.slave.take()
    }

    /// Get the slave fd (borrowed). Panics if already taken.
    pub fn slave_fd(&self) -> &OwnedFd {
        self.slave.as_ref().expect("slave fd already taken")
    }

    /// Put the real terminal into raw mode so keystrokes pass through
    /// to the PTY without interpretation.
    pub fn set_raw_mode(&self) -> Result<()> {
        if self.original_termios.is_some() {
            let mut raw = termios::tcgetattr(io::stdin())
                .context("failed to get terminal attributes for raw mode")?;
            termios::cfmakeraw(&mut raw);
            termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &raw)
                .context("failed to set terminal to raw mode")?;
        }
        Ok(())
    }

    /// Sync the PTY slave's window size with the real terminal.
    pub fn sync_window_size(&self) -> Result<()> {
        let stdin_fd = io::stdin().as_raw_fd();
        if !unistd::isatty(stdin_fd).unwrap_or(false) {
            return Ok(());
        }

        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(stdin_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
                libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws);
            }
        }
        Ok(())
    }

    /// Run the I/O relay loop: shuttle bytes between the real terminal and the
    /// PTY master until the child exits (master returns EOF or error).
    pub fn relay_io(&self) -> Result<std::thread::JoinHandle<()>> {
        let master_fd = self.master.as_raw_fd();
        let stdin_fd = io::stdin().as_raw_fd();

        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();

        // Thread 1: stdin -> PTY master
        let stdin_thread = std::thread::spawn(move || {
            use nix::poll::{PollFd, PollFlags, poll};
            let stdin_borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(stdin_fd) };
            let master_borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(master_fd) };
            let mut buf = [0u8; 4096];
            let mut fds = [PollFd::new(&stdin_borrowed, PollFlags::POLLIN)];

            while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                match poll(&mut fds, 100) {
                    Ok(n) if n > 0 => {
                        match nix::unistd::read(&stdin_borrowed, &mut buf) {
                            Ok(0) => break, // EOF
                            Ok(bytes) => {
                                let mut written = 0;
                                while written < bytes {
                                    match nix::unistd::write(&master_borrowed, &buf[written..bytes])
                                    {
                                        Ok(0) => break,
                                        Ok(w) => written += w,
                                        Err(nix::errno::Errno::EINTR) => continue,
                                        Err(_) => return, // Child PTY closed or error
                                    }
                                }
                            }
                            Err(nix::errno::Errno::EINTR) => continue,
                            Err(_) => break, // Stdin error
                        }
                    }
                    Ok(_) => continue, // Timeout
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(_) => break,
                }
            }
        });

        // Thread 2 (Current Thread): PTY master -> stdout
        let mut buf = [0u8; 4096];
        let master_borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(master_fd) };
        loop {
            match nix::unistd::read(&master_borrowed, &mut buf) {
                Ok(0) => {
                    // EOF — child has exited and closed its end of the PTY
                    break;
                }
                Ok(n) => {
                    let mut stdout = io::stdout();
                    if stdout.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = stdout.flush();
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(nix::errno::Errno::EIO) => {
                    // Linux returns EIO when the slave side of a PTY is closed.
                    break;
                }
                Err(_) => {
                    break; // Other error
                }
            }
        }

        running.store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(stdin_thread)
    }
}

impl Drop for PtyPair {
    fn drop(&mut self) {
        // Restore original terminal settings.
        if let Some(ref original) = self.original_termios {
            let _ = termios::tcsetattr(io::stdin(), SetArg::TCSANOW, original);
        }
    }
}
