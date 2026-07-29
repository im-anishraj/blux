use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result};
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
    pub fn relay_io(&self) -> Result<()> {
        let master_fd = self.master.as_raw_fd();
        let stdin_fd = io::stdin().as_raw_fd();

        let mut buf = [0u8; 4096];

        loop {
            // Use poll(2) to wait for data on either stdin or the PTY master.
            let mut fds = [
                libc::pollfd {
                    fd: stdin_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: master_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };

            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    // Interrupted by signal — retry.
                    continue;
                }
                return Err(err).context("poll failed");
            }

            // stdin → PTY master (user input)
            if fds[0].revents & libc::POLLIN != 0 {
                let mut stdin_file = unsafe { std::fs::File::from_raw_fd(stdin_fd) };
                let n = stdin_file.read(&mut buf);
                // Prevent the File from closing stdin when dropped.
                std::mem::forget(stdin_file);

                match n {
                    Ok(0) => {
                        // stdin EOF — nothing more to send.
                    }
                    Ok(n) => {
                        let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
                        let _ = master_file.write_all(&buf[..n]);
                        std::mem::forget(master_file);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        // stdin error — stop reading from stdin but keep relaying master output.
                    }
                }
            }

            // PTY master → stdout (child output)
            if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
                let n = master_file.read(&mut buf);
                std::mem::forget(master_file);

                match n {
                    Ok(0) | Err(_) => {
                        // Master EOF or error — child has exited.
                        break;
                    }
                    Ok(n) => {
                        let _ = io::stdout().write_all(&buf[..n]);
                        let _ = io::stdout().flush();
                    }
                }
            }

            // Master hung up without POLLIN data.
            if fds[1].revents & libc::POLLHUP != 0 && fds[1].revents & libc::POLLIN == 0 {
                break;
            }
        }

        Ok(())
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
