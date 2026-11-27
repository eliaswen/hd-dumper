//! Progress reporting. The library reports through [`Progress`]; the CLI uses
//! [`Console`], and an app can forward the same calls to its own UI.

use std::io::{IsTerminal, Write};

/// Receives progress from [`crate::dump`]. Every method has a no-op default.
pub trait Progress {
    /// A status line, e.g. `Scanning libg.so for the data-type registry ...`.
    fn message(&mut self, _message: &str) {}
    /// `done` of `total` APK data entries are read; `name` is the current one.
    fn entry(&mut self, _done: usize, _total: usize, _name: &str) {}
}

/// Discards all progress.
pub struct Silent;

impl Progress for Silent {}

/// Status lines on stderr, with a live one-line counter while the APK's data
/// entries are read when stderr is a terminal that understands ANSI escapes
/// (on Windows, the console is switched to virtual-terminal mode first).
pub struct Console {
    live: bool,
    drawn: bool,
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Console {
    pub fn new() -> Self {
        Self {
            live: std::io::stderr().is_terminal() && enable_ansi(),
            drawn: false,
        }
    }
}

impl Progress for Console {
    fn message(&mut self, message: &str) {
        if self.drawn {
            eprintln!();
            self.drawn = false;
        }
        eprintln!("{message}");
    }

    fn entry(&mut self, done: usize, total: usize, name: &str) {
        if !self.live || (!done.is_multiple_of(16) && done != total) {
            return;
        }
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\r\x1b[2KReading assets/data [{done}/{total}] {name}");
        let _ = err.flush();
        self.drawn = true;
    }
}

/// Turn on ANSI escape processing for stderr. Always true off Windows.
#[cfg(windows)]
fn enable_ansi() -> bool {
    use windows_sys::Win32::System::Console::{
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE,
        SetConsoleMode,
    };
    // SAFETY: plain Win32 calls on the process's own standard handle.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_ansi() -> bool {
    true
}
