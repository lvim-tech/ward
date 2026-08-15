//! The terminal front-end.
//!
//! Drawn on the device gpg-agent named in `OPTION ttyname`, opened directly — never on
//! stdin or stdout, which belong to the protocol. A pinentry that draws on its own stdout
//! is a pinentry that corrupts the conversation it is having.
//!
//! The hard part here is not drawing; it is putting the terminal back. Raw mode is a
//! property of somebody else's session, and every way out of this module — accepting,
//! cancelling, timing out, being killed — has to pass through the restore. `panic = "abort"`
//! means `Drop` is not a guarantee, which is why the signal handler exists as well.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use crate::secret::Secret;
use crate::server::State;
use crate::ui::{Frontend, Outcome};

/// The terminal to restore, reachable from a signal handler.
///
/// A handler may do almost nothing safely; an atomic load and `tcsetattr` are on the short
/// list of what it may. The saved settings are leaked on purpose — the process is about to
/// end, and freeing them would introduce exactly the race the handler must not have.
static RESTORE_FD: AtomicI32 = AtomicI32::new(-1);
static RESTORE_TERMIOS: AtomicPtr<libc::termios> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn on_signal(sig: libc::c_int) {
    let fd = RESTORE_FD.load(Ordering::SeqCst);
    let t = RESTORE_TERMIOS.load(Ordering::SeqCst);
    if fd >= 0 && !t.is_null() {
        // SAFETY: async-signal-safe, and the pointer was leaked so it cannot have been freed.
        unsafe {
            libc::tcsetattr(fd, libc::TCSAFLUSH, t);
            // Leave the alternate screen so the session comes back as it was.
            // The length comes from the literal: counting it by hand here once wrote a
            // byte past the end of rodata into somebody's terminal.
            const RESTORE_SEQ: &[u8] = b"\x1b[?1049l\x1b[?25h";
            libc::write(
                fd,
                RESTORE_SEQ.as_ptr() as *const libc::c_void,
                RESTORE_SEQ.len(),
            );
        }
    }
    // Re-raising with the default handler makes the exit status honest about what killed us,
    // which matters to whatever is watching the process.
    // SAFETY: restoring the default disposition and re-raising is signal-safe.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

pub struct TtyFrontend {
    fd: RawFd,
    saved: libc::termios,
    raw: bool,
    cols: usize,
}

impl TtyFrontend {
    pub fn open(path: &str) -> io::Result<Self> {
        let c = std::ffi::CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tty name has a NUL"))?;
        // O_NOCTTY: opening somebody's terminal must not make it ours. Acquiring a
        // controlling terminal here would attach this process to a session it has no
        // business joining, and job-control signals meant for that session would arrive.
        // SAFETY: a valid NUL-terminated path.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is open.
        if unsafe { libc::isatty(fd) } != 1 {
            // SAFETY: fd is open and owned here.
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a terminal",
            ));
        }

        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd is a terminal and `saved` is a valid out-parameter.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }

        Ok(TtyFrontend {
            fd,
            saved,
            raw: false,
            cols: window_width(fd),
        })
    }

    fn enter_raw(&mut self) -> io::Result<()> {
        if self.raw {
            return Ok(());
        }
        let mut t = self.saved;
        // Characters arrive unbuffered and unechoed: the echo is ours to draw, because a
        // terminal echoing a passphrase is the failure this whole program is about.
        t.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
        t.c_iflag &= !(libc::IXON | libc::ICRNL | libc::INLCR | libc::BRKINT);
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        // Publish the restore route BEFORE taking the terminal, not after. A signal in
        // between the two would otherwise kill us with the default disposition and leave
        // somebody's session raw and echoless — the exact damage the handler exists to
        // prevent. Publishing early is harmless: `tcsetattr(saved)` on a terminal still in
        // its saved state is a no-op, and the alternate-screen exit is idempotent.
        //
        // The termios block is leaked on purpose (the handler must not see freed memory),
        // but it is leaked once and then reused: a fresh Box per prompt would leak one per
        // GETPIN. Safe to overwrite here because the handler is disarmed between prompts —
        // RESTORE_FD is -1 — and nothing writes it while a prompt is live.
        let leaked = RESTORE_TERMIOS.load(Ordering::SeqCst);
        let leaked = if leaked.is_null() {
            Box::into_raw(Box::new(self.saved))
        } else {
            // SAFETY: leaked by us, never freed, and unreachable by the handler right now.
            unsafe { *leaked = self.saved };
            leaked
        };
        RESTORE_TERMIOS.store(leaked, Ordering::SeqCst);
        RESTORE_FD.store(self.fd, Ordering::SeqCst);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            // SAFETY: installing a handler with a valid function pointer.
            // Through a pointer rather than straight to an integer: a function item has no
            // meaningful integer value of its own, and the direct cast is the one the
            // compiler warns about because it happens to work today.
            unsafe { libc::signal(sig, on_signal as *const () as libc::sighandler_t) };
        }

        // SAFETY: fd is a terminal, `t` is a fully initialised termios.
        if unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &t) } != 0 {
            let e = io::Error::last_os_error();
            RESTORE_FD.store(-1, Ordering::SeqCst);
            return Err(e);
        }
        self.raw = true;

        // The alternate screen means whatever the user was looking at comes back untouched
        // when the prompt is gone, instead of being scrolled away by it.
        self.write(b"\x1b[?1049h\x1b[?25l")?;
        Ok(())
    }

    fn leave_raw(&mut self) {
        if !self.raw {
            return;
        }
        let _ = self.write(b"\x1b[?1049l\x1b[?25h");
        // SAFETY: fd is a terminal and `saved` was read from it.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
        self.raw = false;
        RESTORE_FD.store(-1, Ordering::SeqCst);
    }

    fn write(&self, buf: &[u8]) -> io::Result<()> {
        let mut b = buf;
        while !b.is_empty() {
            // SAFETY: fd is open, pointer and length describe `b`.
            let n = unsafe { libc::write(self.fd, b.as_ptr() as *const libc::c_void, b.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            b = &b[n as usize..];
        }
        Ok(())
    }

    /// Waits for input, honouring the deadline. `Ok(false)` means the time ran out.
    fn wait(&self, deadline: Option<std::time::Instant>) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // Recomputed each time round rather than once before the loop: EINTR restarts
            // the poll, and handing it the full interval again would let a stream of signals
            // (SIGWINCH on every terminal resize) push SETTIMEOUT out indefinitely.
            let timeout_ms = match deadline {
                None => -1,
                Some(d) => {
                    let left = d.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        return Ok(false);
                    }
                    left.as_millis().min(i32::MAX as u128) as i32
                }
            };
            // SAFETY: one valid pollfd.
            let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(n > 0);
        }
    }

    fn read_byte(&self) -> io::Result<Option<u8>> {
        let mut b = 0u8;
        loop {
            // SAFETY: reading one byte into a valid stack slot.
            let n = unsafe { libc::read(self.fd, &mut b as *mut u8 as *mut libc::c_void, 1) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(if n == 0 { None } else { Some(b) });
        }
    }

    /// True when more input is already waiting.
    ///
    /// Used to tell a bare Escape from the start of an arrow key. Both begin with the same
    /// byte, and cancelling a passphrase prompt because somebody pressed Left would be a
    /// small disaster with an obvious cause.
    fn more_pending(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, zero timeout.
        unsafe { libc::poll(&mut pfd, 1, 25) > 0 }
    }

    fn draw(&self, st: &State, entered: usize, repeat: bool, note: Option<&str>) -> io::Result<()> {
        let w = self.cols.clamp(20, 100);
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(b"\x1b[2J\x1b[H");

        let line = |s: &str, out: &mut Vec<u8>| {
            for chunk in wrap(s, w.saturating_sub(4)) {
                out.extend_from_slice(b"  ");
                out.extend_from_slice(chunk.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        };

        out.extend_from_slice(b"\r\n");
        if let Some(t) = st.title.as_deref() {
            line(t, &mut out);
            out.extend_from_slice(b"\r\n");
        }
        if let Some(d) = st.desc.as_deref() {
            line(d, &mut out);
            out.extend_from_slice(b"\r\n");
        }
        // Error and note wrap like everything else. Left raw, a long SETERROR folded
        // wherever the terminal chose and lost the indent the rest of the prompt keeps.
        let coloured = |s: &str, colour: &[u8], out: &mut Vec<u8>| {
            for chunk in wrap(s, w.saturating_sub(4)) {
                out.extend_from_slice(b"  ");
                out.extend_from_slice(colour);
                out.extend_from_slice(chunk.as_bytes());
                out.extend_from_slice(b"\x1b[0m\r\n");
            }
            out.extend_from_slice(b"\r\n");
        };
        if let Some(e) = st.error.as_deref() {
            coloured(e, b"\x1b[31m", &mut out);
        }
        if let Some(n) = note {
            coloured(n, b"\x1b[33m", &mut out);
        }

        let prompt = if repeat {
            st.repeat.as_deref().unwrap_or("Repeat:")
        } else {
            st.prompt.as_deref().unwrap_or("Passphrase:")
        };
        out.extend_from_slice(b"  ");
        out.extend_from_slice(prompt.as_bytes());
        out.extend_from_slice(b" ");

        // One mark per CHARACTER, and the number beside it. That number is the whole point
        // of ward: a mask that counts bytes shows two marks for one Cyrillic keypress, and a
        // passphrase typed in the wrong keyboard layout then looks exactly like a right one.
        // Capped at the same 80 the window front-end caps at, so a long passphrase does not
        // wrap the mask onto the hint line. The COUNT stays exact — it is the part that has
        // to be true.
        for _ in 0..entered.min(80) {
            out.extend_from_slice("•".as_bytes());
        }
        out.extend_from_slice(format!("  \x1b[2m({entered} characters)\x1b[0m\r\n\r\n").as_bytes());

        out.extend_from_slice(b"  \x1b[2menter accept   esc cancel   ctrl-u clear\x1b[0m\r\n");
        self.write(&out)
    }
}

impl Drop for TtyFrontend {
    fn drop(&mut self) {
        self.leave_raw();
        if self.fd >= 0 {
            // SAFETY: the fd was opened here and is not used again.
            unsafe { libc::close(self.fd) };
        }
    }
}

fn window_width(fd: RawFd) -> usize {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a terminal; TIOCGWINSZ writes into `ws`.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        // A terminal that will not say how wide it is gets the width every terminal has.
        80
    }
}

/// Breaks text at character boundaries so a wrapped Cyrillic line does not lose half a
/// letter to the fold.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let width = width.max(8);
    let mut out = Vec::new();
    for para in s.split('\n') {
        let mut cur = String::new();
        for word in para.split_whitespace() {
            if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
                out.push(std::mem::take(&mut cur));
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
        out.push(cur);
    }
    out
}

impl Frontend for TtyFrontend {
    fn getpin(&mut self, st: &State, into: &mut Secret) -> io::Result<Outcome> {
        self.enter_raw()?;
        let deadline = st
            .timeout_secs
            .filter(|s| *s > 0)
            .map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s));

        // A second buffer only when the agent asked for confirmation. It is locked like the
        // first: a "repeat" field holding the passphrase in ordinary memory would undo the
        // point of the one that does not.
        let mut confirm = if st.repeat.is_some() {
            Some(Secret::with_capacity(into.capacity())?)
        } else {
            None
        };

        let mut on_repeat = false;
        let mut note: Option<String> = None;

        loop {
            let entered = if on_repeat {
                confirm.as_ref().map(|c| c.chars()).unwrap_or(0)
            } else {
                into.chars()
            };
            self.draw(st, entered, on_repeat, note.as_deref())?;

            if !self.wait(deadline)? {
                self.leave_raw();
                return Ok(Outcome::Cancelled);
            }
            let Some(b) = self.read_byte()? else {
                // The terminal went away mid-prompt.
                self.leave_raw();
                return Ok(Outcome::Cancelled);
            };

            match b {
                b'\r' | b'\n' => {
                    if on_repeat {
                        let ok = match confirm.as_ref() {
                            // Constant time, because the comparison is between a passphrase
                            // and its confirmation and a timing difference would leak how
                            // much of the two agree.
                            Some(c) => into.eq_constant_time(c),
                            None => true,
                        };
                        if ok {
                            self.leave_raw();
                            return Ok(Outcome::Ok);
                        }
                        note = Some(
                            st.repeat_error
                                .clone()
                                .unwrap_or_else(|| "the two entries do not match".into()),
                        );
                        into.clear();
                        if let Some(c) = confirm.as_mut() {
                            c.clear();
                        }
                        on_repeat = false;
                    } else if confirm.is_some() {
                        on_repeat = true;
                        note = None;
                    } else {
                        self.leave_raw();
                        return Ok(Outcome::Ok);
                    }
                }
                0x03 => {
                    // Ctrl-C. ISIG is off, so it arrives as a byte rather than a signal —
                    // deliberately, because a signal here would race the terminal restore.
                    self.leave_raw();
                    return Ok(Outcome::Cancelled);
                }
                0x1b => {
                    if self.more_pending() {
                        // An escape sequence: a cursor key, a function key. Swallow it
                        // rather than treating the user's Left arrow as a refusal.
                        while self.more_pending() {
                            let _ = self.read_byte()?;
                        }
                    } else {
                        self.leave_raw();
                        return Ok(Outcome::Cancelled);
                    }
                }
                0x7f | 0x08 => {
                    if on_repeat {
                        if let Some(c) = confirm.as_mut() {
                            c.pop_char();
                        }
                    } else {
                        into.pop_char();
                    }
                }
                0x15 => {
                    if on_repeat {
                        if let Some(c) = confirm.as_mut() {
                            c.clear();
                        }
                    } else {
                        into.clear();
                    }
                }
                // Remaining control characters carry no meaning in a passphrase field and
                // would otherwise be stored invisibly.
                b if b < 0x20 => {}
                b => {
                    let target: &mut Secret = if on_repeat {
                        match confirm.as_mut() {
                            Some(c) => c,
                            None => continue,
                        }
                    } else {
                        &mut *into
                    };
                    // `Secret::push` truncates in silence and documents that the front-end
                    // stops before the capacity — this is where that promise is kept. A new
                    // character is only started if even the longest UTF-8 encoding would
                    // fit, so the buffer can never end on half a letter and leave `chars()`
                    // counting one that is not there. Continuation bytes always fit: their
                    // lead byte was only admitted because room for four was checked.
                    let is_lead = b & 0xC0 != 0x80;
                    if !is_lead || target.len() + 4 <= target.capacity() {
                        target.push(&[b]);
                    }
                }
            }
        }
    }

    fn confirm(&mut self, st: &State, one_button: bool) -> io::Result<Outcome> {
        self.enter_raw()?;
        let deadline = st
            .timeout_secs
            .filter(|s| *s > 0)
            .map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s));

        loop {
            let mut out = Vec::with_capacity(512);
            out.extend_from_slice(b"\x1b[2J\x1b[H\r\n");
            if let Some(d) = st.desc.as_deref() {
                for l in wrap(d, self.cols.clamp(20, 100).saturating_sub(4)) {
                    out.extend_from_slice(format!("  {l}\r\n").as_bytes());
                }
            }
            out.extend_from_slice(b"\r\n  \x1b[2m");
            out.extend_from_slice(if one_button {
                b"enter  dismiss".as_slice()
            } else {
                b"y accept   n decline   esc cancel".as_slice()
            });
            out.extend_from_slice(b"\x1b[0m\r\n");
            self.write(&out)?;

            if !self.wait(deadline)? {
                self.leave_raw();
                return Ok(Outcome::Cancelled);
            }
            let Some(b) = self.read_byte()? else {
                self.leave_raw();
                return Ok(Outcome::Cancelled);
            };
            // Escape needs the same care here as in getpin: an arrow key starts with the
            // same byte, and dismissing "Really delete this key?" because somebody nudged
            // Left is the confirm-dialog version of the disaster getpin already guards.
            if b == 0x1b && self.more_pending() {
                while self.more_pending() {
                    let _ = self.read_byte()?;
                }
                continue;
            }
            if one_button {
                // Only a deliberate keystroke dismisses. Accepting ANY byte meant the first
                // byte of an arrow key closed the message before it had been read.
                match b {
                    b'\r' | b'\n' | b' ' | 0x1b => {
                        self.leave_raw();
                        return Ok(Outcome::Ok);
                    }
                    _ => continue,
                }
            }
            match b {
                b'y' | b'Y' | b'\r' | b'\n' => {
                    self.leave_raw();
                    return Ok(Outcome::Ok);
                }
                b'n' | b'N' => {
                    self.leave_raw();
                    return Ok(Outcome::NotOk);
                }
                0x1b | 0x03 => {
                    self.leave_raw();
                    return Ok(Outcome::Cancelled);
                }
                _ => {}
            }
        }
    }

    fn message(&mut self, st: &State) -> io::Result<()> {
        self.confirm(st, true).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::wrap;

    #[test]
    fn wraps_without_splitting_characters() {
        let lines = wrap("една много дълга фраза за пренасяне на редове", 20);
        for l in &lines {
            assert!(l.chars().count() <= 20, "line too long: {l:?}");
            // A split inside a multi-byte character would not survive being a &str at all,
            // so reaching here at all is part of the assertion.
            assert!(l.is_char_boundary(l.len()));
        }
    }

    #[test]
    fn keeps_explicit_line_breaks() {
        assert_eq!(wrap("one\ntwo", 40), vec!["one", "two"]);
    }
}
