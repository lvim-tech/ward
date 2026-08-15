//! The Assuan line protocol: reading commands on fd 0, writing replies on fd 1.
//!
//! Only this module touches those two descriptors. Everything else — including every
//! front-end — is forbidden them, because stdout is the channel gpg-agent is listening on
//! and a stray `println!` from a drawing routine is a protocol violation that looks like a
//! hang. That rule exists because a pinentry once painted a dialog over somebody's editor.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use crate::secret::Secret;

/// Assuan lines are limited to 1000 bytes including the terminator. Anything longer is a
/// broken peer rather than a long value; values that do not fit are split by the sender.
pub const MAX_LINE: usize = 1000;

/// Error codes are `(source << 24) | code`, with `GPG_ERR_SOURCE_PINENTRY = 5`.
///
/// The distinction between the first two matters to the caller and is easy to collapse by
/// accident: "the user declined" and "nobody could be asked" call for different responses,
/// and an agent that cannot tell them apart will eventually treat one as the other.
pub const ERR_CANCELLED: u32 = (5 << 24) | 99; // GPG_ERR_CANCELED
pub const ERR_NOT_CONFIRMED: u32 = (5 << 24) | 114; // GPG_ERR_NOT_CONFIRMED
pub const ERR_NO_PIN_ENTRY: u32 = (5 << 24) | 67; // GPG_ERR_NO_PIN_ENTRY

/// Decodes the percent escaping Assuan uses for values.
///
/// A malformed escape is kept verbatim rather than dropped: this decodes a description
/// string that will be shown to a human, and a stray `%` in somebody's key comment should
/// appear as a `%`, not vanish or abort the prompt.
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    // The protocol carries UTF-8; a peer that sends something else gets replacement
    // characters rather than a refusal to display its own prompt.
    String::from_utf8_lossy(&out).into_owned()
}

/// Escapes one byte for a `D` line, if it needs escaping.
///
/// Only three bytes must be escaped: the escape character itself and the two that would end
/// or split the line. Escaping more would be harmless but would also make the encoding
/// depend on taste rather than on the protocol.
fn escape_byte(b: u8, out: &mut [u8; 3]) -> usize {
    match b {
        b'%' => {
            out[..3].copy_from_slice(b"%25");
            3
        }
        b'\r' => {
            out[..3].copy_from_slice(b"%0D");
            3
        }
        b'\n' => {
            out[..3].copy_from_slice(b"%0A");
            3
        }
        _ => {
            out[0] = b;
            1
        }
    }
}

/// Percent-encodes a string for a reply. For descriptions and status lines, never for the
/// passphrase — that one never becomes a `String` in the first place.
pub fn percent_encode(s: &str) -> String {
    // Built as BYTES and only then declared to be a string. Pushing each byte as a `char`
    // is the obvious version and is wrong: `b as char` means "this byte is a Latin-1 code
    // point", so every byte of a multi-byte character becomes its own character and is
    // re-encoded as two. The result survives ASCII and mangles everything else — which on
    // this project means it survives every test written in English and corrupts the one
    // alphabet the program exists to handle correctly.
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'%' => out.extend_from_slice(b"%25"),
            b'\r' => out.extend_from_slice(b"%0D"),
            b'\n' => out.extend_from_slice(b"%0A"),
            _ => out.push(b),
        }
    }
    // Only whole UTF-8 sequences and ASCII escapes went in, so what comes out is UTF-8.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// The reply channel. Owns fd 1 and nothing else does.
pub struct Writer {
    /// Everything except the passphrase goes through here; the passphrase is written with a
    /// raw `write(2)` so it never enters a buffer this type would have to wipe.
    fd: libc::c_int,
}

impl Writer {
    pub fn stdout() -> Self {
        Writer { fd: 1 }
    }

    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            // SAFETY: fd 1 with a valid pointer and length.
            let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    pub fn ok(&mut self, text: &str) -> io::Result<()> {
        if text.is_empty() {
            self.write_all(b"OK\n")
        } else {
            self.write_all(format!("OK {}\n", percent_encode(text)).as_bytes())
        }
    }

    pub fn err(&mut self, code: u32, text: &str) -> io::Result<()> {
        self.write_all(format!("ERR {} {}\n", code, percent_encode(text)).as_bytes())
    }

    pub fn status(&mut self, text: &str) -> io::Result<()> {
        self.write_all(format!("S {}\n", percent_encode(text)).as_bytes())
    }

    /// A `D` line carrying ordinary data — used for GETINFO answers, never for a secret.
    pub fn data_str(&mut self, text: &str) -> io::Result<()> {
        self.write_all(format!("D {}\n", percent_encode(text)).as_bytes())
    }

    /// Writes the passphrase out, across as many `D` lines as it takes.
    ///
    /// The bytes travel from the locked buffer through a small stack window that is wiped
    /// before returning, straight to the descriptor. There is deliberately no `String`,
    /// no `format!` and no buffered writer anywhere on this path: each of those would take
    /// a copy onto the heap that nothing could erase afterwards, which is precisely the
    /// leak `Secret` exists to prevent, reintroduced at the last step.
    ///
    /// SEVERAL lines, not one, and that is not caution — it is arithmetic. A pinentry must
    /// accept 2048 characters while an Assuan line holds under 1000 bytes, and escaping can
    /// treble a byte. A single `D` line would therefore break on a long passphrase and on
    /// nothing else: it would pass every test written with a short one, and fail on the
    /// person who took the advice to use a long one. The client concatenates consecutive
    /// `D` payloads, so splitting is invisible to it.
    pub fn data_secret(&mut self, secret: &Secret) -> io::Result<()> {
        // Payload per line, chosen well under the limit so the "D " prefix, the newline and
        // a worst-case escape landing on the boundary all still fit.
        const PAYLOAD: usize = 512;

        let mut win = [0u8; PAYLOAD + 3];
        let mut n = 0usize;
        let mut enc = [0u8; 3];

        let result = (|| -> io::Result<()> {
            self.write_all(b"D ")?;
            for &b in secret.as_bytes() {
                let used = escape_byte(b, &mut enc);
                if n + used > PAYLOAD {
                    self.write_all(&win[..n])?;
                    // End this line and open the next; an escape sequence is never split
                    // across the two, because the check above happens before it is placed.
                    self.write_all(b"\nD ")?;
                    n = 0;
                }
                win[n..n + used].copy_from_slice(&enc[..used]);
                n += used;
            }
            if n > 0 {
                self.write_all(&win[..n])?;
            }
            self.write_all(b"\n")
        })();

        // Wiped on every path, including the error one: a failed write is not a reason to
        // leave a fragment of the passphrase on the stack.
        for slot in win.iter_mut() {
            unsafe { std::ptr::write_volatile(slot, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        result
    }
}

/// The command channel. Owns fd 0.
pub struct Reader {
    inner: BufReader<io::Stdin>,
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

impl Reader {
    pub fn new() -> Self {
        Reader {
            inner: BufReader::new(io::stdin()),
        }
    }

    /// Reads one command line, or `None` at end of input.
    ///
    /// End of input is a normal way for this program to finish: the agent closes the pipe
    /// when it no longer needs the prompt, and treating that as an error would fill its log
    /// with noise for something that happens every time.
    pub fn line(&mut self) -> io::Result<Option<String>> {
        let mut buf = String::new();
        // Bounded, because MAX_LINE is what the protocol allows and an unbounded
        // `read_line` grows for as long as the other end keeps sending without a newline.
        // The real peer is gpg-agent and never does that; stdin is reachable by anyone who
        // can start ward, and that is the one worth not trusting.
        let n = (&mut self.inner)
            .take(MAX_LINE as u64 + 1)
            .read_line(&mut buf)?;
        if buf.len() > MAX_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Assuan line longer than the protocol allows",
            ));
        }
        if n == 0 {
            return Ok(None);
        }
        while buf.ends_with('\n') || buf.ends_with('\r') {
            buf.pop();
        }
        Ok(Some(buf))
    }
}

/// A transcript of the conversation, for working out what the agent actually sends.
///
/// Redacting by construction rather than by remembering to: `data_secret` never passes
/// through here, and the one command that could carry a value in the other direction is
/// logged by name only. A debug log that has to be trusted not to contain the passphrase is
/// a debug log nobody can safely enable.
pub struct Transcript {
    out: Option<std::fs::File>,
}

impl Transcript {
    pub fn open(path: Option<&str>) -> Self {
        let out = path.and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                // The passphrase never reaches this file, but SETDESC and SETKEYINFO do:
                // which key, whose UID, how often it is unlocked. Metadata worth keeping off
                // a shared machine's default 0644. Only applies on creation; an existing
                // file keeps whatever the user gave it.
                .mode(0o600)
                .open(p)
                .ok()
        });
        Transcript { out }
    }

    pub fn note(&mut self, direction: &str, line: &str) {
        if let Some(f) = self.out.as_mut() {
            let _ = writeln!(f, "{direction} {line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_escapes_the_protocol_defines() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("100%25"), "100%");
        assert_eq!(percent_decode("one%0Atwo"), "one\ntwo");
    }

    #[test]
    fn decodes_multibyte_utf8_split_across_escapes() {
        // "па" as %-escaped UTF-8: the two halves of each character arrive separately.
        assert_eq!(percent_decode("%D0%BF%D0%B0"), "па");
    }

    #[test]
    fn keeps_a_malformed_escape_rather_than_dropping_it() {
        assert_eq!(percent_decode("50% off"), "50% off");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("trailing%"), "trailing%");
    }

    #[test]
    fn encode_and_decode_round_trip() {
        for s in ["plain", "with %", "with \n newline", "кирилица", "%25%0A"] {
            assert_eq!(percent_decode(&percent_encode(s)), s);
        }
    }

    #[test]
    fn escapes_only_what_must_be_escaped() {
        let mut out = [0u8; 3];
        assert_eq!(escape_byte(b'a', &mut out), 1);
        assert_eq!(escape_byte(b'%', &mut out), 3);
        assert_eq!(&out, b"%25");
        assert_eq!(escape_byte(b'\n', &mut out), 3);
        assert_eq!(&out, b"%0A");
    }
}
