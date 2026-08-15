//! The one type that holds a passphrase.
//!
//! Not a `String`, not a `Vec<u8>`, and that is the point. Both may reallocate as they grow,
//! and a reallocation leaves the old bytes somewhere on the heap that nothing can reach to
//! erase. An anonymous mapping is the one region whose address and lifetime this program
//! actually controls: it can be locked against swap, excluded from core dumps, and zeroed on
//! release, and it never moves.
//!
//! Only this module touches passphrase bytes at rest. Front-ends write characters into it;
//! the protocol layer writes them out to a file descriptor. Nothing converts it to a string.

use std::io;
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

pub struct Secret {
    ptr: *mut u8,
    cap: usize,
    len: usize,
    locked: bool,
}

impl Secret {
    /// Allocates a locked buffer.
    ///
    /// The capacity is fixed at creation and never grows, because growing means copying,
    /// and copying is exactly what this type exists to avoid. pinentry guarantees callers
    /// 2048 characters, so the caller sizes for that once.
    pub fn with_capacity(cap: usize) -> io::Result<Self> {
        let cap = cap.max(1);
        // SAFETY: an anonymous private mapping with a non-zero length; no fd is involved.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                cap,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let p = p as *mut u8;

        // mlock keeps the pages resident, so they are never written to swap. The default
        // memlock limit is a few megabytes — ample for one passphrase, and the reason this
        // is a small dedicated buffer rather than an attempt to lock the whole heap, which
        // would simply fail.
        // SAFETY: the mapping was just created with this exact length.
        let locked = unsafe { libc::mlock(p as *mut libc::c_void, cap) } == 0;

        // Excluded from any core dump that still happens despite RLIMIT_CORE.
        // SAFETY: same mapping and length.
        unsafe { libc::madvise(p as *mut libc::c_void, cap, libc::MADV_DONTDUMP) };

        Ok(Secret {
            ptr: p,
            cap,
            len: 0,
            locked,
        })
    }

    /// Whether the buffer is actually pinned in RAM. False is worth surfacing: it means the
    /// memlock limit refused, and swap can reach the passphrase after all.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Appends bytes, silently ignoring anything past the capacity.
    ///
    /// Silence is deliberate at this layer: the front-end knows the capacity and stops
    /// accepting input before it is reached, so a truncation here would mean a bug rather
    /// than a user typing too much, and returning an error the caller could not act on
    /// would only move the bug somewhere quieter.
    pub fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.len >= self.cap {
                return;
            }
            // SAFETY: len < cap, so the offset is inside the mapping.
            unsafe { ptr::write(self.ptr.add(self.len), b) };
            self.len += 1;
        }
    }

    /// Removes the last CHARACTER, not the last byte.
    ///
    /// A Cyrillic letter is two bytes in UTF-8; deleting one of them would leave half a
    /// character behind and desynchronise every count that follows. This is the same lesson
    /// the mask enforces from the other direction.
    pub fn pop_char(&mut self) {
        if self.len == 0 {
            return;
        }
        // Step back over the continuation bytes to the lead byte, zeroing as we go, then
        // remove the lead byte itself. Checking the byte BEFORE the cursor instead of the
        // one at it stops one byte short and leaves a dangling lead byte behind — half a
        // character, which then counts as a whole one and desynchronises the mask from what
        // was actually typed.
        self.len -= 1;
        // SAFETY: len stays within the mapping throughout.
        unsafe {
            while self.len > 0 && (*self.ptr.add(self.len)) & 0xC0 == 0x80 {
                ptr::write(self.ptr.add(self.len), 0);
                self.len -= 1;
            }
            ptr::write(self.ptr.add(self.len), 0);
        }
    }

    /// The number of CHARACTERS held.
    ///
    /// This is the number the mask displays, and it is the whole reason ward exists.
    /// `pinentry-curses` shows one asterisk per byte, so a Cyrillic passphrase draws two
    /// asterisks per keypress and a wrong keyboard layout looks exactly like a right one.
    /// That silence hid a forgotten passphrase for three years and cost a password store.
    pub fn chars(&self) -> usize {
        self.as_bytes()
            .iter()
            .filter(|&&b| b & 0xC0 != 0x80)
            .count()
    }

    /// The number of bytes held. For the protocol layer, not for the mask.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Borrows the raw bytes. Crate-visible on purpose: this is the seam where the value
    /// could escape, so it is kept where the whole of it can be read in one sitting.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        // SAFETY: the first `len` bytes of the mapping are initialised.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Compares two buffers without letting the time taken say how far they agree.
    ///
    /// This compares a passphrase against its confirmation. An early return on the first
    /// differing byte would leak the length of the common prefix through timing — small,
    /// but free to avoid, and the sort of thing that is never added later.
    pub fn eq_constant_time(&self, other: &Secret) -> bool {
        let a = self.as_bytes();
        let b = other.as_bytes();
        let mut diff = (a.len() ^ b.len()) as u8;
        let n = a.len().min(b.len());
        for i in 0..n {
            diff |= a[i] ^ b[i];
        }
        diff == 0 && a.len() == b.len()
    }

    /// Wipes the contents without releasing the buffer. Used between retry attempts: the
    /// agent re-runs GETPIN after a wrong passphrase, and the previous one must not survive
    /// into the next prompt.
    pub fn clear(&mut self) {
        wipe(self.ptr, self.cap);
        self.len = 0;
    }
}

/// Overwrites a region and stops the compiler from deciding the writes are pointless.
///
/// A plain loop assigning zeroes to memory that is about to be unmapped is dead code by any
/// reasonable analysis, and at `opt-level = "s"` a reasonable analysis is exactly what
/// happens: the memset the programmer believed in is deleted. `write_volatile` may not be
/// elided, and the fence keeps it from being reordered past the release that follows. This
/// five-line function is the entire value `zeroize` would add, which is why ward does not
/// take the dependency.
fn wipe(p: *mut u8, n: usize) {
    for i in 0..n {
        // SAFETY: the caller guarantees `n` bytes are mapped at `p`.
        unsafe { ptr::write_volatile(p.add(i), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(self.ptr, self.cap);
        // SAFETY: the mapping was created here with this length and is not aliased.
        unsafe {
            if self.locked {
                libc::munlock(self.ptr as *mut libc::c_void, self.cap);
            }
            libc::munmap(self.ptr as *mut libc::c_void, self.cap);
        }
        self.ptr = ptr::null_mut();
        self.len = 0;
        self.cap = 0;
    }
}

// The buffer is owned exclusively and never shared; the raw pointer is the only reason the
// automatic implementations do not apply.
unsafe impl Send for Secret {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_characters_not_bytes() {
        let mut s = Secret::with_capacity(64).unwrap();
        // Six Cyrillic characters, twelve bytes. A byte-counting mask would show twelve
        // asterisks for six keypresses — the failure that started this project.
        s.push("парола".as_bytes());
        assert_eq!(s.len(), 12);
        assert_eq!(s.chars(), 6);
    }

    #[test]
    fn backspace_removes_a_whole_character() {
        let mut s = Secret::with_capacity(64).unwrap();
        s.push("абв".as_bytes());
        s.pop_char();
        assert_eq!(s.chars(), 2);
        assert_eq!(s.as_bytes(), "аб".as_bytes());
    }

    #[test]
    fn backspace_on_empty_is_harmless() {
        let mut s = Secret::with_capacity(8).unwrap();
        s.pop_char();
        assert!(s.is_empty());
    }

    #[test]
    fn refuses_to_grow_past_capacity() {
        let mut s = Secret::with_capacity(4).unwrap();
        s.push(b"abcdefgh");
        assert_eq!(s.len(), 4);
        assert_eq!(s.as_bytes(), b"abcd");
    }

    #[test]
    fn clear_leaves_zeros_behind() {
        let mut s = Secret::with_capacity(16).unwrap();
        s.push(b"hunter2");
        let p = s.ptr;
        let cap = s.cap;
        s.clear();
        assert!(s.is_empty());
        // SAFETY: still mapped; `s` is alive until the end of the test.
        let raw = unsafe { std::slice::from_raw_parts(p, cap) };
        assert!(raw.iter().all(|&b| b == 0), "wipe left bytes behind");
    }
}
