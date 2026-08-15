//! Closing the two paths by which a passphrase held in memory reaches the disk without
//! anyone deciding it should.
//!
//! Both are real rather than theoretical: this machine writes core dumps to
//! /var/lib/systemd/coredump by default, and a dump of a process holding a passphrase is a
//! plain file with the passphrase in it, readable by root forever after.

/// Applies the process-level hardening and reports what actually took effect.
///
/// It reports rather than returns unit, because a hardening step that silently fails is
/// worse than one that was never attempted: it leaves you believing in a protection you do
/// not have. The caller logs this to stderr, which gpg-agent captures.
///
/// Called as the first statement in `main`, before a `Secret` can exist. PR_SET_DUMPABLE
/// only governs whether another process may attach from that point on; dropping it after a
/// passphrase is already in memory would leave a window in which it could be read.
pub fn harden() -> Vec<&'static str> {
    let mut done = Vec::new();

    // A zero core limit is honoured by the kernel before any handler runs, so it also
    // defeats systemd-coredump: there is nothing to hand over.
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a fully initialised rlimit and RLIMIT_CORE is a valid resource.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) } == 0 {
        done.push("core dumps disabled");
    }

    // PR_SET_DUMPABLE 0 additionally stops another process from attaching with ptrace and
    // reading this one's memory — the same thing a debugger does, and the same thing a
    // curious root does.
    // SAFETY: prctl with PR_SET_DUMPABLE takes one integer argument and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } == 0 {
        done.push("ptrace/dump denied");
    }

    done
}

/// Reports active swap, which is the other path from memory to disk.
///
/// Nothing here can prevent a page from being written to an unencrypted swap device —
/// `mlock` keeps our own pages resident, but says nothing about hibernation, which writes
/// all of memory out by definition. The honest response is to say so rather than to imply a
/// guarantee that does not exist.
pub fn swap_warning() -> Option<String> {
    let text = std::fs::read_to_string("/proc/swaps").ok()?;
    // The first line is the header; anything after it is a live swap device.
    let devices = text
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .count();
    if devices == 0 {
        return None;
    }
    Some(format!(
        "swap is active ({devices} devices) — unless it is encrypted, memory can reach the disk"
    ))
}
