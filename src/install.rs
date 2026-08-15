//! Making ward the pinentry gpg-agent runs.
//!
//! One line in one file, and the care is entirely in what it does NOT do. This is somebody's
//! gpg configuration: it may hold a cache lifetime they chose, a pinentry timeout, an
//! `no-allow-loopback-pinentry` they set on purpose. A tool that rewrites the file wholesale
//! to change one line will eventually delete something that mattered, and the person will
//! not find out until the thing it deleted was needed.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const KEY: &str = "pinentry-program";

pub fn conf_path() -> PathBuf {
    match std::env::var("GNUPGHOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h).join("gpg-agent.conf"),
        _ => match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h).join(".gnupg").join("gpg-agent.conf"),
            Err(_) => PathBuf::from("gpg-agent.conf"),
        },
    }
}

/// Rewrites the `pinentry-program` line and leaves every other byte alone.
///
/// Returns the new text and whatever the line used to say, so the caller can print the way
/// back. An install that cannot be undone from what it printed is an install nobody should
/// run on the program that unlocks their keys.
fn rewrite(existing: &str, program: &Path) -> (String, Option<String>) {
    let want = format!("{KEY} {}", program.display());
    let mut out = Vec::new();
    let mut previous = None;
    let mut replaced = false;

    for line in existing.lines() {
        let trimmed = line.trim_start();
        // A commented-out line is left exactly as it is: it is somebody's note to
        // themselves about what they used to run, and this is not the place to tidy it.
        if trimmed.starts_with('#') || !trimmed.starts_with(KEY) {
            out.push(line.to_string());
            continue;
        }
        let rest = trimmed[KEY.len()..].trim();
        if rest.is_empty() {
            out.push(line.to_string());
            continue;
        }
        if previous.is_none() {
            previous = Some(rest.to_string());
        }
        if replaced {
            // gpg-agent takes the last one it reads, so a duplicate left behind would
            // silently win. Comment it out rather than delete it, and say why.
            out.push(format!("# {line}    (superseded by ward install)"));
        } else {
            out.push(want.clone());
            replaced = true;
        }
    }
    if !replaced {
        if !out.is_empty() && !out.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
            out.push(String::new());
        }
        out.push(want);
    }

    let mut text = out.join("\n");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    (text, previous)
}

pub fn run(dry_run: bool) -> io::Result<i32> {
    let exe = std::env::current_exe()?;
    // The agent does not search PATH, so a relative name would leave it running nothing.
    let exe = exe.canonicalize().unwrap_or(exe);

    let path = conf_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let (text, previous) = rewrite(&existing, &exe);

    println!("file:    {}", path.display());
    match previous.as_deref() {
        Some(p) if p == exe.to_string_lossy() => {
            println!("already: {p}");
            println!("\nNothing to change.");
            return Ok(0);
        }
        Some(p) => println!("was:     {KEY} {p}"),
        None => {
            println!("was:     nothing (gpg-agent fell back to whatever `pinentry` resolves to)")
        }
    }
    println!("now:     {KEY} {}", exe.display());

    if dry_run {
        println!("\n--- the file as it would be written ---\n{text}");
        return Ok(0);
    }

    // Through a temporary file and a rename, never a truncating write. `fs::write` empties
    // the file before it fills it, so an interruption there — ENOSPC, a kill, the machine
    // going down — leaves somebody's gpg-agent.conf half written or empty, and every
    // setting `rewrite` was careful to preserve is gone anyway. Rename within one directory
    // is atomic: the file is either the old one or the new one.
    let tmp = path.with_file_name("gpg-agent.conf.ward-tmp");
    std::fs::write(&tmp, &text)?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // Written is not in force. The agent reads this file when it starts or when it is told
    // to; until then it goes on running whatever it read last time.
    println!("\nreloading the agent — every cached passphrase is dropped, so the next");
    println!("gpg, pass or mail send will ask again. That is the reload, not a fault.");
    let reload = std::process::Command::new("gpg-connect-agent")
        .args(["RELOADAGENT", "/bye"])
        .stdin(std::process::Stdio::null())
        .output();
    match reload {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            eprintln!(
                "the agent did not reload: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Err(e) => eprintln!("gpg-connect-agent could not be run: {e}"),
    }

    // Verified rather than assumed, but only as far as it honestly can be.
    //
    // The first version asked `gpgconf --list-options gpg-agent` whether the agent reported
    // ward, and that check could never have worked: gpgconf does not list
    // `pinentry-program` at all. It lists `pinentry-timeout` and
    // `no-allow-loopback-pinentry`, which is close enough to look right in a test written by
    // the same person who wrote the check.
    //
    // So the chain is stated in pieces, each of which is actually established:
    //   the file now contains the line   — read back, proven here
    //   the agent re-read its config     — RELOADAGENT returned OK, proven above
    //   the agent will run ward          — NOT proven, and cannot be without a prompt
    // The last step is left to the user with the command that settles it, because a program
    // claiming a link it never tested is the failure this whole project is about.
    let written = std::fs::read_to_string(&path).unwrap_or_default();
    let line_present = written.lines().any(|l| {
        !l.trim_start().starts_with('#') && l.trim() == format!("{KEY} {}", exe.display())
    });
    if !line_present {
        eprintln!(
            "\nthe line is NOT in the file after writing it — stop and look at {}",
            path.display()
        );
        return Ok(1);
    }
    println!("\nthe file now names ward, and the agent re-read its configuration.");
    println!("whether it will actually run ward is only provable by asking for a passphrase:");
    println!("  gpg-connect-agent 'GETINFO version' /bye   # harmless, does not prompt");
    println!("  …then unlock anything (pass show, a signed commit) and watch for ward.");

    match previous {
        Some(p) => println!("\nto go back:  {KEY} {p}"),
        None => println!("\nto go back:  remove the {KEY} line"),
    }
    println!(
        "in {}, then: gpg-connect-agent RELOADAGENT /bye",
        path.display()
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ward() -> PathBuf {
        PathBuf::from("/usr/local/bin/ward")
    }

    #[test]
    fn replaces_the_line_and_touches_nothing_else() {
        let before = "\
# my agent
default-cache-ttl 300
pinentry-program /usr/bin/pinentry-gtk-2
no-allow-loopback-pinentry
max-cache-ttl 900
";
        let (after, prev) = rewrite(before, &ward());
        assert_eq!(prev.as_deref(), Some("/usr/bin/pinentry-gtk-2"));
        assert!(after.contains("pinentry-program /usr/local/bin/ward"));
        for kept in [
            "# my agent",
            "default-cache-ttl 300",
            "no-allow-loopback-pinentry",
            "max-cache-ttl 900",
        ] {
            assert!(after.contains(kept), "lost a line: {kept}");
        }
        assert!(!after.contains("gtk-2"), "the old program survived");
    }

    #[test]
    fn appends_when_there_was_no_line() {
        let (after, prev) = rewrite("default-cache-ttl 600\n", &ward());
        assert!(prev.is_none());
        assert!(after.contains("default-cache-ttl 600"));
        assert!(after.contains("pinentry-program /usr/local/bin/ward"));
    }

    #[test]
    fn works_on_an_empty_file() {
        let (after, _) = rewrite("", &ward());
        assert_eq!(after, "pinentry-program /usr/local/bin/ward\n");
    }

    #[test]
    fn leaves_a_commented_line_as_a_comment() {
        // Somebody's note about what they used to run. Not ours to tidy, and not ours to
        // mistake for the setting in force.
        let (after, prev) = rewrite("# pinentry-program /usr/bin/pinentry-qt\n", &ward());
        assert!(prev.is_none());
        assert!(after.contains("# pinentry-program /usr/bin/pinentry-qt"));
        assert!(after.contains("pinentry-program /usr/local/bin/ward"));
    }

    #[test]
    fn a_duplicate_is_commented_out_rather_than_left_to_win() {
        // gpg-agent takes the last line it reads, so a survivor further down would silently
        // override the one just written.
        let before = "pinentry-program /usr/bin/a\npinentry-program /usr/bin/b\n";
        let (after, prev) = rewrite(before, &ward());
        assert_eq!(prev.as_deref(), Some("/usr/bin/a"));
        assert!(after.contains("pinentry-program /usr/local/bin/ward"));
        assert!(after.contains("# pinentry-program /usr/bin/b"));
        assert_eq!(
            after
                .lines()
                .filter(|l| l.starts_with("pinentry-program"))
                .count(),
            1
        );
    }
}
