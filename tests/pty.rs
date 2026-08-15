//! The terminal front-end, driven through a pseudo-terminal.
//!
//! No human, no real terminal, no gpg. The test allocates its own pty, tells ward to draw
//! on the slave through `OPTION ttyname`, types into the master, and reads the protocol
//! reply off a pipe. That separation is the whole reason this is testable at all: the
//! prompt goes to the terminal, the answer goes to stdout, and the two never mix.
//!
//! Every child here is started with `--frontend tty` AND with the display variables removed.
//! Both, not either: ward prefers a window whenever one can be opened, so a test run from a
//! desktop session would otherwise put real windows on the developer's screen — which is
//! precisely what happened the first time this file was run after the window existed. The
//! flag states the intent and the scrubbed environment makes it true even if the flag is
//! ever misspelled.
//!
//! This is also the layer that guards the founding bug. `pinentry-curses` counts bytes, so
//! a Cyrillic passphrase draws two marks per keypress; ward counts characters. A test that
//! only ever typed ASCII would pass either way, which is why the alphabet here is not
//! decoration.

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::time::Duration;

struct Pty {
    master: std::fs::File,
    slave_path: String,
}

fn open_pty() -> Pty {
    // SAFETY: the standard posix_openpt / grantpt / unlockpt / ptsname sequence.
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(m), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(m), 0, "unlockpt failed");
        let name = libc::ptsname(m);
        assert!(!name.is_null(), "ptsname failed");
        let slave_path = std::ffi::CStr::from_ptr(name)
            .to_string_lossy()
            .into_owned();
        Pty {
            master: std::fs::File::from(OwnedFd::from_raw_fd(m)),
            slave_path,
        }
    }
}

fn ward_bin() -> String {
    // The integration test binary sits beside the program it tests.
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.push("ward");
    p.to_string_lossy().into_owned()
}

/// Runs one GETPIN conversation: feeds the given keystrokes, returns the protocol replies.
fn getpin_with(keys: &[&[u8]], extra: &str) -> String {
    let mut pty = open_pty();
    let mut child = Command::new(ward_bin())
        .args(["--frontend", "tty"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DISPLAY")
        .spawn()
        .expect("ward did not start");

    let mut sin = child.stdin.take().unwrap();
    let script = format!(
        "OPTION ttyname={}\nSETDESC test\n{}GETPIN\nBYE\n",
        pty.slave_path, extra
    );
    sin.write_all(script.as_bytes()).unwrap();
    sin.flush().unwrap();

    // The prompt has to be up before the keystrokes mean anything.
    std::thread::sleep(Duration::from_millis(250));
    for k in keys {
        pty.master.write_all(k).unwrap();
        pty.master.flush().unwrap();
        std::thread::sleep(Duration::from_millis(60));
    }

    drop(sin);
    let out = child.wait_with_output().expect("ward did not finish");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Runs one conversation with the terminal named by a command-line FLAG rather than by an
/// `OPTION` line, and with a script of the caller's choosing.
fn converse(args: &[&str], script: &str, keys: &[&[u8]]) -> String {
    let mut pty = open_pty();
    let mut argv: Vec<String> = vec!["--frontend".into(), "tty".into()];
    for a in args {
        argv.push(a.replace("{tty}", &pty.slave_path));
    }
    let mut child = Command::new(ward_bin())
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DISPLAY")
        .spawn()
        .expect("ward did not start");

    let mut sin = child.stdin.take().unwrap();
    sin.write_all(script.replace("{tty}", &pty.slave_path).as_bytes())
        .unwrap();
    sin.flush().unwrap();

    std::thread::sleep(Duration::from_millis(250));
    for k in keys {
        pty.master.write_all(k).unwrap();
        pty.master.flush().unwrap();
        std::thread::sleep(Duration::from_millis(60));
    }

    drop(sin);
    let out = child.wait_with_output().expect("ward did not finish");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn an_arrow_key_is_not_a_refusal_in_confirm_either() {
    // The same guard `an_arrow_key_is_not_a_refusal` puts on GETPIN. CONFIRM used to take
    // the first byte of an arrow key as Escape and answer ERR CANCELED, so nudging a cursor
    // key at "Really delete this key?" failed the operation with nobody having decided.
    let replies = converse(
        &[],
        "OPTION ttyname={tty}\nSETDESC really?\nCONFIRM\nBYE\n",
        &[b"\x1b[D", b"y"],
    );
    assert!(
        replies.contains("OK") && !replies.contains("ERR 83886179"),
        "an arrow key cancelled the confirmation: {replies:?}"
    );
}

#[test]
fn escape_still_cancels_a_confirmation() {
    // The other half of the same change: a BARE Escape must still be a refusal, or the fix
    // above would have bought its safety by making the key do nothing at all.
    let replies = converse(
        &[],
        "OPTION ttyname={tty}\nSETDESC really?\nCONFIRM\nBYE\n",
        &[b"\x1b"],
    );
    assert!(
        replies.contains("ERR 83886179"),
        "escape did not cancel the confirmation: {replies:?}"
    );
}

#[test]
fn the_terminal_can_be_named_on_the_command_line() {
    // `--ttyname` is documented in the usage text. It used to be parsed and thrown away, so
    // a caller that passed it instead of sending `OPTION ttyname` got no prompt at all.
    let replies = converse(
        &["--ttyname", "{tty}"],
        "SETDESC test\nGETPIN\nBYE\n",
        &["парола".as_bytes(), b"\r"],
    );
    assert!(
        replies.contains("D парола"),
        "--ttyname did not name the terminal: {replies:?}"
    );
}

#[test]
fn a_cyrillic_passphrase_survives_the_round_trip() {
    // Six characters, twelve bytes. A byte-counting mask would have shown twelve marks;
    // what matters for the protocol is that all twelve bytes come back intact.
    let replies = getpin_with(&["парола".as_bytes(), b"\r"], "");
    assert!(
        replies.contains("D парола"),
        "the passphrase did not come back: {replies:?}"
    );
    assert!(replies.contains("OK closing connection"));
}

#[test]
fn backspace_removes_a_whole_cyrillic_character() {
    // Type four characters, delete one, keep three. Deleting a byte instead would send back
    // a broken sequence — the same off-by-one that the unit test caught in `pop_char`.
    let replies = getpin_with(&["парол".as_bytes(), b"\x7f", b"\r"], "");
    assert!(
        replies.contains("D паро"),
        "backspace did not remove one character: {replies:?}"
    );
}

#[test]
fn escape_cancels_and_says_so_distinctly() {
    let replies = getpin_with(&[b"abc", b"\x1b"], "");
    assert!(
        replies.contains("ERR 83886179"),
        "escape did not cancel: {replies:?}"
    );
}

#[test]
fn an_arrow_key_is_not_a_refusal() {
    // A cursor key starts with the same byte as Escape. Treating it as cancellation would
    // abandon a half-typed passphrase because somebody reached for the wrong key.
    let replies = getpin_with(&[b"ab", b"\x1b[D", b"cd", b"\r"], "");
    assert!(
        replies.contains("D abcd"),
        "an arrow key cancelled the prompt: {replies:?}"
    );
}

#[test]
fn ctrl_u_clears_the_entry() {
    let replies = getpin_with(&[b"wrong", b"\x15", b"right", b"\r"], "");
    assert!(
        replies.contains("D right"),
        "ctrl-u did not clear: {replies:?}"
    );
}

#[test]
fn an_empty_entry_is_an_answer_not_an_error() {
    let replies = getpin_with(&[b"\r"], "");
    assert!(
        !replies.contains("ERR"),
        "an empty passphrase was reported as a failure: {replies:?}"
    );
}

#[test]
fn a_repeated_entry_must_match_and_is_announced() {
    let replies = getpin_with(
        &["тайна".as_bytes(), b"\r", "тайна".as_bytes(), b"\r"],
        "SETREPEAT Repeat:\n",
    );
    assert!(
        replies.contains("S PIN_REPEATED"),
        "the agreement was not announced: {replies:?}"
    );
    assert!(replies.contains("D тайна"), "{replies:?}");
}

#[test]
fn the_terminal_is_given_back_exactly_as_it_was() {
    let pty = open_pty();
    // SAFETY: the slave path names a terminal this test just created.
    let (before, after) = unsafe {
        let c = std::ffi::CString::new(pty.slave_path.clone()).unwrap();
        let fd = libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(fd >= 0);
        let mut before: libc::termios = std::mem::zeroed();
        libc::tcgetattr(fd, &mut before);

        let mut child = Command::new(ward_bin())
            .args(["--frontend", "tty"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .spawn()
            .unwrap();
        let mut sin = child.stdin.take().unwrap();
        writeln!(sin, "OPTION ttyname={}", pty.slave_path).unwrap();
        writeln!(sin, "GETPIN").unwrap();
        sin.flush().unwrap();
        std::thread::sleep(Duration::from_millis(250));

        // Killed mid-prompt, which is the case `Drop` cannot cover: with `panic = "abort"`
        // and a signal arriving, only the handler can put the terminal back.
        libc::kill(child.id() as i32, libc::SIGTERM);
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(150));

        let mut after: libc::termios = std::mem::zeroed();
        libc::tcgetattr(fd, &mut after);
        libc::close(fd);
        (before, after)
    };
    assert_eq!(
        before.c_lflag, after.c_lflag,
        "ward was killed and left the terminal in raw mode"
    );
}

#[test]
fn with_no_display_and_no_terminal_it_refuses_loudly() {
    let mut child = Command::new(ward_bin())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DISPLAY")
        .spawn()
        .unwrap();
    let mut sin = child.stdin.take().unwrap();
    sin.write_all(b"GETPIN\nBYE\n").unwrap();
    drop(sin);
    let mut s = String::new();
    child.stdout.take().unwrap().read_to_string(&mut s).unwrap();
    let _ = child.wait();
    // Not cancellation: nobody declined, there was nowhere to ask.
    assert!(s.contains("ERR 83886147"), "expected a loud refusal: {s:?}");
    assert!(!s.contains("83886179"), "reported as a cancellation: {s:?}");
}
