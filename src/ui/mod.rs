//! What a front-end is, and how one is chosen.
//!
//! The protocol layer knows nothing about drawing and a front-end knows nothing about
//! Assuan. That seam is what makes both testable: the protocol can be driven with a fake
//! front-end and no terminal, and a front-end can be driven with a hand-built `State` and
//! no protocol.
//!
//! A front-end must never write to stdout. That descriptor is the channel gpg-agent is
//! listening on, and a stray character from a drawing routine is a protocol violation that
//! presents as a hang.

#[cfg(feature = "gui")]
pub mod gui;
pub mod tty;

use crate::secret::Secret;
use crate::server::State;

/// How a prompt ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The user answered. For `getpin`, the buffer holds what they typed — possibly nothing,
    /// which the protocol reports as an `OK` with no data rather than as an error.
    Ok,
    /// The user declined, dismissed the window, or the timeout expired. The manual makes
    /// timeout indistinguishable from cancellation on purpose, so ward does not invent a
    /// distinction the caller could not act on.
    Cancelled,
    /// A three-button `CONFIRM` answered with the middle option.
    NotOk,
    /// The prompt could not be shown at all — the window failed to appear AFTER the probe
    /// had said a display was there. Nobody was asked and nobody declined, so this must not
    /// come back as `Cancelled`: "the user declined" and "nobody could be asked" are
    /// different answers, and the agent acts on the difference.
    Unavailable,
}

pub trait Frontend {
    /// Asks for a passphrase, appending what is typed into `into`.
    ///
    /// The buffer is passed in rather than returned so that it is allocated, locked and
    /// wiped by the caller: a front-end that created its own would be a second place where
    /// the rules about where a passphrase may live have to be got right.
    fn getpin(&mut self, st: &State, into: &mut Secret) -> std::io::Result<Outcome>;

    fn confirm(&mut self, st: &State, one_button: bool) -> std::io::Result<Outcome>;

    fn message(&mut self, st: &State) -> std::io::Result<()>;
}

/// Why no front-end could be built. Carried as text because it goes straight into the `ERR`
/// line and into gpg-agent's log, and a caller staring at a failed decryption deserves to
/// read what was missing rather than a number.
pub struct NoFrontend(pub String);

/// Chooses where to draw.
///
/// The obvious rule — "the agent sent `ttyname`, so use it" — is wrong, and was observed to
/// be wrong. A graphical application launched from a shell inherits `GPG_TTY`, so the agent
/// dutifully forwards a terminal nobody is watching; the prompt then appears on a screen
/// out of view, or worse, over whatever that terminal was showing. A window appearing when
/// the user expected a terminal is merely surprising. So: a display wins whenever one can
/// actually be reached, and only then does the terminal get a turn.
///
/// "Reached" means the socket connects, not that the variable is set. A stale
/// `WAYLAND_DISPLAY` naming a dead socket is exactly how the previous pinentry failed
/// silently, and trusting the variable would reproduce it.
pub fn select(st: &State) -> Result<Box<dyn Frontend>, NoFrontend> {
    // An explicit choice beats every heuristic. `PINENTRY_USER_DATA` is the canonical
    // channel for it: gpg forwards it per client through the agent, so it can differ from
    // one invocation to the next — something no configuration file can do.
    let forced = st
        .env("PINENTRY_USER_DATA")
        .and_then(|v| {
            v.split_whitespace()
                .find_map(|w| w.strip_prefix("ward:").map(str::to_string))
        })
        .or_else(|| st.forced_frontend.clone());

    match forced.as_deref() {
        Some("tty") => return tty_frontend(st).map_err(NoFrontend),
        Some("gui") => return gui_frontend(st).map_err(NoFrontend),
        Some(other) => {
            eprintln!("ward: ignoring unknown front-end request: {other}");
        }
        None => {}
    }

    // The window first, and only then the terminal. Building it is itself the probe: it
    // connects to the compositor or the X server, so a variable naming a socket that no
    // longer exists fails here instead of being believed.
    let window_failure = match gui_frontend(st) {
        Ok(f) => return Ok(f),
        Err(e) => e,
    };
    match tty_frontend(st) {
        Ok(f) => Ok(f),
        // Both halves of the story, because either one alone sends the reader looking in
        // the wrong place: "no terminal" hides that there was no display either.
        Err(tty_failure) => Err(NoFrontend(format!("{window_failure}; {tty_failure}"))),
    }
}

#[cfg(feature = "gui")]
fn gui_frontend(st: &State) -> Result<Box<dyn Frontend>, String> {
    // The display the CLIENT had, not the one this process inherited. ward is started by
    // gpg-agent, a daemon whose environment was fixed whenever it happened to start —
    // possibly in a session that has since ended. Setting these for the duration lets the
    // windowing library find the right server without teaching it about Assuan.
    for key in [
        "WAYLAND_DISPLAY",
        "DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
    ] {
        if let Some(v) = st.client_env.get(key) {
            std::env::set_var(key, v);
        }
    }
    if let Some(d) = st.display.as_deref() {
        std::env::set_var("DISPLAY", d);
    }
    gui::GuiFrontend::new().map(|f| Box::new(f) as Box<dyn Frontend>)
}

#[cfg(not(feature = "gui"))]
fn gui_frontend(_st: &State) -> Result<Box<dyn Frontend>, String> {
    Err("built without the window".to_string())
}

fn tty_frontend(st: &State) -> Result<Box<dyn Frontend>, String> {
    let name = st
        .ttyname
        .clone()
        .ok_or_else(|| "no terminal was named either".to_string())?;
    match tty::TtyFrontend::open(&name) {
        Ok(f) => Ok(Box::new(f)),
        Err(e) => Err(format!("{name} could not be opened: {e}")),
    }
}
