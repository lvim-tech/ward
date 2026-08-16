//! Command dispatch: what the agent asks for, and what ward answers.
//!
//! The state here is the pinentry's own idea of the prompt it is about to draw — the
//! description, the labels, the error from the previous attempt. It is accumulated across
//! many commands and consumed by one (`GETPIN`, `CONFIRM`, `MESSAGE`), which is why it is a
//! struct rather than parameters.

use std::collections::HashMap;
use std::io;

use crate::assuan::{
    percent_decode, Reader, Transcript, Writer, ERR_CANCELLED, ERR_NOT_CONFIRMED, ERR_NO_PIN_ENTRY,
};
use crate::secret::Secret;
use crate::ui::{self, Outcome};

/// The buffer every prompt gets. pinentry guarantees callers 2048 characters, and a
/// character can be four bytes, so the mapping is sized once for the worst case rather than
/// grown later — growing means copying, and a copy of a passphrase is what `Secret` exists
/// to prevent.
const PASSPHRASE_CAPACITY: usize = 2048 * 4;

/// Everything the agent has told us about the prompt it wants.
#[derive(Default)]
pub struct State {
    pub desc: Option<String>,
    pub prompt: Option<String>,
    pub title: Option<String>,
    pub error: Option<String>,
    pub ok: Option<String>,
    pub cancel: Option<String>,
    pub notok: Option<String>,
    pub repeat: Option<String>,
    pub repeat_error: Option<String>,
    pub keyinfo: Option<String>,
    pub quality_bar: Option<String>,
    pub timeout_secs: Option<u64>,

    /// `OPTION default-*` values: the agent's translations of the standard button labels,
    /// used when the caller did not set an explicit one.
    pub defaults: HashMap<String, String>,

    /// The client's session environment, arriving as `OPTION putenv=NAME=VALUE`.
    ///
    /// This is the only trustworthy source for `WAYLAND_DISPLAY`, `DISPLAY` and
    /// `PINENTRY_USER_DATA`. ward's own environment is the AGENT's environment, inherited
    /// whenever that daemon happened to start — which may be a login session that has since
    /// ended. Reading the display from there is how a prompt ends up addressed to a screen
    /// that no longer exists.
    pub client_env: HashMap<String, String>,

    pub ttyname: Option<String>,
    pub ttytype: Option<String>,
    pub display: Option<String>,
    pub lc_ctype: Option<String>,
    pub lc_messages: Option<String>,
    pub owner: Option<String>,

    /// True when the agent asked us not to grab the keyboard. Recorded now, honoured by the
    /// X11 front-end later; on Wayland there is nothing to honour, because an ordinary
    /// client cannot grab in the first place.
    pub no_grab: bool,

    /// The agent offers to let a pinentry consult an external password manager. ward records
    /// the offer and never acts on it: it has no cache and never emits `PASSWORD_FROM_CACHE`.
    /// Accepting the option keeps prompts working on agents that treat a refusal as fatal;
    /// what it means here is written down rather than implied.
    pub external_cache_allowed: bool,

    /// The permanent form of the front-end override, from `--frontend` on the
    /// `pinentry-program` line. `PINENTRY_USER_DATA` beats it, because that one can differ
    /// per invocation and a configuration file cannot.
    pub forced_frontend: Option<String>,

    /// `--timeout` from the command line, surviving `RESET`.
    ///
    /// `timeout_secs` is per-request and cleared with the rest of the prompt; a timeout
    /// given on the `pinentry-program` line belongs to the connection, so it is kept here
    /// and put back after every reset. A later `SETTIMEOUT` still overrides it.
    pub default_timeout_secs: Option<u64>,
}

impl State {
    /// Clears what belongs to one request, keeping what belongs to the connection.
    ///
    /// `RESET` means "forget the prompt", not "forget who you are talking to": the options
    /// and the client environment were established once at startup and the agent does not
    /// resend them.
    fn reset_request(&mut self) {
        self.desc = None;
        self.prompt = None;
        self.error = None;
        self.repeat = None;
        self.repeat_error = None;
        self.quality_bar = None;
        self.timeout_secs = self.default_timeout_secs;
    }

    /// Looks a variable up in the client's environment first and ward's own second.
    pub fn env(&self, name: &str) -> Option<String> {
        self.client_env
            .get(name)
            .cloned()
            .or_else(|| std::env::var(name).ok())
    }
}

/// Splits `COMMAND rest` into its two halves.
fn split_command(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        // The remainder starts AT the separator, not one byte past it, and `trim_start`
        // removes the separator itself. `char::is_whitespace` matches U+00A0 and U+2003 as
        // well as the space, and those are two and three bytes: `i + 1` landed inside the
        // character and panicked — with `panic = "abort"` that is the process gone, no `ERR`
        // and no `BYE`, on a line anything able to write to our stdin could send.
        Some(i) => (&line[..i], line[i..].trim_start()),
        None => (line, ""),
    }
}

/// Runs the conversation until the agent says `BYE` or closes the pipe.
pub fn serve(
    reader: &mut Reader,
    writer: &mut Writer,
    log: &mut Transcript,
    initial: State,
) -> io::Result<()> {
    // The agent waits for this before sending anything.
    writer.ok("Pleased to meet you")?;
    log.note("<--", "OK Pleased to meet you");

    // The whole state, not just the front-end override: the command line can carry the
    // display and the terminal too, and callers that pass them as flags rather than as
    // OPTION lines were previously ignored while the help text said otherwise.
    let mut st = initial;

    while let Some(line) = reader.line()? {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        log.note("-->", &line);
        let (cmd, rest) = split_command(&line);
        let upper = cmd.to_ascii_uppercase();

        match upper.as_str() {
            "SETDESC" => {
                st.desc = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETPROMPT" => {
                st.prompt = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETTITLE" => {
                st.title = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETERROR" => {
                st.error = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETOK" => {
                st.ok = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETCANCEL" => {
                st.cancel = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETNOTOK" => {
                st.notok = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETREPEAT" => {
                st.repeat = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETREPEATERROR" => {
                st.repeat_error = Some(percent_decode(rest));
                writer.ok("")?;
            }
            "SETKEYINFO" => {
                st.keyinfo = if rest == "--clear" {
                    None
                } else {
                    Some(rest.to_string())
                };
                writer.ok("")?;
            }
            "SETQUALITYBAR" => {
                // Accepted and never rendered. Drawing it means answering the agent's
                // `INQUIRE QUALITY` with the partial passphrase on every keystroke — real
                // exposure, repeated per character, to colour a bar. Strength advice belongs
                // where the passphrase is chosen, not where it is typed.
                st.quality_bar = Some(percent_decode(rest));
                writer.ok("")?;
            }
            // The agent sends this when it wants any externally cached copy dropped. ward
            // has no cache to drop, so agreeing is the whole of the correct answer — but it
            // is named rather than left to the unknown-command path, which would log a line
            // per prompt about something entirely expected.
            "CLEARPASSPHRASE" => {
                writer.ok("")?;
            }
            "SETQUALITYBAR_TT" | "SETGENPIN" | "SETGENPIN_TT" => {
                writer.ok("")?;
            }
            "SETTIMEOUT" => {
                st.timeout_secs = rest.trim().parse::<u64>().ok();
                writer.ok("")?;
            }
            "OPTION" => {
                handle_option(&mut st, rest);
                writer.ok("")?;
            }
            "GETINFO" => {
                handle_getinfo(&st, writer, rest.trim())?;
            }
            "RESET" => {
                st.reset_request();
                writer.ok("")?;
            }
            "NOP" => {
                writer.ok("")?;
            }
            "MESSAGE" | "CONFIRM" | "GETPIN" => {
                // Choosing the front-end here, per request, rather than once at startup:
                // the options that decide it — the client's display, its tty — arrive after
                // the greeting and can differ between one prompt and the next.
                let mut front = match ui::select(&st) {
                    Ok(f) => f,
                    Err(ui::NoFrontend(why)) => {
                        // Loud, not silent, and distinct from cancellation. "the user
                        // declined" and "nobody could be asked" demand different responses,
                        // and a caller that cannot tell them apart will conflate them —
                        // which is exactly how the previous pinentry failed here: no window,
                        // no terminal, no message, just a GPG operation that did not work.
                        eprintln!("ward: {upper}: {why}");
                        writer.err(ERR_NO_PIN_ENTRY, &why)?;
                        st.error = None;
                        continue;
                    }
                };

                match upper.as_str() {
                    "GETPIN" => {
                        // A buffer that could not be allocated is answered, not died on.
                        // Letting the error out of `serve` killed the process with no reply
                        // at all, which reaches the agent as a broken pipe — the silent
                        // failure this program exists to stop being.
                        let mut secret = match Secret::with_capacity(PASSPHRASE_CAPACITY) {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("ward: no locked buffer: {e}");
                                writer.err(ERR_NO_PIN_ENTRY, "no memory for the passphrase")?;
                                st.error = None;
                                continue;
                            }
                        };
                        if !secret.is_locked() {
                            // Said out loud rather than assumed: without mlock the
                            // passphrase can reach swap, and a program that claims locked
                            // memory it did not get is worse than one that never claimed it.
                            eprintln!("ward: the passphrase buffer is NOT locked in RAM");
                        }
                        // A front-end that fails mid-prompt (its own locked buffer refused,
                        // the terminal went away) is answered too. Propagating out of
                        // `serve` ended the process without a reply on a GETPIN the agent is
                        // still waiting on.
                        let got = match front.getpin(&st, &mut secret) {
                            Ok(o) => o,
                            Err(e) => {
                                eprintln!("ward: the prompt failed: {e}");
                                writer.err(ERR_NO_PIN_ENTRY, "the prompt could not be shown")?;
                                st.error = None;
                                continue;
                            }
                        };
                        match got {
                            Outcome::Ok => {
                                if st.repeat.is_some() {
                                    // The agent needs to know the two entries agreed;
                                    // otherwise it asks the user to repeat again itself.
                                    writer.status("PIN_REPEATED")?;
                                }
                                if secret.is_empty() {
                                    // An empty passphrase is an answer, not a failure: the
                                    // protocol says so, and a key with no passphrase is a
                                    // thing that exists.
                                    writer.ok("")?;
                                } else {
                                    writer.data_secret(&secret)?;
                                    writer.ok("")?;
                                }
                            }
                            Outcome::Unavailable => {
                                writer.err(ERR_NO_PIN_ENTRY, "the display went away")?
                            }
                            _ => writer.err(ERR_CANCELLED, "Operation cancelled")?,
                        }
                    }
                    "CONFIRM" => {
                        let one_button = rest.split_whitespace().any(|w| w == "--one-button");
                        match front.confirm(&st, one_button)? {
                            Outcome::Ok => writer.ok("")?,
                            Outcome::NotOk => writer.err(ERR_NOT_CONFIRMED, "not confirmed")?,
                            Outcome::Unavailable => {
                                writer.err(ERR_NO_PIN_ENTRY, "the display went away")?
                            }
                            Outcome::Cancelled => {
                                writer.err(ERR_CANCELLED, "Operation cancelled")?
                            }
                        }
                    }
                    _ => {
                        front.message(&st)?;
                        writer.ok("")?;
                    }
                }

                // The error belongs to the attempt that just happened; the manual has it
                // reset by the next GETPIN or CONFIRM, and leaving it set would repeat a
                // stale complaint over a fresh prompt.
                st.error = None;
            }
            "BYE" => {
                // The reply is attempted and its failure ignored. gpg-agent sends BYE and
                // closes the pipe without waiting, so the courtesy answer races a closed
                // descriptor and loses about half the time. Treating that as an error put
                // "Broken pipe" in the agent's log after every single prompt — an alarming
                // line for a conversation that ended exactly as intended.
                let _ = writer.ok("closing connection");
                log.note("<--", "OK closing connection");
                return Ok(());
            }
            _ => {
                // The agent grows new verbs across versions and treats some failures as
                // fatal, so an unknown command is answered OK rather than refused: a
                // compatibility yes to something we do not render is harmless, while a no
                // can kill the prompt entirely. Logged so it stays visible instead of
                // silently accumulating.
                eprintln!("ward: unknown command: {cmd}");
                writer.ok("")?;
            }
        }
    }
    Ok(())
}

fn handle_option(st: &mut State, rest: &str) {
    let (name, value) = match rest.split_once('=') {
        Some((n, v)) => (n.trim(), v),
        None => (rest.trim(), ""),
    };
    let name = name.trim_start_matches("--");

    match name {
        "ttyname" => st.ttyname = Some(percent_decode(value)),
        "ttytype" => st.ttytype = Some(percent_decode(value)),
        "display" => st.display = Some(percent_decode(value)),
        "lc-ctype" => st.lc_ctype = Some(percent_decode(value)),
        "lc-messages" => st.lc_messages = Some(percent_decode(value)),
        "owner" => st.owner = Some(percent_decode(value)),
        "grab" => st.no_grab = false,
        "no-grab" => st.no_grab = true,
        "allow-external-password-cache" => st.external_cache_allowed = true,
        // Named so it stops being logged as unknown on every prompt: it points at the
        // agent's socket and exists so a pinentry can touch it to keep the agent alive.
        // ward has nothing to do with it, and saying so once here is better than a log
        // line per passphrase.
        "touch-file" => {}
        "putenv" => {
            // `putenv=NAME=VALUE`, and NAME alone means unset.
            let decoded = percent_decode(value);
            match decoded.split_once('=') {
                Some((k, v)) => {
                    st.client_env.insert(k.to_string(), v.to_string());
                }
                None => {
                    st.client_env.remove(&decoded);
                }
            }
        }
        other if other.starts_with("default-") => {
            st.defaults.insert(other.to_string(), percent_decode(value));
        }
        other => {
            eprintln!("ward: unknown option: {other}");
        }
    }
}

fn handle_getinfo(st: &State, writer: &mut Writer, what: &str) -> io::Result<()> {
    match what {
        "pid" => {
            // SAFETY: getpid takes no arguments and cannot fail.
            let pid = unsafe { libc::getpid() };
            writer.data_str(&pid.to_string())?;
            writer.ok("")
        }
        "version" => {
            writer.data_str(env!("CARGO_PKG_VERSION"))?;
            writer.ok("")
        }
        "flavor" => {
            // The agent logs this. Naming ourselves rather than borrowing another
            // pinentry's flavour keeps its log honest about what actually asked.
            writer.data_str("ward")?;
            writer.ok("")
        }
        "ttyinfo" => {
            let dash = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".to_string());
            let line = format!(
                "{} {} {}",
                dash(&st.ttyname),
                dash(&st.ttytype),
                dash(&st.display)
            );
            writer.data_str(&line)?;
            writer.ok("")
        }
        _ => writer.ok(""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_command_from_its_argument() {
        assert_eq!(split_command("GETPIN"), ("GETPIN", ""));
        assert_eq!(
            split_command("SETDESC hello there"),
            ("SETDESC", "hello there")
        );
        assert_eq!(
            split_command("OPTION  ttyname=/dev/pts/3"),
            ("OPTION", "ttyname=/dev/pts/3")
        );
    }

    #[test]
    fn a_multibyte_space_does_not_split_a_character_in_half() {
        // `char::is_whitespace` matches more than the space, and the ones it matches are not
        // all one byte. Slicing one byte past the separator landed inside U+00A0 and
        // panicked — which under `panic = "abort"` is the process gone with no reply at all,
        // reachable by anything that can write to ward's stdin.
        assert_eq!(split_command("GETPIN\u{00A0}x"), ("GETPIN", "x"));
        assert_eq!(split_command("SETDESC\u{2003}text"), ("SETDESC", "text"));
        assert_eq!(split_command("GETPIN\u{00A0}"), ("GETPIN", ""));
    }

    #[test]
    fn putenv_carries_the_clients_session() {
        let mut st = State::default();
        handle_option(&mut st, "putenv=WAYLAND_DISPLAY=wayland-0");
        assert_eq!(st.client_env.get("WAYLAND_DISPLAY").unwrap(), "wayland-0");
    }

    #[test]
    fn putenv_without_a_value_unsets() {
        let mut st = State::default();
        handle_option(&mut st, "putenv=DISPLAY=:0");
        handle_option(&mut st, "putenv=DISPLAY");
        assert!(!st.client_env.contains_key("DISPLAY"));
    }

    #[test]
    fn client_environment_beats_our_own() {
        let mut st = State::default();
        std::env::set_var("WARD_TEST_VAR", "from-agent-environment");
        assert_eq!(st.env("WARD_TEST_VAR").unwrap(), "from-agent-environment");
        st.client_env
            .insert("WARD_TEST_VAR".into(), "from-client".into());
        assert_eq!(st.env("WARD_TEST_VAR").unwrap(), "from-client");
    }

    #[test]
    fn reset_forgets_the_prompt_but_not_the_connection() {
        let mut st = State::default();
        handle_option(&mut st, "ttyname=/dev/pts/9");
        st.desc = Some("please".into());
        st.error = Some("wrong".into());
        st.reset_request();
        assert!(st.desc.is_none());
        assert!(st.error.is_none());
        assert_eq!(st.ttyname.as_deref(), Some("/dev/pts/9"));
    }
}
