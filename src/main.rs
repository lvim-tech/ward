//! ward — a pinentry that asks and never keeps.
//!
//! gpg-agent runs this program whenever it needs a passphrase, hands it the Assuan protocol
//! on stdin and stdout, and reads back what the human typed. That is the whole job. There
//! is no cache, no file and no keyring: the agent does the remembering, in its own locked
//! memory, and a pinentry that stores anything is a pinentry that leaks.

use std::process::ExitCode;

use ward::{assuan, harden, install, server};

const USAGE: &str = "\
ward — a passphrase prompt for gpg-agent

usage:
  ward [options]        speak the Assuan protocol on stdin/stdout (how gpg-agent runs it)
  ward install          make gpg-agent use ward (--dry-run shows the file first)
  ward --version
  ward --help

options:
  --frontend tty|gui    force a front-end instead of choosing by what is reachable
  --display NAME        as OPTION display
  --ttyname PATH        as OPTION ttyname
  --ttytype NAME        as OPTION ttytype
  --lc-ctype VALUE      as OPTION lc-ctype
  --lc-messages VALUE   as OPTION lc-messages
  --timeout SECONDS     as SETTIMEOUT
  --transcript PATH     append the conversation to PATH; passphrases are never written

ward is not run by hand. Point gpg-agent at it:
  pinentry-program /path/to/ward
in ~/.gnupg/gpg-agent.conf, then: gpg-connect-agent RELOADAGENT /bye
";

fn main() -> ExitCode {
    // First statement, before anything can hold a passphrase. PR_SET_DUMPABLE only governs
    // attachment from the moment it is set, so dropping it later would leave a window in
    // which another process could read what we are holding.
    let hardened = harden::harden();

    let args = std::env::args().skip(1);
    let mut transcript_path: Option<String> = None;
    let mut st = server::State::default();

    let argv: Vec<String> = args.collect();
    if argv.first().map(String::as_str) == Some("install") {
        let dry = argv.iter().any(|a| a == "--dry-run" || a == "--print");
        return match install::run(dry) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("ward install: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let mut args = argv.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--version" | "-V" => {
                println!("ward {}", env!("CARGO_PKG_VERSION"));
                println!("hardening: {}", hardened.join(", "));
                if let Some(w) = harden::swap_warning() {
                    println!("warning: {w}");
                }
                return ExitCode::SUCCESS;
            }
            "--transcript" => transcript_path = args.next(),
            "--frontend" => st.forced_frontend = args.next(),
            // Some callers pass these as flags rather than as OPTION lines. They are wired
            // into the same state the OPTION lines fill, because accepting a flag and then
            // discarding it is worse than rejecting it: the help text promised they worked.
            // A later OPTION or SETTIMEOUT from the agent still wins — it is more recent.
            "--display" => st.display = args.next(),
            "--ttyname" => st.ttyname = args.next(),
            "--ttytype" => st.ttytype = args.next(),
            "--lc-ctype" => st.lc_ctype = args.next(),
            "--lc-messages" => st.lc_messages = args.next(),
            "--timeout" => {
                match args.next().as_deref().map(str::parse::<u64>) {
                    Some(Ok(s)) => {
                        st.default_timeout_secs = Some(s);
                        st.timeout_secs = Some(s);
                    }
                    // Not fatal: a pinentry that dies on a bad flag dies before it can say
                    // why, and gpg-agent shows the user nothing at all.
                    Some(Err(e)) => eprintln!("ward: --timeout is not a number of seconds: {e}"),
                    None => eprintln!("ward: --timeout wants a number of seconds"),
                }
            }
            other => {
                eprintln!("ward: ignoring unknown argument: {other}");
            }
        }
    }

    // gpg-agent captures our stderr into its own log, which is the only place a note like
    // this can usefully go: stdout is the protocol.
    eprintln!("ward: hardening: {}", hardened.join(", "));
    if let Some(w) = harden::swap_warning() {
        eprintln!("ward: {w}");
    }

    let mut reader = assuan::Reader::new();
    let mut writer = assuan::Writer::stdout();
    let mut log = assuan::Transcript::open(transcript_path.as_deref());

    match server::serve(&mut reader, &mut writer, &mut log, st) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ward: {e}");
            ExitCode::FAILURE
        }
    }
}
