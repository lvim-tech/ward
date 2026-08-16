# ward

A passphrase prompt for `gpg-agent`, and nothing else.

In a lock, the *wards* are the obstructions the wrong key cannot pass. That is what this
is: the thing standing between a key and the secrets it opens, whose only job is to ask.

It exists because on this machine no installed pinentry was both usable and safe. The
terminal ones cannot draw when a program is launched from a menu rather than a shell;
every graphical one links `libsecret`, so it can offer to hand the passphrase to an OS
keyring — which turns the master password of a password store into something guarded by
the login password instead of by memory.

## What it will not do

- **Keep anything.** No cache, no file, no keyring, no `libsecret`. gpg-agent does the
  caching, in its own locked memory; a pinentry that stores is a pinentry that leaks.
- **Count bytes.** A masked field that counts bytes shows two asterisks for one Cyrillic
  character and stays silent while a wrong keyboard layout turns a passphrase into
  something else. That failure hid a forgotten passphrase for three years and cost a
  password store. This one counts characters and says how many.

## Install

```sh
cargo build --release
./target/release/ward install       # add --dry-run to see the file first
```

`ward install` writes a single `pinentry-program` line into `~/.gnupg/gpg-agent.conf`
and reloads the agent. It rewrites that one line and leaves every other byte alone — a
cache lifetime, a timeout, a `no-allow-loopback-pinentry` set on purpose all survive —
and it writes through a temporary file and a rename, never a truncating write, so a
crash mid-write cannot leave the config empty. Put the binary where it will live first
(e.g. `~/.local/bin/ward`) and install from there; the line records that path.

## Usage

```
ward                 speak the Assuan protocol on stdin/stdout (how gpg-agent runs it)
ward install         make gpg-agent use ward   (--dry-run / --print shows the file first)
ward --version
ward --help
```

You never run `ward` yourself for a real prompt — gpg-agent spawns it when something
(`gpg`, `pass`, a signed commit, a mail send) needs a passphrase and none is cached. It
appears only when there is something to ask: a key with no passphrase never summons it.

```
--frontend tty|gui   force a front-end instead of choosing by what is reachable
```

## How it works

**The protocol.** gpg-agent talks to a pinentry over Assuan on stdin/stdout —
`SETDESC`, `SETPROMPT`, `GETPIN`, `CONFIRM`, `BYE`. ward answers exactly that and stores
nothing between calls. The agent starts a process per operation and ends it, and within
one it may ask more than once — a wrong passphrase comes back as `SETERROR` and another
`GETPIN` on the same connection. Nothing of the previous attempt survives into the next:
the buffer is wiped between them.

**Front-end selection — the decision that is easy to get wrong.** "If `OPTION ttyname`
was given, draw on that tty" is wrong: a graphical application launched from a shell
inherits `GPG_TTY`, so the prompt would land on a terminal nobody is looking at. The rule
is **a window whenever a display is reachable; the terminal only when none is.** Failing
loudly beats prompting somewhere invisible.

**The mask counts characters, not bytes**, and shows the count — because that number is
the one honest thing a masked field can say, and a byte count lies about every multibyte
character typed.

## Building

The default build is graphical (`winit` + `softbuffer` + `fontdue`, Wayland and X11);
without a window ward cannot answer a prompt raised from a menu or a browser, which is the
situation it was written for. `--no-default-features` leaves a tty-only pinentry whose
whole dependency tree is `libc` — nothing that could hold the passphrase links in.

```sh
cargo build --release                       # graphical (default)
cargo build --release --no-default-features # tty-only
```

## Honest limits

Wayland gives an ordinary client no keyboard grab, so the X11 `XGrabKeyboard` behaviour of
other pinentries — locking every keypress to the prompt — cannot be reproduced here. That
is stated plainly rather than implied away: ward asks for the passphrase; it does not
promise no other window can read the keyboard while it is open.

## Licence

BSD-3-Clause
