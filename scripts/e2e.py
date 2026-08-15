#!/usr/bin/env python3
"""End to end against a real gpg-agent, in a cage it cannot get out of.

Everything here exists because of one property of gpg-agent: it is a daemon, and the pinentry
it spawns draws on the terminal the AGENT inherited when it started — not the one the client
is using. A test run casually from a working shell can therefore seize and corrupt that
shell. It has happened during this project's development, twice.

So:

  * a throwaway GNUPGHOME, never the real one, and the script refuses to run if that is not
    what it was given;
  * every gpg invocation under setsid, so the process group has no controlling terminal for
    an accidental grab to find;
  * a pseudo-terminal allocated by this script and named in GPG_TTY, so the prompt has
    somewhere to go that belongs to the test;
  * --frontend tty, so ward never reaches for a window on a live desktop;
  * key generation through --pinentry-mode loopback, which spawns no pinentry at all.

What it proves: that gpg-agent runs ward, that ward's prompt reaches the terminal the client
named, that a passphrase typed into it comes back through the Assuan D line, and that gpg
accepts it and decrypts. That is the whole chain, and none of it is provable any other way.
"""

import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time

PASSPHRASE = "тест-фраза-на-кирилица"  # the alphabet is not decoration: it is the founding bug


def run(cmd, **kw):
    """Every helper invocation, with stdin nailed shut.

    Not politeness — this is the hole that put a prompt on a developer's screen. `setsid`
    detaches the process group but does not close inherited descriptors, and gpg takes the
    terminal it tells the agent about from GPG_TTY or, failing that, from `ttyname(0)`. A
    call that merely captures stdout still hands its own stdin through, and if that is a
    real terminal the agent will be told to draw there. Closing it here means no future edit
    to this file can reintroduce the mistake by forgetting.
    """
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main() -> int:
    ward = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/release/ward")
    if not os.path.isfile(ward):
        print(f"no ward binary at {ward}", file=sys.stderr)
        return 2

    home = tempfile.mkdtemp(prefix="ward-e2e-")
    os.chmod(home, 0o700)
    env = dict(os.environ, GNUPGHOME=home)
    # Nothing in here may reach a live desktop.
    env.pop("WAYLAND_DISPLAY", None)
    env.pop("DISPLAY", None)
    # An inherited GPG_TTY would name the terminal this script was started from — the one
    # thing that must never receive a prompt from it.
    env.pop("GPG_TTY", None)

    try:
        wrapper = os.path.join(home, "ward-tty")
        with open(wrapper, "w") as f:
            # gpg-agent gives pinentry-program no arguments, so the choice of front-end has
            # to be made by the thing it runs.
            # The wrapper also records that it ran at all, and ward's stderr with it:
            # "the agent did not start ward" and "ward started and drew nothing" are
            # different failures that look identical from outside.
            f.write(
                f'#!/bin/sh\n'
                f'echo "wrapper ran: $*" >> "{home}/ward.log"\n'
                f'exec "{ward}" --frontend tty --transcript "{home}/assuan.log" '
                f'"$@" 2>> "{home}/ward.log"\n'
            )
        os.chmod(wrapper, 0o755)

        with open(os.path.join(home, "gpg-agent.conf"), "w") as f:
            # The agent's own log is the only witness to what it did with the pinentry:
            # "it never tried" and "it tried and the program failed" look identical from
            # outside, and guessing between them is how an afternoon disappears.
            f.write(
                f"pinentry-program {wrapper}\n"
                f"allow-loopback-pinentry\n"
                f"log-file {home}/agent.log\n"
                f"debug ipc\n"
            )

        print("· generating a key (loopback: no pinentry is spawned)")
        r = run(["setsid", "-w", "gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
                 "--passphrase", PASSPHRASE, "--quick-gen-key", "Ward E2E <e2e@test.invalid>",
                 "default", "default", "never"], env=env)
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            return 1

        r = run(["gpg", "--list-secret-keys", "--with-colons"], env=env)
        fpr = next(l.split(":")[9] for l in r.stdout.splitlines() if l.startswith("fpr"))
        print(f"· key {fpr[-16:]}")

        # Whether the key is protected at all decides whether a prompt is even possible. A
        # test that assumes it and then reports "no prompt appeared" is a test that blames
        # the pinentry for a key with no passphrase.
        r = run(["gpg-connect-agent", "KEYINFO --list", "/bye"], env=env)
        prot = [ln.split()[7] for ln in r.stdout.splitlines()
                if ln.startswith("S KEYINFO") and len(ln.split()) > 7]
        grips = [ln.split()[2] for ln in r.stdout.splitlines() if ln.startswith("S KEYINFO")]
        print(f"· agent says protection = {prot or 'nothing'} (P = has a passphrase)")
        if "P" not in prot:
            print("the generated key has NO passphrase — nothing would ever prompt",
                  file=sys.stderr)
            return 1

        clear = os.path.join(home, "message")
        with open(clear, "w") as f:
            f.write("the chain works\n")
        r = run(["setsid", "-w", "gpg", "--batch", "--yes", "--trust-model", "always",
                 "--encrypt", "--recipient", fpr, "--output", clear + ".gpg", clear], env=env)
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            return 1

        # The cache has to be empty or the decryption proves nothing — but the agent must
        # stay UP. Killing it and expecting gpg to start a fresh one is what the first
        # version did, and the agent's own log showed the truth: it shut down and nothing
        # ever brought it back, so gpg sat waiting for a socket that was gone. Forgetting
        # the passphrase is a different operation from ending the process, and this is the
        # one that was actually wanted.
        for grip in grips:
            run(["gpg-connect-agent", f"CLEAR_PASSPHRASE --mode=normal {grip}", "/bye"], env=env)
        r = run(["gpg-connect-agent", "KEYINFO --list", "/bye"], env=env)
        still = [ln.split()[2][:8] for ln in r.stdout.splitlines()
                 if ln.startswith("S KEYINFO") and len(ln.split()) > 6 and ln.split()[6] == "1"]
        if still:
            print(f"the agent is still holding {still} — the test would prove nothing",
                  file=sys.stderr)
            return 1
        print("· the agent has forgotten the passphrase (verified, not assumed)")

        print("· decrypting — this must make gpg-agent run ward")
        master, slave = pty.openpty()
        tty_name = os.ttyname(slave)

        # gpg is given the pty as its ACTUAL terminal, not merely told the name of one.
        # Naming it is not enough and that cost several rounds to learn: gpg decides whether
        # it may ask a human from whether it HAS a terminal, and with stdin closed it decides
        # it may not — so it waits forever instead of prompting, silently, with an empty log.
        # The pty belongs to this script, so handing it over is safe; the developer's terminal
        # is never involved.
        errlog = os.path.join(home, "gpg.log")
        errf = open(errlog, "wb")
        proc = subprocess.Popen(
            ["setsid", "-w", "gpg", "--decrypt", clear + ".gpg"],
            env=dict(env, GPG_TTY=tty_name),
            stdin=slave, stdout=slave, stderr=errf,
        )
        os.close(slave)

        deadline = time.time() + 20
        drawn = b""
        while time.time() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                try:
                    drawn += os.read(master, 65536)
                except OSError:
                    break
            if b"assphrase" in drawn:
                break

        if b"assphrase" not in drawn:
            proc.kill()
            errf.flush()
            print("ward never asked for a passphrase", file=sys.stderr)
            for name in ("ward.log", "assuan.log", "gpg.log", "agent.log"):
                path = os.path.join(home, name)
                print(f"--- {name} ---", file=sys.stderr)
                print(open(path).read()[-1500:] if os.path.exists(path) else "(never created)",
                      file=sys.stderr)
            return 1
        print(f"· ward drew {len(drawn)} bytes and asked on the terminal it was given")

        os.write(master, PASSPHRASE.encode() + b"\r")
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            print("gpg never finished after the passphrase", file=sys.stderr)
            return 1
        time.sleep(0.4)
        while select.select([master], [], [], 0.2)[0]:
            try:
                drawn += os.read(master, 65536)
            except OSError:
                break
        os.close(master)

        if proc.returncode != 0 or b"the chain works" not in drawn:
            errf.flush()
            print(f"decryption failed (exit {proc.returncode})", file=sys.stderr)
            print(open(errlog).read()[-1500:], file=sys.stderr)
            return 1

        print("· gpg accepted the passphrase and decrypted")
        print("\nPASS — gpg-agent → ward → the terminal → back through the D line → gpg")
        return 0
    finally:
        run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], env=env)
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
