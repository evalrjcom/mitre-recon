# MITRE ATT&CK Toolkit

A single-file Tkinter GUI for Kali Linux / Parrot OS / other pentest distros
that organizes the pentest tools already on the box by MITRE ATT&CK
(Enterprise) **tactic** — 14 tabs, Reconnaissance (TA0043) through Impact
(TA0040) — for OSCP lab and CTF use.

Pick a tactic tab, pick a tool, type a target, and either launch it in your
normal external terminal or run it in a **live embedded terminal right in
the tab** (a real pty, rendered via [`pyte`](https://pypi.org/project/pyte/))
so you can follow output without alt-tabbing.

## Features

- **14 tactic tabs** with curated, best-in-class tools per tactic (Nmap /
  theHarvester under Reconnaissance, Hydra / sqlmap under Initial Access,
  Hashcat / John under Credential Access, Impacket's `psexec.py` /
  `secretsdump.py` under Lateral Movement, and so on through Impact).
- **Distro detection** — flags Kali, Parrot, BlackArch, BackBox, Pentoo,
  Wifislax, Cyborg Hawk and ArchStrike by name; other distros still work,
  just unlabeled. Tool availability is always checked individually via
  `shutil.which()`, never assumed from the distro.
- **Embedded terminal** with scrollback (`pyte.HistoryScreen`, Page Up/Page
  Down to scroll), Send Ctrl+C, and a SIGKILL "Force Kill" fallback.
- **Optional chroot** execution via `os.chroot()` — documented as a
  filesystem-layout convenience only, **not** a security sandbox.
- **Session logging** to `~/mitre_toolkit_sessions/session_<date>.log` for
  every run (tactic, tool, target, resolved argv), with credential-bearing
  flags (`-p`/`-P`/`-H`/`--password`/etc., including combined forms like
  `-pSecret` or `--password=Secret`) redacted before anything touches disk —
  tool-aware, so e.g. msfvenom's `-p` (payload module, not a password) is
  left untouched.
- **PNG snapshots** of the terminal buffer and **zip report bundling**
  (snapshots + the session log) for dropping straight into an OSCP report.
- **JSON export** of the session log, **target queue** (one target per
  line, or a CIDR — auto-expanded, capped at 1024 hosts) to run a tool
  against a whole list, and **Copy Command** to clipboard.
- Safe argv handling throughout: `shlex.split()`/`shlex.quote()`, **never**
  `shell=True`, never shell string-concatenation.

## Run

```bash
# On Kali/Parrot (Debian-based):
sudo apt install python3-tk
pip install --break-system-packages pyte Pillow   # optional: embedded terminal + PNG snapshots

python3 mitre_toolkit_v4.py
```

`pyte`/`Pillow` are optional — missing either only disables that specific
feature (embedded terminal, PNG snapshots respectively); the rest of the app
still works. If your distro's `python3-tk` only binds to a specific Python
minor version (e.g. `python3.12`), run the script with that interpreter.

The script creates `~/mitre_toolkit_sessions/` for logs and snapshots, and
`~/.mitre_toolkit_v4.json` to remember your terminal emulator and chroot
path between runs (falls back through `.mitre_toolkit_v3.json` /
`v2.json` / `v1.json` if you're upgrading from an earlier version).

## Safety, scope, and legal notes

- This is an **orchestration front end**, not an exploit toolkit: it
  contains no exploit code, payloads, or attack logic of its own — only
  command templates over tools you already installed.
- Only point it at hosts you're authorized to test — your OSCP lab,
  HTB/THM boxes, or your own range. Running these tools against anything
  else is illegal in most jurisdictions.
- Target/argument input is passed to each tool as an isolated argv element
  (never through a shell), so a target string can't be used to inject extra
  shell commands — but the tool it's handed to can still do whatever that
  tool normally does with its arguments (e.g. Hydra brute-forcing a live
  service). Scope discipline is still on you.
- Running the GUI as root (required for chroot) means anything launched
  from it also runs as root. Only set a chroot path when you actually need
  one.
- Stopping or force-killing a running tool (or quitting the app) signals
  the tool's **whole process group**, not just the embedded shell wrapper,
  so a tool it spawns a child process for (e.g. a listener) is actually
  terminated, not orphaned.

> For authorized penetration testing, red-team engagements, and OSCP-style
> lab practice only. You are responsible for holding written authorization
> for every host you touch.
