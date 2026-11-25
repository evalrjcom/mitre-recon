# ATT&CK Lifecycle Toolkit

A single-file Tkinter control panel for Kali Linux / Parrot OS that organizes
the tooling already on the box by MITRE ATT&CK (Enterprise) **tactic**
(Reconnaissance through Impact), rather than by a generic methodology phase.

For each tactic it lists curated, best-in-class tools, shows whether each is
installed (`shutil.which`), resolves a command template against your
engagement variables (target, LHOST, LPORT, interface, wordlist, output
directory), and launches the selected tool in a detached terminal window —
or just copies the resolved command if you'd rather paste it yourself.

This is a **launcher and reference**, not an exploitation framework. It runs
standard, publicly documented security tools already present on the system.
It ships no exploit payloads, no malware, and no destructive tooling — the
Impact tactic specifically offers only a benign, non-destructive
proof-of-access artifact, with anything destructive left as a reference
pointer requiring separate written authorization.

Pure Python standard library (`tkinter` + `subprocess`). No external
dependencies.

## Run

```bash
sudo apt install python3-tk   # if tkinter is missing
python3 attack_lifecycle_toolkit_v1.1.0.py
```

You'll be asked to confirm you have written authorization for your target
scope before the window opens.

Fill in the engagement variables at the top (Target, LHOST, LPORT, LAN
interface, wordlist, output directory) — LHOST is pre-filled from a VPN
tunnel interface when one is up (the common case for OSCP/PWK-style labs),
falling back to the OS default route otherwise. Pick a tactic on the left,
pick a tool on the right, and either **Launch in terminal** or **Copy
command**.

## Safety notes

- No `shell=True` anywhere; every substituted value is `shlex.quote()`-d.
- Every `{placeholder}` a tool's command template references is required
  and validated before launch, not just the ones declared up front.
- Input is restricted to an allowlist of characters that still excludes
  shell metacharacters and raw control bytes (blocking both shell injection
  and terminal-escape-sequence injection), while permitting ordinary
  URL/CIDR punctuation (`sqlmap -u http://host/page.php?id=1&x=2`, `/24`).
- Launched tools run in their own session, so closing the GUI can't take
  down an active listener/handler with it.

> For authorized penetration testing, red-team engagements, and OSCP-style
> lab practice only. You are responsible for holding written authorization
> for every host you touch — the in-app confirmation is not a substitute
> for a signed scope / rules-of-engagement document.
