#!/usr/bin/env python3
"""
mitre_toolkit_v4.py
--------------------------------------------------------------------
MITRE ATT&CK Tactic Launcher for Kali / Parrot / other pentest distros
(OSCP lab / CTF use)

Purpose
-------
A single-file Tkinter GUI that organizes the security tools already
bundled in mainstream pentest distros (Kali Linux, Parrot Security OS,
BlackArch, and similar Debian/Arch-based derivatives) by MITRE ATT&CK
tactic, and launches the selected tool (with a user-supplied target/
argument string) in a new terminal window, or in a terminal embedded
right in the tab -- against one target, or a whole queue of them. It
does not embed any exploit code, payload generators' output, or attack
automation of its own -- it is purely an orchestration / reporting
front-end over tools you already have installed and are authorized to
use (OSCP labs, HTB, your own range).

Every launch is timestamped and appended to a local session log
(~/mitre_toolkit_sessions/session_<date>.log) so you can reuse the
log as raw material for your OSCP report timeline; it can also be
exported to JSON (File > Export Session Log as JSON) and a tab's log
entries + PNG snapshots bundled into one zip (per-tab "Bundle Report"
button) for dropping straight into a report. Credential-bearing flags
(-p/--password/-H/--hash/etc., including combined forms like -pFoo or
--password=Foo) are redacted before anything is written to that log --
see SessionLogger._redact_argv(). v4: that redaction is now tool-aware
-- msfvenom's "-p" (payload module, e.g. "-p windows/meterpreter/
reverse_tcp") is no longer mistaken for a password flag and masked,
which previously corrupted exactly the report data this log exists
to preserve.

Design notes
------------
- Tool availability is checked with shutil.which() at startup; tools
  not found on $PATH are greyed out rather than hidden, so you can
  see what your distro expects vs. what's actually installed.
- Commands are launched via the user's terminal emulator (auto-
  detected, overridable) using `-e` / `-hold` semantics so the
  window stays open after the tool exits and you can read output.
- Target/argument substitution uses a `{target}` placeholder in each
  command template. Most tools take a single bare host/IP/URL/path,
  substituted as ONE argv element. A handful of tools (Hydra, netexec,
  hashcat, nc, scp, msfvenom, searchsploit, john, responder) expect the
  target field to hold several of THEIR OWN arguments, space-separated,
  exactly as documented in that tool's notes (e.g. Hydra: "-l admin -P
  wordlist.txt ssh://10.10.10.10") -- those tools are marked
  target_is_argv=True on their Tool() entry, and the target string is
  itself shlex.split() into multiple argv elements. Either way, nothing
  is ever passed through a shell string built by concatenation and
  `shell=True` is never used: the *user's* target text is parsed with
  Python's own shlex (no shell involved), and the resulting argv list
  is what actually executes.
- A live hint under the target field flags a target string that looks
  malformed for the currently selected tool (stray spaces for a
  simple-target tool, unbalanced quotes for an argv-mode one) before
  you launch anything, not after.
- No command is ever executed with shell=True.

Requires: Python 3.8+, Tkinter (python3-tk), and a pentest distro
(Kali, Parrot, BlackArch, etc.) with the referenced tools on $PATH.
Optional, for the embedded-terminal tabs: `pip install pyte Pillow`
(pyte renders the pty output and its scrollback history; Pillow
renders PNG snapshots).

Chroot note: a chroot target (File > Set Chroot Path) requires running
this GUI as root, and os.chroot() alone is NOT a security sandbox --
a root process can trivially escape a plain chroot. It exists here as
a convenience for running a tool against a different filesystem layout
(e.g. a 32-bit or legacy toolchain), not as isolation/containment.
"""

import ast
import json
import os
import platform
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_network, AddressValueError
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import pty
except ImportError:      # pty is POSIX-only; toolkit is Linux-only anyway
    pty = None

try:
    import pyte
except ImportError:
    pyte = None

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = ImageDraw = ImageFont = None

APP_VERSION = "4.0.0"
APP_TITLE = f"MITRE ATT&CK Toolkit Launcher v{APP_VERSION}"
LOG_DIR = Path.home() / "mitre_toolkit_sessions"
SNAPSHOT_DIR = LOG_DIR / "snapshots"
REPORT_DIR = LOG_DIR / "reports"
CONFIG_PATH = Path.home() / ".mitre_toolkit_v4.json"
# v4: config filename bumped alongside the script version, same as the
# v1 -> v2 -> v3 bumps. load_config() falls back through v3's, v2's and
# v1's paths so an existing install's saved terminal/chroot settings
# aren't dropped.
LEGACY_CONFIG_PATHS = [
    Path.home() / ".mitre_toolkit_v3.json",
    Path.home() / ".mitre_toolkit_v2.json",
    Path.home() / ".mitre_toolkit_v1.json",
]

TERM_COLS = 100     # initial/fallback embedded-terminal size, in character
TERM_ROWS = 28      # cells, before the pane's own <Configure> handler (see
                     # ToolkitApp._build_tactic_tab) measures its real size.
SCROLLBACK_LINES = 2000   # pyte.HistoryScreen history size (v3: scrollback)
MAX_QUEUE_TARGETS = 1024  # sanity cap when a CIDR expands to many hosts

# ---------------------------------------------------------------------------
# Terminal emulator detection
# ---------------------------------------------------------------------------

# Each entry: (binary_name, argv_template_for_running_a_command_and_staying_open)
# {cmd} is replaced with the full shell-quoted command string.
TERMINAL_CANDIDATES = [
    ("qterminal", ["qterminal", "-e", "bash", "-c", "{cmd}; echo; read -p 'Press Enter to close...'"]),
    ("x-terminal-emulator", ["x-terminal-emulator", "-e", "bash", "-c", "{cmd}; echo; read -p 'Press Enter to close...'"]),
    ("xterm", ["xterm", "-hold", "-e", "bash", "-c", "{cmd}"]),
    ("mate-terminal", ["mate-terminal", "--", "bash", "-c", "{cmd}; echo; read -p 'Press Enter to close...'"]),
    ("gnome-terminal", ["gnome-terminal", "--", "bash", "-c", "{cmd}; echo; read -p 'Press Enter to close...'"]),
]


def detect_terminal():
    for binary, template in TERMINAL_CANDIDATES:
        if shutil.which(binary):
            return binary, template
    return None, None


# ---------------------------------------------------------------------------
# Pentest distro detection
# ---------------------------------------------------------------------------

# Known pentest-oriented distros: (id/id_like token to match, display name).
# Matched against /etc/os-release's ID and ID_LIKE fields (case-insensitive).
KNOWN_PENTEST_DISTROS = [
    ("kali", "Kali Linux"),
    ("parrot", "Parrot Security OS"),
    ("blackarch", "BlackArch"),
    ("backbox", "BackBox"),
    ("pentoo", "Pentoo"),
    ("wifislax", "Wifislax"),
    ("cyborg", "Cyborg Hawk"),
    ("archstrike", "ArchStrike"),
]


def parse_os_release(path: str = "/etc/os-release") -> dict:
    """Minimal /etc/os-release parser -- avoids a subprocess dependency."""
    data = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip().strip('"')
    except OSError:
        pass
    return data


def detect_distro() -> dict:
    """
    Returns a dict: {
        "pretty_name": str,      # human-readable string for the status bar
        "id": str,               # os-release ID, lowercased ('' if unknown)
        "known_pentest": bool,   # True if it matches a known pentest distro
        "matched_label": str,    # friendly name of the matched distro, or ""
    }
    Works on any Linux distro -- unrecognized ones still report their
    real name via os-release rather than being forced into a guess.
    """
    if sys.platform != "linux":
        return {
            "pretty_name": platform.platform(),
            "id": "",
            "known_pentest": False,
            "matched_label": "",
        }

    osr = parse_os_release()
    os_id = osr.get("ID", "").lower()
    os_id_like = osr.get("ID_LIKE", "").lower()
    pretty = osr.get("PRETTY_NAME") or osr.get("NAME") or platform.platform()

    haystack = f"{os_id} {os_id_like} {pretty.lower()}"
    matched_label = ""
    for token, label in KNOWN_PENTEST_DISTROS:
        if re.search(rf"\b{re.escape(token)}\b", haystack):
            matched_label = label
            break

    return {
        "pretty_name": pretty,
        "id": os_id,
        "known_pentest": bool(matched_label),
        "matched_label": matched_label,
    }


# ---------------------------------------------------------------------------
# Data model: MITRE ATT&CK tactics -> tools available on the distro
# ---------------------------------------------------------------------------

@dataclass
class Tool:
    name: str
    binary: str                 # binary checked with shutil.which
    description: str
    template: str                # argv-style template string; {target} placeholder
    notes: str = ""
    # True when the target field holds several of the TOOL's OWN
    # arguments, space-separated (e.g. Hydra: "-l admin -P wordlist.txt
    # ssh://10.10.10.10"), rather than one bare host/IP/URL/path. See
    # ToolkitApp._build_argv() for how this is used.
    target_is_argv: bool = False


@dataclass
class Tactic:
    tactic_id: str
    name: str
    tools: list = field(default_factory=list)


# NOTE: templates assume the *binary itself* is on PATH (the distro ships
# all of these in its default/full metapackages, or via `sudo apt install`).
# {target} is substituted as described on Tool.target_is_argv above.
TACTICS = [
    Tactic("TA0043", "Reconnaissance", [
        Tool("Nmap (service/version scan)", "nmap",
             "Active network/service enumeration.",
             "nmap -sC -sV -oN nmap_{target_safe}.txt {target}"),
        Tool("theHarvester (OSINT)", "theHarvester",
             "Passive OSINT: emails, subdomains, hosts.",
             "theHarvester -d {target} -b all"),
        Tool("whois", "whois",
             "Domain registration lookup.",
             "whois {target}"),
        Tool("dnsenum", "dnsenum",
             "DNS enumeration / zone transfer attempts.",
             "dnsenum {target}"),
        Tool("Amass (subdomain enum)", "amass",
             "Passive+active subdomain enumeration.",
             "amass enum -d {target}"),
    ]),
    Tactic("TA0042", "Resource Development", [
        Tool("msfvenom (payload staging)", "msfvenom",
             "Build a payload binary for an authorized engagement. "
             "You supply full LHOST/LPORT/format args in the target field.",
             "msfvenom {target}", target_is_argv=True),
        Tool("searchsploit", "searchsploit",
             "Search local Exploit-DB mirror for a product/version "
             "(e.g. 'openssh 7.2' -- space-separated search terms).",
             "searchsploit {target}", target_is_argv=True),
    ]),
    Tactic("TA0001", "Initial Access", [
        Tool("Metasploit Framework", "msfconsole",
             "Exploit framework console (interactive).",
             "msfconsole"),
        Tool("Hydra (service brute force)", "hydra",
             "Credential brute force against a service. Target field: "
             "e.g. '-l admin -P wordlist.txt ssh://10.10.10.10'.",
             "hydra {target}", target_is_argv=True),
        Tool("sqlmap", "sqlmap",
             "Automated SQL injection testing against a URL.",
             "sqlmap -u {target} --batch"),
    ]),
    Tactic("TA0002", "Execution", [
        Tool("Metasploit Framework", "msfconsole",
             "Use exploit/multi/handler or a chosen module interactively.",
             "msfconsole"),
        Tool("CrackMapExec/NetExec", "netexec",
             "Execute commands / validate creds across SMB, WinRM, etc. "
             "Target field: full netexec argv, e.g. 'smb 10.10.10.0/24 -u user -p pass -x whoami'.",
             "netexec {target}", target_is_argv=True),
    ]),
    Tactic("TA0003", "Persistence", [
        Tool("Metasploit Framework", "msfconsole",
             "Use post/*/manage/persistence modules interactively.",
             "msfconsole"),
    ]),
    Tactic("TA0004", "Privilege Escalation", [
        Tool("LinPEAS (local script)", "bash",
             "Runs a locally-downloaded linpeas.sh -- put the full path "
             "in the target field, e.g. '/opt/peass/linpeas.sh'.",
             "bash {target}"),
        Tool("Metasploit local_exploit_suggester", "msfconsole",
             "Interactive: use post/multi/recon/local_exploit_suggester.",
             "msfconsole"),
    ]),
    Tactic("TA0005", "Defense Evasion", [
        Tool("msfvenom (encoded payload)", "msfvenom",
             "Encode/obfuscate a payload for an authorized test. Full "
             "args (encoder, iterations, format) go in the target field.",
             "msfvenom {target}", target_is_argv=True),
    ]),
    Tactic("TA0006", "Credential Access", [
        Tool("Hashcat", "hashcat",
             "Offline hash cracking. Target field: full hashcat argv, "
             "e.g. '-m 1000 hashes.txt rockyou.txt'.",
             "hashcat {target}", target_is_argv=True),
        Tool("John the Ripper", "john",
             "Offline password cracking. Target field: hash file (+opts), "
             "e.g. 'hashes.txt --format=nt'.",
             "john {target}", target_is_argv=True),
        Tool("Responder", "responder",
             "LLMNR/NBT-NS/mDNS poisoner for credential capture. Target "
             "field: interface flag, e.g. '-I eth0'.",
             "responder {target}", target_is_argv=True),
    ]),
    Tactic("TA0007", "Discovery", [
        Tool("NetExec (AD/host enum)", "netexec",
             "Domain/AD enumeration. Target field: full netexec argv.",
             "netexec {target}", target_is_argv=True),
        Tool("enum4linux-ng", "enum4linux-ng",
             "SMB/AD host enumeration.",
             "enum4linux-ng {target}"),
    ]),
    Tactic("TA0008", "Lateral Movement", [
        Tool("Impacket psexec.py", "psexec.py",
             "Lateral movement over SMB with valid creds. Target field: "
             "e.g. 'user:pass@10.10.10.10'.",
             "psexec.py {target}"),
        Tool("Impacket wmiexec.py", "wmiexec.py",
             "Lateral movement over WMI with valid creds.",
             "wmiexec.py {target}"),
    ]),
    Tactic("TA0009", "Collection", [
        Tool("Impacket secretsdump.py", "secretsdump.py",
             "Dump SAM/NTDS/LSA secrets with valid creds/hash.",
             "secretsdump.py {target}"),
    ]),
    Tactic("TA0011", "Command and Control", [
        Tool("Metasploit multi/handler", "msfconsole",
             "Interactive: set up a listener for a staged payload.",
             "msfconsole"),
        Tool("netcat listener", "nc",
             "Simple TCP listener. Target field: e.g. '-lvnp 4444'.",
             "nc {target}", target_is_argv=True),
    ]),
    Tactic("TA0010", "Exfiltration", [
        Tool("netcat (file transfer)", "nc",
             "Simple TCP transfer. Target field: full nc argv.",
             "nc {target}", target_is_argv=True),
        Tool("scp", "scp",
             "Exfil over SSH to your attack box. Target field: full scp argv.",
             "scp {target}", target_is_argv=True),
    ]),
    Tactic("TA0040", "Impact", [
        Tool("Metasploit Framework", "msfconsole",
             "Interactive -- impact-stage modules per engagement scope.",
             "msfconsole"),
    ]),
]


# ---------------------------------------------------------------------------
# Session logger
# ---------------------------------------------------------------------------

class SessionLogger:
    # Flags whose FOLLOWING token (space-separated form: "-p", "secret") is
    # masked before anything is written to disk.
    _SENSITIVE_FLAGS = {
        "-p", "-P", "--password", "--passwords", "--pass",
        "-H", "--hash", "--hashes", "-k", "--key", "--ntlm",
    }
    # v3: also catch the COMBINED forms of the same flags -- "-pSecret",
    # "--password=Secret" -- which the v2 redaction missed entirely
    # (flagged in the v2 audit's "Suggested Improvements").
    _COMBINED_LONG_RE = re.compile(
        r'^(--password|--passwords|--pass|--hash|--hashes|--key|--ntlm)=(.+)$'
    )
    _COMBINED_SHORT_RE = re.compile(r'^-([pPHk])(.+)$')
    # v4 CHANGED: redaction is now tool-aware. The generic "-p"/"-P" rule
    # above is a false-positive magnet for tools where those letters mean
    # something other than "password" -- msfvenom uses "-p" for the
    # PAYLOAD module name (e.g. "-p windows/meterpreter/reverse_tcp"),
    # which is exactly the kind of detail the OSCP report log exists to
    # preserve, not scrub. Caught in the v3->v4 audit: _redact_argv had
    # no knowledge of which tool it was redacting for, so it masked
    # msfvenom's payload argument on every single run. Binaries listed
    # here have their "-p"/"-P"/"--pass*" flags excluded from masking;
    # add to this set if another tool overloads the same letters for a
    # non-secret meaning.
    _PASSWORD_FLAGS_NOT_APPLICABLE = {"msfvenom"}

    def __init__(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d")
        self.path = LOG_DIR / f"session_{stamp}.log"

    @classmethod
    def _redact_argv(cls, argv: list, tool_binary: str = "") -> list:
        """Mask credential-bearing values before they're written to disk,
        in both the space-separated form (-p secret) and the combined
        form (-psecret, --password=secret). Heuristic, not exhaustive --
        treat the log as reporting evidence, not as a guaranteed-safe
        credential store. tool_binary (v4 NEW) narrows the flag set for
        tools where a masked letter has a different, non-secret meaning
        (see _PASSWORD_FLAGS_NOT_APPLICABLE)."""
        sensitive_flags = cls._SENSITIVE_FLAGS
        long_re = cls._COMBINED_LONG_RE
        short_re = cls._COMBINED_SHORT_RE
        if tool_binary in cls._PASSWORD_FLAGS_NOT_APPLICABLE:
            sensitive_flags = sensitive_flags - {"-p", "-P", "--pass", "--password", "--passwords"}
            long_re = re.compile(r'^(--hash|--hashes|--key|--ntlm)=(.+)$')
            short_re = re.compile(r'^-([Hk])(.+)$')
        redacted = []
        mask_next = False
        for token in argv:
            if mask_next:
                redacted.append("***REDACTED***")
                mask_next = False
                continue
            long_match = long_re.match(token)
            if long_match:
                redacted.append(f"{long_match.group(1)}=***REDACTED***")
                continue
            short_match = short_re.match(token)
            if short_match:
                redacted.append(f"-{short_match.group(1)}***REDACTED***")
                continue
            redacted.append(token)
            if token in sensitive_flags:
                mask_next = True
        return redacted

    def log(self, tactic: str, tool: str, argv: list, target: str, tool_binary: str = ""):
        safe_argv = self._redact_argv(argv, tool_binary=tool_binary)
        # The raw target string can itself be "-l admin -p hunter2 ..." for
        # argv-mode tools, so redact it the same way (split/rejoin) rather
        # than logging it a second time unredacted.
        try:
            safe_target = " ".join(self._redact_argv(shlex.split(target), tool_binary=tool_binary))
        except ValueError:
            safe_target = "<unparsable target string>"
        line = (
            f"{datetime.now().isoformat(timespec='seconds')}\t"
            f"tactic={tactic}\ttool={tool}\ttarget={safe_target!r}\t"
            f"argv={safe_argv!r}\n"
        )
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            # Logging is best-effort and must never block running a tool.
            print(f"[mitre_toolkit] warning: could not write session log: {exc}",
                  file=sys.stderr)

    def export_json(self) -> Path:
        """v3 NEW: parse this session's tab-separated log into a list of
        JSON records (one per launch), for scripting report generation.
        Raises OSError/ValueError on read/write failure; caller handles
        user-facing messaging."""
        out_path = self.path.with_suffix(".json")
        records = []
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                rec = {"timestamp": parts[0]}
                for part in parts[1:]:
                    key, _, raw_value = part.partition("=")
                    if not key:
                        continue
                    try:
                        # Fields are logged via repr() (!r) -- literal_eval
                        # is the safe inverse (no eval of arbitrary code).
                        rec[key] = ast.literal_eval(raw_value)
                    except (ValueError, SyntaxError):
                        rec[key] = raw_value
                records.append(rec)
        out_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
        return out_path


# ---------------------------------------------------------------------------
# Config (terminal override, persisted)
# ---------------------------------------------------------------------------

def load_config() -> dict:
    for candidate in [CONFIG_PATH, *LEGACY_CONFIG_PATHS]:
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
    return {}


def save_config(cfg: dict) -> None:
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Target-list parsing (v3 NEW: multi-target queue)
# ---------------------------------------------------------------------------

def parse_target_list(raw_text: str) -> tuple:
    """Parse a block of text (one target/CIDR per line, '#' comments and
    blank lines ignored) into a flat list of target strings. A line that
    parses as a CIDR network is expanded to its individual host addresses
    (capped at MAX_QUEUE_TARGETS to avoid accidentally queuing, say, a
    /8). Returns (targets, warnings) -- warnings is a list of human-
    readable strings about anything truncated or skipped."""
    targets = []
    warnings = []
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line:
            try:
                network = ip_network(line, strict=False)
            except (AddressValueError, ValueError):
                network = None
            if network is not None:
                hosts = list(network.hosts()) or [network.network_address]
                if len(hosts) > MAX_QUEUE_TARGETS:
                    warnings.append(
                        f"{line} expands to {len(hosts)} hosts -- "
                        f"truncated to the first {MAX_QUEUE_TARGETS}."
                    )
                    hosts = hosts[:MAX_QUEUE_TARGETS]
                targets.extend(str(h) for h in hosts)
                continue
        targets.append(line)
    if len(targets) > MAX_QUEUE_TARGETS:
        warnings.append(
            f"Target list has {len(targets)} entries -- truncated to "
            f"the first {MAX_QUEUE_TARGETS}."
        )
        targets = targets[:MAX_QUEUE_TARGETS]
    return targets, warnings


# ---------------------------------------------------------------------------
# Embedded terminal: pty + pyte screen buffer (with scrollback), optional chroot
# ---------------------------------------------------------------------------

class TerminalSession:
    """
    Runs one command under a real pty and feeds its output into a
    pyte.HistoryScreen, so a Tkinter Text widget can render/follow it
    live and the user can scroll back through output pyte has already
    scrolled off-screen (Page Up / Page Down in the pane -- see
    ToolkitApp._tk_event_to_bytes / forward_key).

    If chroot_path is set, the child process calls os.chroot() before
    exec -- this REQUIRES the whole GUI to be running as root, and the
    chroot target must be a populated root filesystem (with /bin/bash,
    shared libs, and the pentest tool itself installed inside it).
    Nothing here builds or provisions that chroot; it must already exist.
    NOTE: os.chroot() alone is not a security boundary -- a root
    process can escape a plain chroot with well-known techniques. This
    is a filesystem-layout convenience, not a sandbox.
    """

    def __init__(self, argv: list, chroot_path: str = "",
                 cols: int = TERM_COLS, rows: int = TERM_ROWS):
        if pty is None or pyte is None:
            raise RuntimeError(
                "Embedded terminals require the 'pty' (POSIX-only) and "
                "'pyte' packages. Install pyte with: pip install pyte"
            )
        self.argv = argv
        self.chroot_path = chroot_path
        self.cols, self.rows = cols, rows
        # v3: HistoryScreen (not plain Screen) adds scrollback -- the user
        # can Page Up/Down through output that's scrolled off the visible
        # pane instead of only ever seeing the last `rows` lines.
        if hasattr(pyte, "HistoryScreen"):
            self.screen = pyte.HistoryScreen(cols, rows, history=SCROLLBACK_LINES)
        else:  # pragma: no cover -- older pyte without HistoryScreen
            self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.Stream(self.screen)
        self.out_queue: "queue.Queue[bytes]" = queue.Queue()
        self.alive = True
        # finalized tracks whether _poll_terminals has already done its one
        # post-exit redraw, so a finished session doesn't get the Text
        # widget cleared/reinserted on every single poll tick forever.
        self.finalized = False
        self.master_fd = None
        self.proc = None
        self._lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._fd_closed = False
        self._reader_thread = None
        self._start()

    def _start(self):
        master_fd, slave_fd = pty.openpty()
        chroot_path = self.chroot_path

        def preexec():
            os.setsid()
            if chroot_path:
                os.chroot(chroot_path)
                os.chdir("/")

        try:
            self.proc = subprocess.Popen(
                self.argv,
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                preexec_fn=preexec, close_fds=True,
            )
        finally:
            os.close(slave_fd)
        self.master_fd = master_fd

        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _read_loop(self):
        while self.alive:
            try:
                chunk = os.read(self.master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            self.out_queue.put(chunk)
        self.alive = False
        # Closing is centralized and idempotent (see _close_master_fd) so
        # whichever side notices EOF/exit first reclaims the fd -- avoids
        # leaking it for the lifetime of the app on a natural process exit.
        self._close_master_fd()

    def _close_master_fd(self):
        with self._close_lock:
            if not self._fd_closed and self.master_fd is not None:
                try:
                    os.close(self.master_fd)
                except OSError:
                    pass
                self._fd_closed = True

    def drain_into_screen(self) -> bool:
        """Feed any pending output into the pyte screen. Returns True if
        anything changed (so the caller knows to redraw)."""
        changed = False
        with self._lock:
            while True:
                try:
                    chunk = self.out_queue.get_nowait()
                except queue.Empty:
                    break
                self.stream.feed(chunk.decode("utf-8", errors="replace"))
                changed = True
        return changed

    def send_keys(self, data: bytes):
        if self.master_fd is not None and self.alive:
            try:
                os.write(self.master_fd, data)
            except OSError:
                pass

    def scroll(self, lines: int):
        """v3 NEW: scroll the HistoryScreen's viewport. Positive = back
        into history (Page Up), negative = toward the live tail (Page
        Down). No-op on a plain Screen (older pyte without history)."""
        if not hasattr(self.screen, "prev_page"):
            return
        with self._lock:
            if lines > 0:
                for _ in range(lines):
                    self.screen.prev_page()
            else:
                for _ in range(-lines):
                    self.screen.next_page()

    def resize(self, cols: int, rows: int):
        import fcntl
        import struct
        import termios
        if cols == self.cols and rows == self.rows:
            return
        self.cols, self.rows = cols, rows
        self.screen.resize(rows, cols)   # pyte.Screen.resize(lines, columns)
        if self.master_fd is not None and self.alive:
            try:
                fcntl.ioctl(
                    self.master_fd, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0),
                )
            except OSError:
                pass

    def is_running(self) -> bool:
        return self.alive and self.proc is not None and self.proc.poll() is None

    def _signal_process_group(self, sig: int):
        """v4 CHANGED (critical bug fix): terminate()/kill() used to call
        self.proc.terminate()/.kill(), which signals ONLY the immediate
        child -- the "bash -lc ..." wrapper, not whatever bash itself
        forks to actually run the tool. Confirmed experimentally (this
        file's own v4 smoke test): when a pty is attached, bash does NOT
        exec() the command in-place the way it does with a plain pipe/
        no-tty stdio -- it forks, so the real tool (hydra, a netcat
        listener, a long-running scan, ...) ends up as bash's CHILD. On
        SIGTERM/SIGKILL to bash alone, bash dies and is reaped, but that
        grandchild is immediately re-parented and keeps running to
        completion, orphaned and invisible to this GUI -- e.g. an active
        Hydra brute-force or a Responder listener the user believed they
        had stopped (Force Kill / Stop / Quit) silently continues in the
        background. preexec() already calls os.setsid() for every
        session, which makes the child its own process-group leader, so
        signaling the whole group with os.killpg(pid, sig) reaches that
        child AND every process it has forked, not just the top one."""
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            os.killpg(self.proc.pid, sig)
        except ProcessLookupError:
            pass  # already gone -- nothing to signal
        except OSError:
            # Fall back to signaling just the direct child -- better than
            # nothing if, for some reason, it isn't its own group leader.
            try:
                self.proc.send_signal(sig)
            except OSError:
                pass

    def terminate(self):
        """Graceful stop (SIGTERM, to the whole process group -- see
        _signal_process_group). See kill() for an immediate SIGKILL
        fallback when a tool ignores this."""
        self.alive = False
        self._signal_process_group(signal.SIGTERM)
        self._close_master_fd()
        # Join (bounded, so a wedged thread can't hang the GUI) so the
        # reader thread has observed the close and exited before the
        # caller opens a new pty for this tab -- otherwise the kernel
        # could reuse the just-closed fd number for the new session
        # while the old thread is still mid-read on it.
        if self._reader_thread is not None and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=1.0)

    def kill(self):
        """v3 NEW: SIGKILL fallback for a tool that ignores SIGTERM/
        Ctrl+C (terminate() uses SIGTERM; some tools -- or a hung
        interactive session -- won't respond to that). v4: now signals
        the whole process group too, same fix as terminate()."""
        self.alive = False
        self._signal_process_group(signal.SIGKILL)
        self._close_master_fd()
        if self._reader_thread is not None and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=1.0)

    def render_text(self) -> str:
        return "\n".join(self.screen.display)

    def render_png(self, path: Path):
        """Render the current screen buffer to a monochrome PNG snapshot."""
        if Image is None:
            raise RuntimeError(
                "PNG snapshots require Pillow. Install with: pip install Pillow"
            )
        font = None
        for candidate in (
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        ):
            if Path(candidate).exists():
                font = ImageFont.truetype(candidate, 14)
                break
        if font is None:
            font = ImageFont.load_default()

        char_w, char_h = 9, 17
        img_w = self.cols * char_w + 20
        img_h = self.rows * char_h + 20
        img = Image.new("RGB", (img_w, img_h), color=(12, 12, 12))
        draw = ImageDraw.Draw(img)
        for row_idx, line in enumerate(self.screen.display):
            draw.text((10, 10 + row_idx * char_h), line,
                       font=font, fill=(0, 255, 70))
        path.parent.mkdir(parents=True, exist_ok=True)
        img.save(path, "PNG")


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class ToolkitApp(tk.Tk):
    # v3 NEW: light format check for a "simple" (non-argv) target -- a
    # bare host/IP/URL/path shouldn't contain stray spaces or quotes.
    # Deliberately permissive (this flags obvious mistakes, it does not
    # validate that something is a real hostname).
    _SIMPLE_TARGET_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._\-:/%?=&@~]*[A-Za-z0-9/])?$')

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x720")
        self.minsize(820, 600)

        self.config_data = load_config()
        self.logger = SessionLogger()
        self.distro_info = detect_distro()
        self.chroot_path = self.config_data.get("chroot_path", "")
        self.terminal_sessions = {}   # tactic_id -> TerminalSession
        self.terminal_widgets = {}    # tactic_id -> tk.Text
        self.terminal_sizes = {}      # tactic_id -> (cols, rows), from <Configure>
        self._tab_refreshers = {}     # tactic_id -> callable taking no args
        self._tab_current_tool = {}   # tactic_id -> currently selected Tool
        self._queues = {}             # tactic_id -> {"targets": [...], "index": int}
        # v4 NEW: tactic_id -> that tab's real "Resolved command" StringVar.
        # _advance_queue_by_id used to fall back to a brand-new throwaway
        # StringVar for every target after the first one in a queue run,
        # so the on-screen command preview would freeze after target #1
        # and silently stop reflecting what was actually executing for
        # the rest of the queue. Keeping the real one here lets every
        # queued run update the visible widget instead of an orphaned var.
        self._tab_cmd_vars = {}

        term_binary, term_template = detect_terminal()
        override = self.config_data.get("terminal_binary")
        if override and shutil.which(override):
            term_binary = override
            for b, t in TERMINAL_CANDIDATES:
                if b == override:
                    term_template = t
                    break
        self.terminal_binary = term_binary
        self.terminal_template = term_template

        self._build_menu()
        self._build_layout()
        # Registered ONCE (not once per tab) -- only refreshes the active
        # tab's preview + hint, so a keystroke in the target field does
        # O(1) work instead of O(number of tabs).
        self.target_var.trace_add("write", lambda *_: self._refresh_active_tab())
        self.notebook.bind("<<NotebookTabChanged>>", lambda _e: self._refresh_active_tab())
        # v4 CHANGED (bug fix): keep the scheduled-callback id so _on_close
        # can cancel it. Previously the recurring self.after(150, ...)
        # chain was never cancelled, so whichever tick was already queued
        # when the window was destroyed would fire anyway and hit
        # "invalid command name ..." (a TclError) trying to touch
        # already-destroyed widgets -- caught by this file's own v4
        # smoke test, which saw that exact error printed on teardown.
        self._poll_after_id = self.after(150, self._poll_terminals)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if not self.terminal_binary:
            messagebox.showwarning(
                APP_TITLE,
                "No supported terminal emulator was found on $PATH "
                "(tried qterminal, x-terminal-emulator, xterm, mate-terminal, "
                "gnome-terminal). Launch buttons will be disabled until "
                "you install one or set a custom terminal via "
                "File > Set Terminal Binary.",
            )

        if not self.distro_info["known_pentest"]:
            messagebox.showinfo(
                APP_TITLE,
                f"Detected OS: {self.distro_info['pretty_name']}\n\n"
                "This isn't one of the pentest distros this toolkit knows "
                "about by name (Kali, Parrot, BlackArch, BackBox, Pentoo, "
                "Wifislax, Cyborg Hawk, ArchStrike). The tool list will "
                "still work -- tools are detected individually via $PATH --"
                " but package names/paths may differ on your distro.",
            )

    # -- menu -----------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Set Terminal Binary...", command=self._set_terminal_binary)
        file_menu.add_command(label="Open Session Log Folder", command=self._open_log_folder)
        file_menu.add_command(label="Export Session Log as JSON", command=self._export_log_json)
        file_menu.add_command(label="Show Detected OS", command=self._show_distro_info)
        file_menu.add_command(label="Set Chroot Path...", command=self._set_chroot_path)
        file_menu.add_separator()
        # v4 CHANGED (bug fix): this used to call self.destroy directly,
        # which skipped _on_close()'s session.terminate() loop entirely.
        # Any tool still running in an embedded terminal (hydra, a
        # listener, msfconsole, ...) was orphaned as a live background
        # process with its pty fd leaked, instead of being sent SIGTERM
        # and cleanly joined, every time the GUI was closed via this menu
        # item rather than the window's [x] button. Both paths now go
        # through the same cleanup.
        file_menu.add_command(label="Quit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        self.config(menu=menubar)

    def _set_terminal_binary(self):
        top = tk.Toplevel(self)
        top.title("Set Terminal Binary")
        top.geometry("360x120")
        tk.Label(top, text="Terminal binary name (must be on $PATH):").pack(pady=(12, 4))
        entry = tk.Entry(top, width=30)
        entry.insert(0, self.terminal_binary or "")
        entry.pack()

        def apply_and_close():
            val = entry.get().strip()
            if not val:
                top.destroy()
                return
            if not shutil.which(val):
                messagebox.showerror(APP_TITLE, f"'{val}' was not found on $PATH.")
                return
            known = {b: t for b, t in TERMINAL_CANDIDATES}
            if val not in known:
                messagebox.showerror(
                    APP_TITLE,
                    f"'{val}' is not a recognized terminal template. "
                    f"Supported: {', '.join(known)}",
                )
                return
            self.terminal_binary = val
            self.terminal_template = known[val]
            self.config_data["terminal_binary"] = val
            save_config(self.config_data)
            top.destroy()

        tk.Button(top, text="Save", command=apply_and_close).pack(pady=10)

    def _show_distro_info(self):
        info = self.distro_info
        messagebox.showinfo(
            APP_TITLE,
            f"Pretty name: {info['pretty_name']}\n"
            f"os-release ID: {info['id'] or '(unknown)'}\n"
            f"Recognized pentest distro: "
            f"{info['matched_label'] if info['known_pentest'] else 'No'}",
        )

    def _set_chroot_path(self):
        top = tk.Toplevel(self)
        top.title("Set Chroot Path")
        top.geometry("460x210")
        tk.Label(
            top, wraplength=420, justify="left",
            text=(
                "Path to a chroot root filesystem to run each embedded-"
                "terminal command inside (must contain a working /bin/bash "
                "plus the target tool and its libs). Requires this GUI to "
                "run as root. Leave blank to run commands directly on the "
                "host instead.\n\n"
                "SECURITY NOTE: a plain os.chroot() is NOT a sandbox. A "
                "process running as root (which this GUI must be, to set "
                "a chroot at all) can escape a chroot with well-known "
                "techniques. Only use this for filesystem-layout "
                "convenience against targets you already control, never "
                "as a containment boundary."
            ),
        ).pack(pady=(12, 6), padx=10)
        entry = tk.Entry(top, width=48)
        entry.insert(0, self.chroot_path)
        entry.pack()

        def apply_and_close():
            val = entry.get().strip()
            if val and not Path(val).is_dir():
                messagebox.showerror(APP_TITLE, f"'{val}' is not a directory.")
                return
            if val and os.geteuid() != 0:
                messagebox.showwarning(
                    APP_TITLE,
                    "A chroot path is set, but this process is not running "
                    "as root -- os.chroot() will fail at launch time unless "
                    "you restart this GUI with sudo.",
                )
            self.chroot_path = val
            self.config_data["chroot_path"] = val
            save_config(self.config_data)
            top.destroy()

        tk.Button(top, text="Save", command=apply_and_close).pack(pady=10)

    def _export_log_json(self):
        """v3 NEW: File > Export Session Log as JSON."""
        try:
            out_path = self.logger.export_json()
        except (OSError, ValueError) as exc:
            messagebox.showerror(APP_TITLE, f"Could not export log: {exc}")
            return
        messagebox.showinfo(APP_TITLE, f"Session log exported to:\n{out_path}")

    def _on_close(self):
        # v4 CHANGED (bug fix): cancel the pending poll-loop callback
        # before destroying the window -- otherwise that already-queued
        # self.after(150, self._poll_terminals) tick fires anyway against
        # now-destroyed widgets and raises a TclError ("invalid command
        # name ..."). See the matching comment in __init__.
        if getattr(self, "_poll_after_id", None) is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except tk.TclError:
                pass
        for session in self.terminal_sessions.values():
            session.terminate()
        self.destroy()

    def _poll_terminals(self):
        for tactic_id, session in list(self.terminal_sessions.items()):
            widget = self.terminal_widgets.get(tactic_id)
            if widget is None:
                continue
            if session.drain_into_screen():
                self._redraw_terminal(widget, session)
            # Only do the one post-exit redraw once (guarded by
            # session.finalized) instead of re-clearing and re-inserting
            # the whole buffer into the Tk widget on every poll tick
            # forever for every finished session.
            if not session.is_running() and not session.finalized:
                self._redraw_terminal(widget, session)
                session.finalized = True
                # v3: advance this tab's target queue (if one is running)
                # now that its current run has finished.
                if tactic_id in self._queues:
                    self.after(300, lambda tid=tactic_id: self._advance_queue_by_id(tid))
        self._poll_after_id = self.after(150, self._poll_terminals)

    @staticmethod
    def _redraw_terminal(widget: tk.Text, session: TerminalSession):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", session.render_text())
        widget.see("end")
        widget.config(state="disabled")

    def _open_log_folder(self):
        try:
            subprocess.Popen(["xdg-open", str(LOG_DIR)])
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not open log folder: {exc}")

    # -- main layout ------------------------------------------------------
    def _build_layout(self):
        top_frame = ttk.Frame(self, padding=8)
        top_frame.pack(fill="x")

        ttk.Label(top_frame, text="Target / Argument string:").pack(side="left")
        self.target_var = tk.StringVar()
        target_entry = ttk.Entry(top_frame, textvariable=self.target_var, width=50)
        target_entry.pack(side="left", padx=6, fill="x", expand=True)

        # v3 NEW: live hint -- flags a target string that looks malformed
        # for the currently selected tool (stray spaces for a simple-
        # target tool, unbalanced quotes for an argv-mode one) before you
        # launch anything.
        self.target_hint_var = tk.StringVar()
        self.target_hint_label = ttk.Label(
            top_frame, textvariable=self.target_hint_var, foreground="#b35900",
        )
        self.target_hint_label.pack(side="left", padx=6)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)

        for tactic in TACTICS:
            frame = ttk.Frame(self.notebook, padding=8)
            self.notebook.add(frame, text=f"{tactic.tactic_id} {tactic.name}")
            self._build_tactic_tab(frame, tactic)

        status = ttk.Frame(self, padding=(8, 0, 8, 8))
        status.pack(fill="x")
        term_label = self.terminal_binary or "NONE FOUND"
        distro_label = self.distro_info["matched_label"] or self.distro_info["pretty_name"]
        self.status_label = ttk.Label(
            status,
            text=(
                f"v{APP_VERSION}    |    Distro: {distro_label}    |    "
                f"Terminal: {term_label}    |    Log: {self.logger.path}"
            ),
        )
        self.status_label.pack(side="left")

    def _build_tactic_tab(self, frame, tactic: Tactic):
        left = ttk.Frame(frame)
        left.pack(side="left", fill="y", padx=(0, 10))

        listbox = tk.Listbox(left, width=42, height=20, exportselection=False)
        for tool in tactic.tools:
            available = bool(shutil.which(tool.binary))
            label = tool.name if available else f"{tool.name}  [not found: {tool.binary}]"
            listbox.insert("end", label)
            if not available:
                listbox.itemconfig("end", foreground="#aaaaaa")
        listbox.pack(side="left", fill="y")
        scrollbar = ttk.Scrollbar(left, orient="vertical", command=listbox.yview)
        scrollbar.pack(side="left", fill="y")
        listbox.config(yscrollcommand=scrollbar.set)

        right = ttk.Frame(frame)
        right.pack(side="left", fill="both", expand=True)

        desc_text = tk.Text(right, height=6, wrap="word", state="disabled")
        desc_text.pack(fill="x", pady=(0, 8))

        cmd_var = tk.StringVar()
        self._tab_cmd_vars[tactic.tactic_id] = cmd_var  # v4 NEW: see __init__
        cmd_label = ttk.Label(right, text="Resolved command:")
        cmd_label.pack(anchor="w")
        cmd_entry = ttk.Entry(right, textvariable=cmd_var, state="readonly")
        cmd_entry.pack(fill="x", pady=(0, 8))

        # Button rows: kept short (2-3 per row) -- a single wide row can
        # exceed the available frame width on narrower windows, and Tk's
        # pack geometry manager silently leaves the overflow button
        # unmapped (0 width, invisible) rather than wrapping it.
        btn_row1 = ttk.Frame(right)
        btn_row1.pack(anchor="w", pady=(0, 2))
        ttk.Button(
            btn_row1, text="Launch in External Terminal",
            command=lambda: self._launch(tactic, listbox, cmd_var),
        ).pack(side="left")
        ttk.Button(
            btn_row1, text="Run in Embedded Terminal",
            command=lambda: self._run_embedded(tactic, listbox, cmd_var),
        ).pack(side="left", padx=6)
        ttk.Button(
            btn_row1, text="Copy Command",
            command=lambda: self._copy_command(cmd_var),
        ).pack(side="left", padx=6)

        btn_row2 = ttk.Frame(right)
        btn_row2.pack(anchor="w", pady=(0, 2))
        ttk.Button(
            btn_row2, text="Send Ctrl+C",
            command=lambda: self._send_ctrl_c(tactic),
        ).pack(side="left")
        ttk.Button(
            btn_row2, text="Force Kill",
            command=lambda: self._force_kill(tactic),
        ).pack(side="left", padx=6)
        ttk.Button(
            btn_row2, text="Save PNG Snapshot",
            command=lambda: self._save_png_snapshot(tactic),
        ).pack(side="left", padx=6)

        btn_row3 = ttk.Frame(right)
        btn_row3.pack(anchor="w", pady=(0, 6))
        ttk.Button(
            btn_row3, text="Run Against Target List...",
            command=lambda: self._open_target_queue_dialog(tactic, listbox, cmd_var),
        ).pack(side="left")
        ttk.Button(
            btn_row3, text="Stop Queue",
            command=lambda: self._stop_queue(tactic),
        ).pack(side="left", padx=6)
        ttk.Button(
            btn_row3, text="Bundle Report (log + snapshots)",
            command=lambda: self._bundle_report(tactic),
        ).pack(side="left", padx=6)

        ttk.Label(right, text="Embedded terminal (click inside, then type to follow along; "
                               "PageUp/PageDown to scroll history):").pack(anchor="w")
        term_frame = ttk.Frame(right)
        term_frame.pack(fill="both", expand=True)
        term_text = tk.Text(
            term_frame, height=14, bg="#0c0c0c", fg="#00ff46",
            insertbackground="#00ff46", font=("DejaVu Sans Mono", 10),
            state="disabled", wrap="none",
        )
        term_text.pack(side="left", fill="both", expand=True)
        term_scroll = ttk.Scrollbar(term_frame, orient="vertical", command=term_text.yview)
        term_scroll.pack(side="left", fill="y")
        term_text.config(yscrollcommand=term_scroll.set)
        self.terminal_widgets[tactic.tactic_id] = term_text
        self.terminal_sizes[tactic.tactic_id] = (TERM_COLS, TERM_ROWS)

        # Wires TerminalSession.resize() to the pane's real pixel size (via
        # the widget's own font metrics), so a session started in this tab
        # uses the pane's actual size instead of a hardcoded 100x28, and
        # live-resizes a running session when the window/pane is resized.
        def on_configure(event, tactic_id=tactic.tactic_id, widget=term_text):
            fnt = tkfont.Font(font=widget.cget("font"))
            char_w = max(fnt.measure("0"), 1)
            char_h = max(fnt.metrics("linespace"), 1)
            cols = max(event.width // char_w, 10)
            rows = max(event.height // char_h, 4)
            self.terminal_sizes[tactic_id] = (cols, rows)
            session = self.terminal_sessions.get(tactic_id)
            if session is not None and session.is_running():
                session.resize(cols, rows)

        term_text.bind("<Configure>", on_configure)

        def forward_key(event, tactic_id=tactic.tactic_id):
            session = self.terminal_sessions.get(tactic_id)
            if session is None:
                return "break"
            # v3: Page Up/Down scroll the HistoryScreen's viewport locally
            # instead of being forwarded to the child process.
            if event.keysym == "Prior":
                session.drain_into_screen()
                session.scroll(5)
                self._redraw_terminal(self.terminal_widgets[tactic_id], session)
                return "break"
            if event.keysym == "Next":
                session.drain_into_screen()
                session.scroll(-5)
                self._redraw_terminal(self.terminal_widgets[tactic_id], session)
                return "break"
            if not session.is_running():
                return "break"
            data = self._tk_event_to_bytes(event)
            if data:
                session.send_keys(data)
            return "break"  # keep the Text widget read-only to the user;
                             # keystrokes go to the pty, not the buffer

        term_text.bind("<Key>", forward_key)

        def on_select(_event=None):
            sel = listbox.curselection()
            if not sel:
                return
            tool = tactic.tools[sel[0]]
            self._tab_current_tool[tactic.tactic_id] = tool
            desc_text.config(state="normal")
            desc_text.delete("1.0", "end")
            desc_text.insert("1.0", f"{tool.name}\n\n{tool.description}\n\n{tool.notes}")
            desc_text.config(state="disabled")
            self._refresh_command_preview(tool, cmd_var)
            self._update_target_hint(tool)

        listbox.bind("<<ListboxSelect>>", on_select)
        # Registered once per tab in this dict rather than via a per-tab
        # target_var.trace_add() (see ToolkitApp.__init__ for why).
        self._tab_refreshers[tactic.tactic_id] = on_select

        if tactic.tools:
            listbox.selection_set(0)
            on_select()

    def _refresh_active_tab(self):
        """Re-run the currently visible tab's on_select() (updates its
        command preview + target hint against the current target text)
        without touching the other tabs."""
        try:
            current = self.notebook.select()
            if not current:
                return
            index = self.notebook.index(current)
        except tk.TclError:
            return
        if 0 <= index < len(TACTICS):
            refresher = self._tab_refreshers.get(TACTICS[index].tactic_id)
            if refresher is not None:
                refresher()

    def _update_target_hint(self, tool: Tool):
        """v3 NEW: compute and display the malformed-target warning for
        the given (currently selected) tool against the current target
        text."""
        target = self.target_var.get().strip()
        hint = ""
        if target and tool is not None:
            if tool.target_is_argv:
                try:
                    shlex.split(target)
                except ValueError:
                    hint = "⚠ unbalanced quotes in argument string"
            elif not self._SIMPLE_TARGET_RE.match(target):
                hint = "⚠ doesn't look like a plain host/IP/URL/path"
        self.target_hint_var.set(hint)

    def _refresh_command_preview(self, tool: Tool, cmd_var: tk.StringVar):
        target = self.target_var.get()
        try:
            argv = self._build_argv(tool, target if target else "<target>", self._safe(target) if target else "<target>")
            cmd_var.set(" ".join(shlex.quote(a) for a in argv))
        except ValueError:
            cmd_var.set("<unbalanced quotes in target>")

    @staticmethod
    def _safe(s: str) -> str:
        # Capped to a sane length for a filename fragment -- an unbounded
        # target string (e.g. a long argv pasted into the target field)
        # could otherwise overflow the ~255-byte filename limit on most
        # Linux filesystems and make the launch fail with ENAMETOOLONG.
        cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in s)
        return cleaned[:80]

    @staticmethod
    def _build_argv(tool: Tool, target: str, target_safe: str) -> list:
        """Resolve a tool's command template against the user's target
        string into a safe argv list -- never through a shell string.

        Most tools take a single-token target (a bare host/IP/URL/path)
        and {target} is substituted as one opaque argv element. Tools
        marked target_is_argv=True (Hydra, netexec, hashcat, nc, scp,
        msfvenom, searchsploit, john, responder) expect the target field
        to hold SEVERAL of their own arguments, space-separated -- for
        those, the target string is itself shlex.split() (pure Python
        tokenizing -- no shell is invoked) and the resulting tokens are
        spliced in at {target}'s position.

        Raises ValueError if the template or the target string has
        unbalanced quoting, which callers surface to the user instead of
        letting a malformed command launch silently wrong.
        """
        template_tokens = shlex.split(tool.template)  # may raise ValueError
        argv = []
        for tok in template_tokens:
            if tok == "{target}" and tool.target_is_argv:
                if target:
                    argv.extend(shlex.split(target))  # may raise ValueError
                # else: empty target -> contribute no tokens at all,
                # matching the "continue with nothing" choice the user
                # already confirmed via the empty-target prompt.
            else:
                # Plain substring substitution (not just an exact-token
                # match) -- matches every OTHER case the original v1 code
                # handled: a bare {target} token for a simple (non-argv)
                # tool, AND {target}/{target_safe} embedded inside a larger
                # token (e.g. "nmap_{target_safe}.txt"). A prior version of
                # this method only handled the exact-token case, which
                # silently dropped substitution for any token where
                # {target} wasn't the WHOLE token -- caught by this file's
                # own smoke test using a template like "echo x={target}".
                argv.append(tok.replace("{target}", target).replace("{target_safe}", target_safe))
        return argv

    def _copy_command(self, cmd_var: tk.StringVar):
        """v3 NEW: Copy Command button."""
        text = cmd_var.get()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    # -- launch -----------------------------------------------------------
    def _resolve_argv(self, tactic: Tactic, listbox: tk.Listbox, target_override: str = None):
        """Shared by _launch and _run_embedded: validates selection/target,
        builds the resolved argv (via _build_argv), and returns
        (tool, argv) or (None, None) if the user should not proceed.
        target_override lets the v3 target queue drive a run without
        going through self.target_var (and the dialogs it would pop)."""
        sel = listbox.curselection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a tool first.")
            return None, None
        tool = tactic.tools[sel[0]]

        if not shutil.which(tool.binary) and not self.chroot_path:
            messagebox.showerror(
                APP_TITLE,
                f"'{tool.binary}' is not on $PATH. Install it "
                f"(e.g. `sudo apt install {tool.binary}`), or point "
                f"File > Set Chroot Path at a root filesystem that has it.",
            )
            return None, None

        target = (self.target_var.get().strip() if target_override is None
                  else target_override.strip())
        if "{target}" in tool.template and not target and target_override is None:
            if not messagebox.askyesno(
                APP_TITLE,
                "The target/argument field is empty. Continue anyway "
                "(the tool will run with no target arguments)?",
            ):
                return None, None

        target_safe = self._safe(target)
        try:
            argv = self._build_argv(tool, target, target_safe)
        except ValueError as exc:
            messagebox.showerror(
                APP_TITLE,
                f"Could not parse the command template or the target/"
                f"argument string (unbalanced quotes?): {exc}",
            )
            return None, None
        return tool, argv

    def _launch(self, tactic: Tactic, listbox: tk.Listbox, cmd_var: tk.StringVar):
        if not self.terminal_binary:
            messagebox.showerror(APP_TITLE, "No terminal emulator configured.")
            return

        tool, argv = self._resolve_argv(tactic, listbox)
        if tool is None:
            return

        cmd_str = " ".join(shlex.quote(a) for a in argv)
        cmd_var.set(cmd_str)

        term_argv = [
            (part.format(cmd=cmd_str) if "{cmd}" in part else part)
            for part in self.terminal_template
        ]

        try:
            subprocess.Popen(term_argv)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Failed to launch terminal: {exc}")
            return

        # v4 CHANGED: pass tool.binary so the logger can skip the
        # password-flag heuristic for tools (e.g. msfvenom) where it
        # doesn't apply -- see SessionLogger._redact_argv.
        self.logger.log(tactic.name, tool.name, argv, self.target_var.get().strip(),
                         tool_binary=tool.binary)

    # -- embedded terminal (pyte + pty, optional chroot) -------------------
    def _run_embedded(self, tactic: Tactic, listbox: tk.Listbox, cmd_var: tk.StringVar,
                       target_override: str = None):
        if pty is None or pyte is None:
            messagebox.showerror(
                APP_TITLE,
                "Embedded terminals need the 'pyte' package (POSIX pty is "
                "built in). Install with: pip install pyte",
            )
            return

        tool, argv = self._resolve_argv(tactic, listbox, target_override=target_override)
        if tool is None:
            return

        cmd_str = " ".join(shlex.quote(a) for a in argv)
        cmd_var.set(cmd_str)

        existing = self.terminal_sessions.get(tactic.tactic_id)
        if existing is not None and existing.is_running():
            if target_override is None and not messagebox.askyesno(
                APP_TITLE,
                "A command is already running in this tab's embedded "
                "terminal. Stop it and start the new one?",
            ):
                return
            existing.terminate()  # blocks briefly (join, timeout=1s) so the
                                   # new pty below can't collide with the
                                   # old session's fd -- see terminate()'s
                                   # own comment for the race it closes.

        if self.chroot_path and os.geteuid() != 0:
            messagebox.showerror(
                APP_TITLE,
                "A chroot path is set but this process is not root -- "
                "os.chroot() requires root. Restart the GUI with sudo, or "
                "clear the chroot path in File > Set Chroot Path.",
            )
            return

        cols, rows = self.terminal_sizes.get(tactic.tactic_id, (TERM_COLS, TERM_ROWS))
        try:
            session = TerminalSession(
                ["bash", "-lc", cmd_str],
                chroot_path=self.chroot_path,
                cols=cols, rows=rows,
            )
        except RuntimeError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Failed to start terminal session: {exc}")
            return

        self.terminal_sessions[tactic.tactic_id] = session
        # Clear the pane immediately so a re-run doesn't briefly show the
        # PREVIOUS run's leftover output before the new session's first
        # poll tick arrives.
        self._redraw_terminal(self.terminal_widgets[tactic.tactic_id], session)
        target_for_log = target_override if target_override is not None else self.target_var.get().strip()
        self.logger.log(tactic.name, tool.name, argv, target_for_log, tool_binary=tool.binary)

    def _send_ctrl_c(self, tactic: Tactic):
        session = self.terminal_sessions.get(tactic.tactic_id)
        if session is None or not session.is_running():
            messagebox.showinfo(APP_TITLE, "No running embedded terminal in this tab.")
            return
        session.send_keys(b"\x03")

    def _force_kill(self, tactic: Tactic):
        """v3 NEW: SIGKILL fallback for a tool that doesn't respond to
        Ctrl+C/SIGTERM."""
        session = self.terminal_sessions.get(tactic.tactic_id)
        if session is None or not session.is_running():
            messagebox.showinfo(APP_TITLE, "No running embedded terminal in this tab.")
            return
        if not messagebox.askyesno(
            APP_TITLE,
            "Force-kill (SIGKILL) the running command in this tab? "
            "Unsaved output in the tool itself may be lost.",
        ):
            return
        session.kill()

    def _save_png_snapshot(self, tactic: Tactic):
        session = self.terminal_sessions.get(tactic.tactic_id)
        if session is None:
            messagebox.showinfo(APP_TITLE, "No embedded terminal session in this tab yet.")
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = self._safe(tactic.name)
        path = SNAPSHOT_DIR / f"{tactic.tactic_id}_{safe_name}_{stamp}.png"
        try:
            session.render_png(path)
        except RuntimeError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        except OSError as exc:
            # v4 CHANGED (bug fix): render_png()'s mkdir()/img.save() can
            # raise OSError (disk full, permission denied, path too long)
            # and this call site only caught RuntimeError (the "no
            # Pillow" case) -- an OSError here used to propagate up
            # uncaught into Tk's default callback-exception handler
            # (a traceback on stderr the user likely never sees) instead
            # of a visible error dialog.
            messagebox.showerror(APP_TITLE, f"Could not save snapshot: {exc}")
            return
        messagebox.showinfo(APP_TITLE, f"Snapshot saved:\n{path}")

    # -- target queue (v3 NEW) --------------------------------------------
    def _open_target_queue_dialog(self, tactic: Tactic, listbox: tk.Listbox, cmd_var: tk.StringVar):
        if not listbox.curselection():
            messagebox.showinfo(APP_TITLE, "Select a tool first.")
            return
        top = tk.Toplevel(self)
        top.title(f"Run Against Target List — {tactic.name}")
        top.geometry("480x380")

        tk.Label(
            top, justify="left", wraplength=440,
            text=(
                "One target per line. '#' comments and blank lines are "
                "ignored. A CIDR (e.g. 10.10.10.0/28) is expanded to its "
                f"individual host addresses (capped at {MAX_QUEUE_TARGETS}). "
                "Each target runs the currently selected tool in this tab's "
                "embedded terminal, one at a time, waiting for each to "
                "finish before starting the next; every run is logged."
            ),
        ).pack(padx=10, pady=(10, 6))

        text_box = tk.Text(top, height=14, width=56)
        text_box.pack(padx=10, fill="both", expand=True)

        def load_from_file():
            path = filedialog.askopenfilename(title="Load target list")
            if not path:
                return
            try:
                content = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                messagebox.showerror(APP_TITLE, f"Could not read {path}: {exc}")
                return
            text_box.delete("1.0", "end")
            text_box.insert("1.0", content)

        btn_frame = ttk.Frame(top)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text="Load from file...", command=load_from_file).pack(side="left")

        def start_queue():
            targets, warnings = parse_target_list(text_box.get("1.0", "end"))
            if not targets:
                messagebox.showinfo(APP_TITLE, "No targets parsed from that list.")
                return
            if warnings:
                messagebox.showwarning(APP_TITLE, "\n".join(warnings))
            if not messagebox.askyesno(
                APP_TITLE,
                f"Run the selected tool against {len(targets)} target(s), "
                f"one at a time, in this tab's embedded terminal?",
            ):
                return
            top.destroy()
            self._queues[tactic.tactic_id] = {"targets": targets, "index": 0}
            self._advance_queue_by_id(tactic.tactic_id, listbox=listbox, cmd_var=cmd_var)

        ttk.Button(btn_frame, text="Start Queue", command=start_queue).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Cancel", command=top.destroy).pack(side="left")

    def _advance_queue_by_id(self, tactic_id: str, listbox: tk.Listbox = None,
                              cmd_var: tk.StringVar = None):
        state = self._queues.get(tactic_id)
        if state is None:
            return
        tactic = next((t for t in TACTICS if t.tactic_id == tactic_id), None)
        if tactic is None:
            del self._queues[tactic_id]
            return
        if state["index"] >= len(state["targets"]):
            del self._queues[tactic_id]
            messagebox.showinfo(
                APP_TITLE,
                f"Target queue for {tactic.name} finished "
                f"({len(state['targets'])} target(s)).",
            )
            return

        # listbox/cmd_var aren't persisted between calls (the queue can be
        # advanced from _poll_terminals, which doesn't have them handy) --
        # recover them from the live tab widgets instead.
        # v4 CHANGED (bug fix): this used to hand _run_embedded a brand-new
        # throwaway StringVar for every target after the first, so the
        # tab's real "Resolved command" field would stop updating after
        # target #1 of a queue and silently show stale output for the
        # rest of the run. Reuse the tab's actual cmd_var (registered in
        # _tab_cmd_vars by _build_tactic_tab) so the preview stays live
        # for every queued target, not just the first.
        if listbox is None:
            listbox = self._find_listbox(tactic_id)
        if cmd_var is None:
            cmd_var = self._tab_cmd_vars.get(tactic_id) or tk.StringVar()

        target = state["targets"][state["index"]]
        state["index"] += 1
        self._run_embedded(tactic, listbox, cmd_var, target_override=target)

    def _find_listbox(self, tactic_id: str):
        term_widget = self.terminal_widgets.get(tactic_id)
        if term_widget is None:
            return None
        # Walk up from the embedded-terminal widget to the tab frame, then
        # find the sibling listbox -- avoids keeping a second parallel
        # tactic_id -> listbox registry in sync with _tab_refreshers.
        frame = term_widget
        while frame is not None and not isinstance(frame.master, ttk.Notebook):
            frame = frame.master
        if frame is None:
            return None
        for child in frame.winfo_children():
            for grandchild in child.winfo_children():
                if isinstance(grandchild, tk.Listbox):
                    return grandchild
        return None

    def _stop_queue(self, tactic: Tactic):
        if tactic.tactic_id in self._queues:
            del self._queues[tactic.tactic_id]
            messagebox.showinfo(APP_TITLE, f"Target queue for {tactic.name} stopped.")
        else:
            messagebox.showinfo(APP_TITLE, "No target queue running in this tab.")

    # -- report bundling (v3 NEW) ------------------------------------------
    def _bundle_report(self, tactic: Tactic):
        """Zip today's session log (full log, since it covers all tabs)
        together with every PNG snapshot taken for THIS tactic into one
        file under ~/mitre_toolkit_sessions/reports/."""
        snapshot_glob = f"{tactic.tactic_id}_*.png"
        snapshots = sorted(SNAPSHOT_DIR.glob(snapshot_glob)) if SNAPSHOT_DIR.exists() else []
        if not snapshots and not self.logger.path.exists():
            messagebox.showinfo(
                APP_TITLE,
                "Nothing to bundle yet -- no log entries or PNG snapshots "
                "for this tactic.",
            )
            return

        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = self._safe(tactic.name)
        zip_path = REPORT_DIR / f"report_{tactic.tactic_id}_{safe_name}_{stamp}.zip"
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                if self.logger.path.exists():
                    zf.write(self.logger.path, arcname=self.logger.path.name)
                for snap in snapshots:
                    zf.write(snap, arcname=f"snapshots/{snap.name}")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not write report zip: {exc}")
            return

        messagebox.showinfo(
            APP_TITLE,
            f"Report bundled ({len(snapshots)} snapshot(s) + the session "
            f"log):\n{zip_path}",
        )

    @staticmethod
    def _tk_event_to_bytes(event) -> bytes:
        """Translate a Tkinter key event on the embedded-terminal Text
        widget into the bytes a real terminal would send for that key."""
        special = {
            "Return": b"\r",
            "BackSpace": b"\x7f",
            "Tab": b"\t",
            "Escape": b"\x1b",
            "Up": b"\x1b[A",
            "Down": b"\x1b[B",
            "Right": b"\x1b[C",
            "Left": b"\x1b[D",
            "Home": b"\x1b[H",
            "End": b"\x1b[F",
            "Delete": b"\x1b[3~",
        }
        keysym = event.keysym
        if keysym in special:
            return special[keysym]
        # Ctrl+<letter> -> control code (Ctrl+C, Ctrl+D, etc.)
        if event.state & 0x4 and len(keysym) == 1 and keysym.isalpha():
            return bytes([ord(keysym.upper()) - 64])
        if event.char:
            return event.char.encode("utf-8", errors="ignore")
        return b""


def main():
    if sys.platform != "linux":
        print("This launcher targets Linux pentest-distro tool paths "
              "(Kali, Parrot, BlackArch, etc.); other platforms are "
              "unsupported.", file=sys.stderr)
    app = ToolkitApp()
    app.mainloop()


if __name__ == "__main__":
    main()
