#!/usr/bin/env python3
"""
reconmap — authorized-use-only Nmap + web reconnaissance toolkit.

Maps every action and finding to MITRE ATT&CK Enterprise techniques.
Use only on systems you have explicit written authorization to test
(OSCP-style labs, contracted engagements, or assets you own).

This tool performs reconnaissance and exposure identification only.
It never exploits a service, never brute-forces credentials, and
never dumps the contents of potentially sensitive files.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import getpass
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse
from zoneinfo import ZoneInfo

# ---------------------------------------------------------------------------
# Optional UI / HTTP libraries (graceful fallback to the standard library)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.theme import Theme

    HAS_RICH = True
except Exception:  # pragma: no cover - optional dependency
    Console = None  # type: ignore[assignment]
    HAS_RICH = False

try:
    import requests as requests_lib

    HAS_REQUESTS = True
except Exception:  # pragma: no cover
    requests_lib = None  # type: ignore[assignment]
    HAS_REQUESTS = False

__version__ = "1.0.0"
TOOL_NAME = "reconmap"
LOCAL_TZ = ZoneInfo("America/Los_Angeles")
USER_AGENT = f"{TOOL_NAME}/{__version__} (authorized engagement)"
CONFIRM_PHRASE = "I HAVE AUTHORIZATION"
NAVIGATOR_LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"
ATTACK_VERSION = "16.1"

# Default nmap timing is polite; never escalate past T4 even if asked.
DEFAULT_TIMING = 3
MAX_TIMING = 4
DEFAULT_RATE = 8.0
DEFAULT_THREADS = 6
DEFAULT_TIMEOUT = 8.0
BODY_FINGERPRINT_LIMIT = 32_768
SENSITIVE_BODY_MAX_STORE = 0  # never store bodies of sensitive paths
MAX_TEXT_STORE = 80_000

SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.env|\.git|\.svn|\.ds_store|\.htaccess|\.htpasswd|id_rsa|id_dsa|"
    r"id_ecdsa|id_ed25519|\.pem|\.key|\.p12|\.pfx|web\.config|"
    r"aws/credentials|\.bak|\.sql|dump|backup)"
)

WEB_PORT_HINTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 3001, 5000, 5001, 9443, 10443}
WEB_SERVICE_HINTS = {
    "http",
    "https",
    "http-alt",
    "https-alt",
    "http-proxy",
    "https-alt",
    "ssl/http",
    "http-proxy-alt",
}

# Official MITRE ATT&CK Enterprise names (verified against attack.mitre.org).
# T1190 is recorded only as a *potential exposure* tag — this tool does not exploit.
ATTACK_CATALOG: dict[str, dict[str, str]] = {
    "T1595": {
        "name": "Active Scanning",
        "tactic": "reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    "T1595.001": {
        "name": "Active Scanning: Scanning IP Blocks",
        "tactic": "reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/001/",
    },
    "T1595.002": {
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/002/",
    },
    "T1595.003": {
        "name": "Active Scanning: Wordlist Scanning",
        "tactic": "reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/003/",
    },
    "T1590": {
        "name": "Gather Victim Network Information",
        "tactic": "reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1590/",
    },
    "T1592.002": {
        "name": "Gather Victim Host Information: Software",
        "tactic": "reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1592/002/",
    },
    "T1594": {
        "name": "Search Victim-Owned Websites",
        "tactic": "reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1594/",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "discovery",
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
}

# Bundled short wordlist — content discovery, not credential guessing.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "admin",
    "administrator",
    "login",
    "signin",
    "dashboard",
    "console",
    "portal",
    "account",
    "accounts",
    "user",
    "users",
    "auth",
    "oauth",
    "sso",
    "api",
    "api/v1",
    "api/v2",
    "api/docs",
    "swagger",
    "swagger-ui",
    "swagger.json",
    "openapi.json",
    "graphql",
    "graphiql",
    "docs",
    "documentation",
    "redoc",
    "health",
    "healthz",
    "ready",
    "status",
    "info",
    "metrics",
    "prometheus",
    "actuator",
    "actuator/health",
    "server-status",
    "server-info",
    "phpinfo.php",
    "phpmyadmin",
    "wp-admin",
    "wp-login.php",
    "wp-content",
    "wp-json",
    "manager",
    "manager/html",
    "jenkins",
    "jira",
    "confluence",
    "grafana",
    "kibana",
    "uploads",
    "upload",
    "files",
    "static",
    "assets",
    "images",
    "css",
    "js",
    "backup",
    "backups",
    "old",
    "tmp",
    "temp",
    "test",
    "testing",
    "dev",
    "staging",
    "config",
    "configuration",
    "settings",
    "debug",
    "trace",
    "README.md",
    "readme.html",
    "CHANGELOG.md",
    "LICENSE",
    "package.json",
    "composer.json",
    "web.config",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "favicon.ico",
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "security.txt",
    ".well-known/security.txt",
    "humans.txt",
    ".git/HEAD",
    ".svn/entries",
    ".env",
    ".DS_Store",
    ".htaccess",
    "cgi-bin",
    "elmah.axd",
    "trace.axd",
)

SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)

# Simple Wappalyzer-like signatures (header name, regex, product).
FINGERPRINTS: tuple[tuple[str, str, str], ...] = (
    ("header:server", r"(?i)apache(?:/([\d.]+))?", "Apache HTTP Server"),
    ("header:server", r"(?i)nginx(?:/([\d.]+))?", "nginx"),
    ("header:server", r"(?i)microsoft-iis(?:/([\d.]+))?", "Microsoft IIS"),
    ("header:server", r"(?i)litespeed(?:/([\d.]+))?", "LiteSpeed"),
    ("header:server", r"(?i)caddy(?:/([\d.]+))?", "Caddy"),
    ("header:server", r"(?i)openresty(?:/([\d.]+))?", "OpenResty"),
    ("header:server", r"(?i)cloudflare", "Cloudflare"),
    ("header:x-powered-by", r"(?i)php(?:/([\d.]+))?", "PHP"),
    ("header:x-powered-by", r"(?i)asp\.net(?:/?([\d.]+))?", "ASP.NET"),
    ("header:x-powered-by", r"(?i)express(?:/([\d.]+))?", "Express"),
    ("header:x-powered-by", r"(?i)next\.js(?:/?([\d.]+))?", "Next.js"),
    ("header:x-generator", r"(?i)drupal\s*([\d.]+)?", "Drupal"),
    ("header:x-generator", r"(?i)wordpress\s*([\d.]+)?", "WordPress"),
    ("cookie", r"(?i)^PHPSESSID$", "PHP"),
    ("cookie", r"(?i)^JSESSIONID$", "Java / JSP"),
    ("cookie", r"(?i)^ASP\.NET_SessionId$", "ASP.NET"),
    ("cookie", r"(?i)^wordpress_", "WordPress"),
    ("cookie", r"(?i)^wp-settings", "WordPress"),
    ("cookie", r"(?i)^csrftoken$", "Django"),
    ("cookie", r"(?i)^_rails", "Ruby on Rails"),
    ("body", r"(?i)wp-content/|wp-includes/|name=\"generator\"\s+content=\"WordPress", "WordPress"),
    ("body", r"(?i)Drupal\.settings|sites/default/files|name=\"Generator\"\s+content=\"Drupal", "Drupal"),
    ("body", r"(?i)/media/system/js/|content=\"Joomla", "Joomla"),
    ("body", r"(?i)laravel_session|content=\"Laravel", "Laravel"),
    ("body", r"(?i)__next|_next/static", "Next.js"),
    ("body", r"(?i)\breact(?:-dom)?@|data-reactroot", "React"),
    ("body", r"(?i)vue(?:\.runtime)?\.js|data-v-app", "Vue.js"),
    ("body", r"(?i)angular(?:\.min)?\.js|ng-version", "Angular"),
    ("body", r"(?i)jquery(?:-[\d.]+)?(?:\.min)?\.js", "jQuery"),
    ("body", r"(?i)tomcat(?:/([\d.]+))?|Apache Tomcat", "Apache Tomcat"),
    ("body", r"(?i)jenkins(?: ver\.|ersion)|hudson", "Jenkins"),
    ("body", r"(?i)grafana", "Grafana"),
    ("body", r"(?i)kibana", "Kibana"),
    ("body", r"(?i)swagger", "Swagger UI"),
    ("body", r"(?i)graphql", "GraphQL"),
    ("body", r"(?i)django", "Django"),
    ("body", r"(?i)flask", "Flask"),
    ("body", r"(?i)werkzeug", "Werkzeug / Flask"),
    ("body", r"(?i)python(?:'s)?\s+http\.server|SimpleHTTP", "Python http.server"),
    ("header:server", r"(?i)SimpleHTTP(?:/([\d.]+))?", "Python http.server"),
    ("header:server", r"(?i)Werkzeug(?:/([\d.]+))?", "Werkzeug / Flask"),
    ("header:server", r"(?i)gunicorn(?:/([\d.]+))?", "Gunicorn"),
    ("header:server", r"(?i)uvicorn", "Uvicorn"),
    ("header:server", r"(?i)kestrel", "ASP.NET Kestrel"),
    ("header:server", r"(?i)jetty(?:/([\d.]+))?", "Jetty"),
    ("title", r"(?i)phpmyadmin", "phpMyAdmin"),
    ("title", r"(?i)grafana", "Grafana"),
    ("title", r"(?i)jenkins", "Jenkins"),
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
def now_local() -> datetime:
    return datetime.now(LOCAL_TZ)


def iso(ts: datetime | None = None) -> str:
    return (ts or now_local()).isoformat(timespec="seconds")


def attack_label(tid: str) -> str:
    meta = ATTACK_CATALOG.get(tid, {})
    name = meta.get("name", "Unknown technique")
    return f"{tid} {name}"


@dataclass
class Finding:
    title: str
    detail: str
    techniques: list[str]
    severity: str = "info"  # info | low | medium | high
    host: str = ""
    port: int | None = None
    url: str = ""
    category: str = "general"
    evidence: dict[str, Any] = field(default_factory=dict)
    # T1190 may only appear as potential_exposure=True; no exploit is performed.
    potential_exposure: bool = False


@dataclass
class PortRecord:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class HostRecord:
    address: str
    state: str = "unknown"
    hostnames: list[str] = field(default_factory=list)
    ports: list[PortRecord] = field(default_factory=list)
    os_guess: str = ""


@dataclass
class WebTarget:
    host: str
    port: int
    scheme: str
    base_url: str


@dataclass
class WebResult:
    target: WebTarget
    final_url: str = ""
    status: int | None = None
    title: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    missing_headers: list[str] = field(default_factory=list)
    present_headers: dict[str, str] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)
    robots: str = ""
    sitemap: str = ""
    discovered: list[dict[str, Any]] = field(default_factory=list)
    optional_tools: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class RunContext:
    engagement: str
    operator: str
    profile: str
    started_at: str
    finished_at: str = ""
    targets: list[str] = field(default_factory=list)
    scope_entries: list[str] = field(default_factory=list)
    authorization: str = ""
    command: str = ""
    run_dir: str = ""
    phases: list[str] = field(default_factory=list)
    skipped_tools: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Console / progress helpers
# ---------------------------------------------------------------------------
class UI:
    def __init__(self) -> None:
        self.rich = HAS_RICH
        self.console = (
            Console(
                theme=Theme(
                    {
                        "ok": "green",
                        "warn": "yellow",
                        "err": "bold red",
                        "muted": "dim",
                        "accent": "cyan",
                    }
                )
            )
            if HAS_RICH
            else None
        )

    def banner(self) -> None:
        text = (
            f"{TOOL_NAME} v{__version__}  —  authorized reconnaissance only\n"
            "Nmap + web recon, mapped to MITRE ATT&CK Enterprise\n"
            "No exploitation. No credential brute force."
        )
        if self.console:
            self.console.print(
                Panel.fit(text, title=f"[accent]{TOOL_NAME}[/]", border_style="cyan")
            )
        else:
            bar = "=" * 64
            print(f"{bar}\n{text}\n{bar}")

    def info(self, msg: str) -> None:
        self._emit(msg, "accent", prefix="[*]")

    def ok(self, msg: str) -> None:
        self._emit(msg, "ok", prefix="[+]")

    def warn(self, msg: str) -> None:
        self._emit(msg, "warn", prefix="[!]")

    def err(self, msg: str) -> None:
        self._emit(msg, "err", prefix="[-]")

    def muted(self, msg: str) -> None:
        self._emit(msg, "muted", prefix="[.]")

    def _emit(self, msg: str, style: str, prefix: str) -> None:
        if self.console:
            self.console.print(f"[{style}]{prefix}[/{style}] {msg}")
        else:
            print(f"{prefix} {msg}")

    def table(self, title: str, columns: list[str], rows: list[list[str]]) -> None:
        if self.console:
            tbl = Table(title=title, expand=False)
            for col in columns:
                tbl.add_column(col)
            for row in rows:
                tbl.add_row(*[str(c) for c in row])
            self.console.print(tbl)
            return
        print(f"\n{title}")
        print(" | ".join(columns))
        print("-" * 60)
        for row in rows:
            print(" | ".join(str(c) for c in row))


ui = UI()


# ---------------------------------------------------------------------------
# Scope guard
# ---------------------------------------------------------------------------
def _normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


class Scope:
    """Refuse any target that is not fully contained in the authorized scope file."""

    def __init__(self, entries: list[str]) -> None:
        self.entries = entries
        self.networks: list[ipaddress._BaseNetwork] = []
        self.hostnames: set[str] = set()
        self._name_ips: dict[str, list[str]] = {}
        for raw in entries:
            item = raw.strip()
            if not item or item.startswith("#"):
                continue
            if self._try_add_network(item):
                continue
            self.hostnames.add(_normalize_name(item))

    @classmethod
    def from_file(cls, path: Path) -> "Scope":
        if not path.is_file():
            raise FileNotFoundError(f"Scope file not found: {path}")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        entries = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
        if not entries:
            raise ValueError(f"Scope file {path} contains no CIDRs, IPs, or hostnames.")
        return cls(entries)

    def _try_add_network(self, item: str) -> bool:
        try:
            if "/" in item:
                self.networks.append(ipaddress.ip_network(item, strict=False))
            else:
                ip = ipaddress.ip_address(item)
                self.networks.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
            return True
        except ValueError:
            return False

    def resolve_name(self, name: str) -> list[str]:
        key = _normalize_name(name)
        if key in self._name_ips:
            return self._name_ips[key]
        ips: list[str] = []
        try:
            for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(name, None):
                ip = sockaddr[0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror as exc:
            raise ValueError(f"Cannot resolve hostname '{name}': {exc}") from exc
        self._name_ips[key] = ips
        return ips

    def ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def network_in_scope(self, net: ipaddress._BaseNetwork) -> bool:
        return any(net.subnet_of(parent) for parent in self.networks if net.version == parent.version)  # type: ignore[arg-type]

    def hostname_in_scope(self, name: str) -> tuple[bool, list[str]]:
        key = _normalize_name(name)
        ips = self.resolve_name(name)
        if key in self.hostnames:
            # Hostname is listed, but every resolved address must still sit in a scope net
            # *or* we accept it as an explicit named asset. Named assets are allowed
            # even if their IPs were not written as CIDRs; we still record the IPs.
            return True, ips
        if ips and all(self.ip_in_scope(ip) for ip in ips):
            return True, ips
        return False, ips

    def check_token(self, token: str) -> tuple[bool, str, list[str]]:
        """Return (allowed, reason, concrete_targets)."""
        token = token.strip()
        if not token:
            return False, "empty target", []
        # CIDR
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                if self.network_in_scope(net):
                    return True, "cidr in scope", [str(net)]
                return False, f"{token} is not fully contained in the authorized scope", []
        except ValueError:
            pass
        # IP
        try:
            ip = str(ipaddress.ip_address(token))
            if self.ip_in_scope(ip):
                return True, "ip in scope", [ip]
            return False, f"{ip} is outside the authorized scope", []
        except ValueError:
            pass
        # Hostname
        try:
            ok, ips = self.hostname_in_scope(token)
        except ValueError as exc:
            return False, str(exc), []
        if ok:
            return True, "hostname in scope", [token, *ips]
        return (
            False,
            f"{token} (resolved {', '.join(ips) or 'no addresses'}) is outside the authorized scope",
            [],
        )


def enforce_scope(scope: Scope, targets: list[str]) -> list[str]:
    allowed: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for token in targets:
        ok, reason, concrete = scope.check_token(token)
        if not ok:
            rejected.append(f"{token}: {reason}")
            continue
        if token not in seen:
            allowed.append(token)
            seen.add(token)
        ui.muted(f"scope ok: {token} ({reason})")
        for item in concrete:
            if item not in seen and item != token:
                seen.add(item)
    if rejected:
        for item in rejected:
            ui.err(f"OUT OF SCOPE — {item}")
        raise SystemExit(
            "Refusing to run: one or more targets fall outside --scope. "
            "Correct the target list or expand the authorized scope file."
        )
    if not allowed:
        raise SystemExit("No in-scope targets to scan.")
    return allowed


# ---------------------------------------------------------------------------
# Authorization gate + audit log
# ---------------------------------------------------------------------------
def require_authorization(
    *,
    flag_set: bool,
    engagement: str,
    operator: str,
    targets: list[str],
    scope_entries: list[str],
) -> str:
    summary = (
        f"\n  Engagement : {engagement}\n"
        f"  Operator   : {operator}\n"
        f"  Targets    : {', '.join(targets)}\n"
        f"  Scope      : {', '.join(scope_entries)}\n"
        f"  Time       : {iso()} (America/Los_Angeles)\n"
    )
    if flag_set:
        ui.ok("Authorization flag --i-have-authorization accepted and logged.")
        return "flag"
    if not sys.stdin.isatty():
        raise SystemExit(
            "Authorization required. Re-run with --i-have-authorization after you "
            "confirm this engagement is authorized, or run interactively and type "
            f"'{CONFIRM_PHRASE}'."
        )
    print("\n" + "-" * 64)
    print("AUTHORIZED USE ONLY")
    print("This tool may be used solely against systems you have explicit")
    print("permission to test (written engagement, lab, or your own assets).")
    print(summary)
    print("-" * 64)
    try:
        answer = input(f"Type {CONFIRM_PHRASE} to continue: ").strip()
    except EOFError as exc:
        raise SystemExit("Authorization confirmation not received.") from exc
    if answer != CONFIRM_PHRASE:
        raise SystemExit("Authorization not confirmed. Aborting.")
    ui.ok("Interactive authorization confirmed and logged.")
    return "interactive"


def write_audit(run_dir: Path, ctx: RunContext, event: str, extra: str = "") -> None:
    line = f"{iso()}  event={event}  engagement={ctx.engagement}  operator={ctx.operator}  {extra}\n"
    with (run_dir / "audit.log").open("a", encoding="utf-8") as fh:
        fh.write(line)


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
def which_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        raise SystemExit(
            "nmap is not installed or not on PATH. Install it (apt/apk) and retry."
        )
    return path


def run_cmd(
    argv: list[str],
    *,
    timeout: int | None = None,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    import subprocess

    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, out, err or f"timed out after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"{argv[0]} not found"


def nmap_timing(value: int) -> str:
    t = max(0, min(int(value), MAX_TIMING))
    if value > MAX_TIMING:
        ui.warn(f"Timing T{value} is too aggressive; capping at T{MAX_TIMING}.")
    return f"-T{t}"


def parse_nmap_xml(path: Path) -> list[HostRecord]:
    if not path.is_file():
        return []
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        ui.warn(f"Failed to parse nmap XML {path.name}: {exc}")
        return []
    root = tree.getroot()
    hosts: list[HostRecord] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"
        addrs: list[str] = []
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in {"ipv4", "ipv6"}:
                addrs.append(addr_el.get("addr", ""))
        names = [
            hn.get("name", "")
            for hn in host_el.findall("hostnames/hostname")
            if hn.get("name")
        ]
        ports: list[PortRecord] = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            svc_el = port_el.find("service")
            scripts = {
                (sc.get("id") or ""): (sc.get("output") or "")
                for sc in port_el.findall("script")
                if sc.get("id")
            }
            ports.append(
                PortRecord(
                    port=int(port_el.get("portid", "0")),
                    protocol=port_el.get("protocol", "tcp"),
                    state=state_el.get("state", "") if state_el is not None else "",
                    service=(svc_el.get("name") or "") if svc_el is not None else "",
                    product=(svc_el.get("product") or "") if svc_el is not None else "",
                    version=(svc_el.get("version") or "") if svc_el is not None else "",
                    extrainfo=(svc_el.get("extrainfo") or "") if svc_el is not None else "",
                    tunnel=(svc_el.get("tunnel") or "") if svc_el is not None else "",
                    scripts=scripts,
                )
            )
        os_guess = ""
        osmatch = host_el.find("os/osmatch")
        if osmatch is not None:
            acc = osmatch.get("accuracy")
            os_guess = f"{osmatch.get('name', '')} ({acc}% confidence)" if acc else osmatch.get("name", "")
        if not addrs:
            continue
        hosts.append(
            HostRecord(
                address=addrs[0],
                state=state,
                hostnames=names,
                ports=ports,
                os_guess=os_guess,
            )
        )
    return hosts


def merge_hosts(base: list[HostRecord], extra: list[HostRecord]) -> list[HostRecord]:
    by_addr: dict[str, HostRecord] = {h.address: h for h in base}
    for host in extra:
        current = by_addr.get(host.address)
        if current is None:
            by_addr[host.address] = host
            continue
        if host.state == "up":
            current.state = "up"
        for name in host.hostnames:
            if name not in current.hostnames:
                current.hostnames.append(name)
        if host.os_guess and not current.os_guess:
            current.os_guess = host.os_guess
        ports = {(p.protocol, p.port): p for p in current.ports}
        for port in host.ports:
            ports[(port.protocol, port.port)] = port
        current.ports = sorted(ports.values(), key=lambda p: (p.protocol, p.port))
    return list(by_addr.values())


def phase_host_discovery(
    nmap: str,
    targets: list[str],
    run_dir: Path,
    timing: int,
    resume: bool,
) -> list[HostRecord]:
    xml_path = run_dir / "nmap-discovery.xml"
    if resume and xml_path.is_file():
        ui.info("Resuming host discovery from existing nmap-discovery.xml")
        return parse_nmap_xml(xml_path)
    argv = [
        nmap,
        "-sn",
        nmap_timing(timing),
        "--reason",
        "-oX",
        str(xml_path),
        "-oN",
        str(run_dir / "nmap-discovery.nmap"),
        *targets,
    ]
    ui.info("Phase 1/3  Host discovery  " + attack_label("T1595.001") + " / " + attack_label("T1018"))
    ui.muted(" ".join(argv))
    code, out, err = run_cmd(argv, timeout=600)
    (run_dir / "nmap-discovery.stdout.txt").write_text(out + ("\n" + err if err else ""), encoding="utf-8")
    if code != 0 and not xml_path.is_file():
        ui.warn(f"nmap discovery exited {code}: {err.strip() or 'no stderr'}")
    hosts = parse_nmap_xml(xml_path)
    up = [h for h in hosts if h.state == "up"]
    ui.ok(f"Discovery complete: {len(up)} host(s) up, {len(hosts)} reported.")
    return hosts


def _port_args(profile: str, ports: str | None, top_ports: int | None) -> list[str]:
    if ports:
        return ["-p", ports]
    if top_ports:
        return ["--top-ports", str(top_ports)]
    if profile == "quick":
        return ["--top-ports", "100"]
    if profile == "full":
        return ["-p-"]
    return ["--top-ports", "1000"]


def phase_port_scan(
    nmap: str,
    targets: list[str],
    run_dir: Path,
    timing: int,
    profile: str,
    ports: str | None,
    top_ports: int | None,
    resume: bool,
) -> list[HostRecord]:
    xml_path = run_dir / "nmap-ports.xml"
    if resume and xml_path.is_file():
        ui.info("Resuming port scan from existing nmap-ports.xml")
        return parse_nmap_xml(xml_path)
    scripts = ["-sV"]
    if profile in {"standard", "full"}:
        scripts.append("-sC")
    # Non-root environments fall back to TCP connect; -Pn covers hosts that
    # ignore ICMP (common on localhost and filtered lab ranges).
    argv = [
        nmap,
        "-Pn",
        *scripts,
        nmap_timing(timing),
        "--reason",
        "--script-timeout",
        "30s",
        "--max-retries",
        "2",
        *_port_args(profile, ports, top_ports),
        "-oX",
        str(xml_path),
        "-oN",
        str(run_dir / "nmap-ports.nmap"),
        *targets,
    ]
    ui.info("Phase 2/3  Port & service scan  " + attack_label("T1046") + " / " + attack_label("T1592.002"))
    ui.muted(" ".join(argv))
    # Full port scans can be long; give them room, but keep a ceiling.
    timeout = 18_000 if profile == "full" and not ports else 3_600
    code, out, err = run_cmd(argv, timeout=timeout)
    (run_dir / "nmap-ports.stdout.txt").write_text(out + ("\n" + err if err else ""), encoding="utf-8")
    if code != 0 and not xml_path.is_file():
        ui.warn(f"nmap port scan exited {code}: {err.strip() or 'no stderr'}")
    hosts = parse_nmap_xml(xml_path)
    open_ports = sum(1 for h in hosts for p in h.ports if p.state == "open")
    ui.ok(f"Port scan complete: {open_ports} open port(s) across {len(hosts)} host(s).")
    return hosts


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, rate: float) -> None:
        self.interval = 1.0 / max(float(rate), 0.1)
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            if delay > 0:
                time.sleep(delay)
            self._next = time.monotonic() + self.interval


@dataclass
class HttpResponse:
    url: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    error: str = ""
    tls: dict[str, Any] = field(default_factory=dict)


def _header_map(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in items:
        out[key.lower()] = value
    return out


def _tls_info_from_sslsock(ssock: ssl.SSLSocket) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        info["protocol"] = ssock.version()
        info["cipher"] = ssock.cipher()
        cert = ssock.getpeercert()
        if not cert:
            # Unverified context often returns an empty dict; fall back to binary parse.
            raw = ssock.getpeercert(binary_form=True)
            if raw:
                info.update(_parse_der_cert(raw))
        else:
            subject = {k: v for pair in cert.get("subject", ()) for k, v in pair}
            issuer = {k: v for pair in cert.get("issuer", ()) for k, v in pair}
            sans = [v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]
            info.update(
                {
                    "subject": subject,
                    "issuer": issuer,
                    "subject_cn": subject.get("commonName", ""),
                    "issuer_cn": issuer.get("commonName", ""),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "san": sans,
                    "serial": cert.get("serialNumber", ""),
                }
            )
    except Exception as exc:  # pragma: no cover - defensive
        info["error"] = str(exc)
    return info


def _parse_der_cert(der: bytes) -> dict[str, Any]:
    """Best-effort cert summary without third-party crypto libraries."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
    except Exception:
        return {"fingerprint_sha256": _sha256_hex(der), "note": "unparsed DER certificate"}
    return {"pem_present": True, "fingerprint_sha256": _sha256_hex(der), "pem_chars": len(pem)}


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def fetch_url(
    url: str,
    *,
    timeout: float,
    limiter: RateLimiter | None = None,
    method: str = "GET",
    verify: bool = False,
    max_body: int = BODY_FINGERPRINT_LIMIT,
) -> HttpResponse:
    if limiter:
        limiter.wait()
    parsed = urlparse(url)
    tls: dict[str, Any] = {}
    if HAS_REQUESTS:
        try:
            resp = requests_lib.request(  # type: ignore[union-attr]
                method,
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                verify=verify,
                stream=True,
            )
            body = resp.raw.read(max_body, decode_content=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            if parsed.scheme == "https":
                tls = {"verified": bool(verify), "note": "see dedicated TLS probe for certificate details"}
            return HttpResponse(str(resp.url), int(resp.status_code), headers, body, tls=tls)
        except Exception as exc:
            # Fall through to urllib so a requests TLS quirk does not hide the service.
            fallback_error = str(exc)
    else:
        fallback_error = ""

    ctx = ssl._create_unverified_context() if parsed.scheme == "https" else None
    req = urllib.request.Request(
        url,
        method=method,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if parsed.scheme == "https" and isinstance(getattr(resp, "fp", None), object):
                sock = getattr(resp, "fp", None)
                raw = getattr(sock, "raw", None)
                ssock = getattr(raw, "_sock", None) or getattr(resp, "fp", None)
                # urllib wraps the SSL socket a few layers down; try a few attributes.
                for candidate in (
                    getattr(resp, "_connection", None),
                    ssock,
                    getattr(resp, "fp", None),
                ):
                    if isinstance(candidate, ssl.SSLSocket):
                        tls = _tls_info_from_sslsock(candidate)
                        break
            body = resp.read(max_body)
            headers = _header_map(resp.headers.items())
            return HttpResponse(resp.geturl(), int(getattr(resp, "status", 200)), headers, body, tls=tls)
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(max_body)
        except Exception:
            pass
        headers = _header_map(exc.headers.items()) if exc.headers else {}
        return HttpResponse(url, int(exc.code), headers, body, error=str(exc))
    except Exception as exc:
        err = str(exc) or fallback_error
        return HttpResponse(url, None, {}, b"", error=err, tls=tls)


def probe_tls(host: str, port: int, timeout: float) -> dict[str, Any]:
    info: dict[str, Any] = {"host": host, "port": port}
    # First try a verifying handshake so we can report trust problems.
    verified = True
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info.update(_tls_info_from_sslsock(ssock))
                info["verified"] = True
                return info
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["verify_error"] = str(exc)
        verified = False
    except Exception as exc:
        info["error"] = str(exc)
        verified = False
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info.update(_tls_info_from_sslsock(ssock))
                info["verified"] = False if not verified else info.get("verified", False)
    except Exception as exc:
        info["error"] = str(exc)
    return info


def extract_title(body: bytes, content_type: str = "") -> str:
    if "json" in content_type.lower():
        return ""
    text = _decode_body(body)
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def _decode_body(body: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return body.decode(enc)
        except UnicodeDecodeError:
            continue
    return body.decode("utf-8", errors="replace")


def fingerprint(headers: dict[str, str], cookies: list[str], body: str, title: str) -> list[str]:
    found: list[str] = []

    def add(name: str, version: str | None = None) -> None:
        label = f"{name} {version}".strip() if version else name
        if label not in found:
            found.append(label)

    for source, pattern, product in FINGERPRINTS:
        regex = re.compile(pattern)
        if source.startswith("header:"):
            value = headers.get(source.split(":", 1)[1], "")
            match = regex.search(value)
            if match:
                add(product, match.group(1) if match.lastindex else None)
        elif source == "cookie":
            for cookie in cookies:
                if regex.search(cookie):
                    add(product)
        elif source == "body":
            match = regex.search(body)
            if match:
                add(product, match.group(1) if match.lastindex else None)
        elif source == "title":
            if regex.search(title or ""):
                add(product)
    # Header product leftovers
    for hdr in ("server", "x-powered-by", "x-generator", "x-aspnet-version"):
        if headers.get(hdr):
            raw = f"{hdr}: {headers[hdr]}"
            if raw not in found:
                # Only add the raw banner if no signature already captured it.
                already = any(headers[hdr].split("/")[0].lower() in f.lower() for f in found)
                if not already:
                    found.append(raw)
    return found


def cookie_names(headers: dict[str, str]) -> list[str]:
    names: list[str] = []
    # urllib/requests may collapse set-cookie; also accept a joined value.
    value = headers.get("set-cookie", "")
    for part in re.split(r",(?=[^ ;]+=)", value) if value else []:
        name = part.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def audit_security_headers(scheme: str, headers: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    # HSTS is only meaningful on HTTPS.
    if scheme != "https":
        missing = [h for h in missing if h != "strict-transport-security"]
        present.pop("strict-transport-security", None)
    return missing, present


def is_web_port(port: PortRecord) -> bool:
    if port.state != "open":
        return False
    name = (port.service or "").lower()
    if port.port in WEB_PORT_HINTS:
        return True
    if any(hint in name for hint in ("http", "ssl")):
        return True
    if port.tunnel == "ssl" and ("http" in name or not name):
        return True
    # http-title / http-server-header scripts are a strong hint.
    return any(k.startswith("http-") for k in port.scripts)


def web_targets_from_hosts(hosts: list[HostRecord]) -> list[WebTarget]:
    targets: list[WebTarget] = []
    seen: set[tuple[str, int, str]] = set()
    for host in hosts:
        for port in host.ports:
            if not is_web_port(port):
                continue
            name = (port.service or "").lower()
            schemes: list[str] = []
            if port.tunnel == "ssl" or "https" in name or port.port in {443, 8443, 9443, 10443}:
                schemes.append("https")
            if "https" not in name or port.port not in {443, 8443}:
                # Also try HTTP on dual-stack or cleartext ports (including 8080).
                if port.port not in {443, 8443, 9443, 10443} or "http" in name:
                    schemes.append("http")
            if not schemes:
                schemes = ["http"]
            # Prefer https first when both exist, but keep both if they differ.
            for scheme in dict.fromkeys(schemes):
                key = (host.address, port.port, scheme)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    WebTarget(
                        host=host.address,
                        port=port.port,
                        scheme=scheme,
                        base_url=f"{scheme}://{host.address}:{port.port}/",
                    )
                )
    return targets


def load_wordlist(path: Path | None) -> list[str]:
    if path:
        words = [
            ln.strip().lstrip("/")
            for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        return words
    return list(DEFAULT_WORDLIST)


def _same_origin(base: str, other: str) -> bool:
    a, b = urlparse(base), urlparse(other)
    return (a.scheme, a.hostname, a.port or _default_port(a.scheme)) == (
        b.scheme,
        b.hostname,
        b.port or _default_port(b.scheme),
    )


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _store_text(text: str) -> str:
    if len(text) > MAX_TEXT_STORE:
        return text[:MAX_TEXT_STORE] + "\n… [truncated]"
    return text


def content_discovery(
    base_url: str,
    wordlist: list[str],
    *,
    timeout: float,
    rate: float,
    threads: int,
) -> list[dict[str, Any]]:
    limiter = RateLimiter(rate)
    interesting = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500}
    results: list[dict[str, Any]] = []
    lock = threading.Lock()

    def probe(path: str) -> None:
        url = urljoin(base_url, path)
        resp = fetch_url(url, timeout=timeout, limiter=limiter)
        if resp.status is None or resp.status not in interesting:
            return
        # Stay quiet about off-origin redirects; just record the hop.
        rec = {
            "path": "/" + path.lstrip("/"),
            "url": resp.url,
            "status": resp.status,
            "length": len(resp.body),
            "content_type": resp.headers.get("content-type", ""),
            "title": extract_title(resp.body, resp.headers.get("content-type", "")),
            "sensitive_name": bool(SENSITIVE_PATH_RE.search(path)),
        }
        # Never store bodies of potentially sensitive files.
        if rec["sensitive_name"]:
            rec["body_stored"] = False
        with lock:
            results.append(rec)

    workers = max(1, min(threads, 16))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(probe, wordlist))
    results.sort(key=lambda r: (r["status"], r["path"]))
    return results


def detect_optional_tools() -> dict[str, str | None]:
    return {
        "whatweb": shutil.which("whatweb"),
        "nikto": shutil.which("nikto"),
        "gobuster": shutil.which("gobuster"),
        "ffuf": shutil.which("ffuf"),
    }


def run_optional_tools(
    target: WebTarget,
    run_dir: Path,
    wordlist: list[str],
    timeout: float,
    threads: int,
    rate: float,
    skipped: dict[str, str],
) -> dict[str, Any]:
    """Run optional local tools if present. Never fail the engagement if one errors."""
    found = detect_optional_tools()
    out: dict[str, Any] = {}
    tools_dir = run_dir / "optional-tools"
    tools_dir.mkdir(exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{target.host}_{target.port}_{target.scheme}")

    # whatweb — technology fingerprint
    if found["whatweb"]:
        report = tools_dir / f"whatweb_{slug}.txt"
        argv = [found["whatweb"], "--color=never", "--no-errors", "-a", "3", target.base_url]
        code, stdout, stderr = run_cmd(argv, timeout=max(60, int(timeout * 8)))
        report.write_text(stdout or stderr, encoding="utf-8")
        out["whatweb"] = {"exit": code, "output": _store_text(stdout.strip() or stderr.strip())}
    else:
        skipped.setdefault("whatweb", "not installed (shutil.which returned None)")

    # nikto — configuration / known-file checks only; we do not enable exploit plugins
    if found["nikto"]:
        report = tools_dir / f"nikto_{slug}.txt"
        argv = [
            found["nikto"],
            "-h",
            target.base_url,
            "-Tuning",
            "1",  # interesting files; not injection/exploit tests
            "-nointeractive",
            "-output",
            str(report),
        ]
        code, stdout, stderr = run_cmd(argv, timeout=300)
        text = report.read_text(encoding="utf-8", errors="replace") if report.is_file() else (stdout or stderr)
        out["nikto"] = {"exit": code, "output": _store_text(text)}
    else:
        skipped.setdefault("nikto", "not installed (shutil.which returned None)")

    # Prefer ffuf over gobuster if both exist, so the target is not double-hit
    # with the same short wordlist.
    wordlist_path = tools_dir / "wordlist-short.txt"
    if not wordlist_path.is_file():
        wordlist_path.write_text("\n".join(wordlist) + "\n", encoding="utf-8")

    if found["ffuf"]:
        report = tools_dir / f"ffuf_{slug}.json"
        argv = [
            found["ffuf"],
            "-u",
            target.base_url.rstrip("/") + "/FUZZ",
            "-w",
            str(wordlist_path),
            "-of",
            "json",
            "-o",
            str(report),
            "-t",
            str(max(1, min(threads, 8))),
            "-rate",
            str(max(1, int(rate))),
            "-timeout",
            str(max(2, int(timeout))),
            "-mc",
            "200,201,204,301,302,307,308,401,403",
            "-s",
        ]
        code, stdout, stderr = run_cmd(argv, timeout=300)
        payload: Any = stdout
        if report.is_file():
            try:
                payload = json.loads(report.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload = report.read_text(encoding="utf-8", errors="replace")
        out["ffuf"] = {"exit": code, "output": payload if not isinstance(payload, str) else _store_text(payload)}
        skipped.setdefault("gobuster", "skipped because ffuf is available (avoid duplicate wordlist hits)")
    else:
        skipped.setdefault("ffuf", "not installed (shutil.which returned None)")
        if found["gobuster"]:
            report = tools_dir / f"gobuster_{slug}.txt"
            argv = [
                found["gobuster"],
                "dir",
                "-u",
                target.base_url,
                "-w",
                str(wordlist_path),
                "-q",
                "-t",
                str(max(1, min(threads, 8))),
                "--delay",
                f"{max(1.0 / max(rate, 0.1), 0.05):.2f}s",
                "-o",
                str(report),
                "--timeout",
                f"{max(2, int(timeout))}s",
                "-s",
                "200,201,204,301,302,307,308,401,403",
            ]
            code, stdout, stderr = run_cmd(argv, timeout=300)
            text = report.read_text(encoding="utf-8", errors="replace") if report.is_file() else (stdout or stderr)
            out["gobuster"] = {"exit": code, "output": _store_text(text)}
        else:
            skipped.setdefault("gobuster", "not installed (shutil.which returned None)")
    return out


def phase_web_recon(
    hosts: list[HostRecord],
    run_dir: Path,
    *,
    profile: str,
    timeout: float,
    rate: float,
    threads: int,
    wordlist_path: Path | None,
    use_optional: bool,
    skipped_tools: dict[str, str],
    do_discovery: bool,
) -> list[WebResult]:
    targets = web_targets_from_hosts(hosts)
    ui.info(
        "Phase 3/3  Web recon  "
        + attack_label("T1594")
        + " / "
        + attack_label("T1595.003")
        + " / "
        + attack_label("T1592.002")
    )
    if not targets:
        ui.warn("No HTTP/HTTPS services discovered; skipping web recon.")
        return []
    ui.info(f"Probing {len(targets)} web endpoint(s).")
    wordlist = load_wordlist(wordlist_path)
    limiter = RateLimiter(rate)
    results: list[WebResult] = []

    def work(tgt: WebTarget) -> WebResult:
        result = WebResult(target=tgt)
        home = fetch_url(tgt.base_url, timeout=timeout, limiter=limiter)
        if home.error and home.status is None:
            result.errors.append(home.error)
            # If http failed on a likely TLS port (or vice versa) we still record it.
            return result
        result.final_url = home.url or tgt.base_url
        result.status = home.status
        result.headers = home.headers
        result.cookies = cookie_names(home.headers)
        result.title = extract_title(home.body, home.headers.get("content-type", ""))
        body_text = _decode_body(home.body)
        result.technologies = fingerprint(home.headers, result.cookies, body_text, result.title)
        result.missing_headers, result.present_headers = audit_security_headers(tgt.scheme, home.headers)
        if tgt.scheme == "https":
            result.tls = probe_tls(tgt.host, tgt.port, timeout)
        # robots / sitemap — Search Victim-Owned Websites (T1594)
        for name, attr in (("robots.txt", "robots"), ("sitemap.xml", "sitemap")):
            resp = fetch_url(urljoin(tgt.base_url, name), timeout=timeout, limiter=limiter)
            if resp.status and resp.status < 400 and resp.body:
                ctype = resp.headers.get("content-type", "")
                if "html" in ctype.lower() and name.endswith(".xml"):
                    continue
                setattr(result, attr, _store_text(_decode_body(resp.body)))
        if do_discovery:
            result.discovered = content_discovery(
                tgt.base_url,
                wordlist,
                timeout=timeout,
                rate=rate,
                threads=threads,
            )
        if use_optional:
            result.optional_tools = run_optional_tools(
                tgt, run_dir, wordlist, timeout, threads, rate, skipped_tools
            )
        return result

    workers = max(1, min(4, len(targets)))
    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=ui.console,
        ) as progress:
            task = progress.add_task("Web recon", total=len(targets))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(work, t): t for t in targets}
                for fut in concurrent.futures.as_completed(futs):
                    results.append(fut.result())
                    progress.advance(task)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for i, result in enumerate(pool.map(work, targets), 1):
                results.append(result)
                ui.muted(f"web recon {i}/{len(targets)} {result.target.base_url} status={result.status}")

    results.sort(key=lambda r: (r.target.host, r.target.port, r.target.scheme))
    ok = sum(1 for r in results if r.status)
    ui.ok(f"Web recon complete: {ok}/{len(results)} endpoint(s) responded.")
    return results


# ---------------------------------------------------------------------------
# Findings + ATT&CK coverage
# ---------------------------------------------------------------------------
def collect_findings(
    ctx: RunContext,
    hosts: list[HostRecord],
    web: list[WebResult],
    phases: set[str],
) -> list[Finding]:
    findings: list[Finding] = []

    if "discover" in phases:
        findings.append(
            Finding(
                title="Host discovery scan executed",
                detail=f"nmap -sn against {', '.join(ctx.targets)} ({len(hosts)} host record(s)).",
                techniques=["T1595.001", "T1018", "T1590"],
                category="scan",
            )
        )
    if "ports" in phases:
        findings.append(
            Finding(
                title="Network service discovery scan executed",
                detail="nmap version/service scan (-sV, and -sC unless profile=quick).",
                techniques=["T1046", "T1595.001", "T1592.002"],
                category="scan",
            )
        )

    for host in hosts:
        open_ports = [p for p in host.ports if p.state == "open"]
        if open_ports:
            summary = ", ".join(f"{p.port}/{p.protocol} ({p.service or 'unknown'})" for p in open_ports)
            findings.append(
                Finding(
                    title=f"Open services on {host.address}",
                    detail=summary,
                    techniques=["T1046", "T1590"],
                    host=host.address,
                    category="host",
                    evidence={"ports": [asdict(p) for p in open_ports]},
                )
            )
        for port in open_ports:
            banner = " ".join(x for x in (port.product, port.version, port.extrainfo) if x)
            if banner or port.service:
                findings.append(
                    Finding(
                        title=f"Service fingerprint {host.address}:{port.port}",
                        detail=banner or port.service,
                        techniques=["T1592.002", "T1046"],
                        host=host.address,
                        port=port.port,
                        category="service",
                        severity="info",
                    )
                )

    for item in web:
        tgt = item.target
        if item.status:
            findings.append(
                Finding(
                    title=f"Website reached {tgt.base_url}",
                    detail=f"HTTP {item.status} title={item.title!r} techs={', '.join(item.technologies) or 'n/a'}",
                    techniques=["T1594", "T1592.002"],
                    host=tgt.host,
                    port=tgt.port,
                    url=item.final_url or tgt.base_url,
                    category="web",
                )
            )
        if item.technologies:
            findings.append(
                Finding(
                    title=f"Software identified on {tgt.base_url}",
                    detail=", ".join(item.technologies),
                    techniques=["T1592.002"],
                    host=tgt.host,
                    port=tgt.port,
                    url=item.final_url or tgt.base_url,
                    category="fingerprint",
                )
            )
        if item.missing_headers:
            sev = "medium" if tgt.scheme == "https" else "low"
            findings.append(
                Finding(
                    title=f"Missing security headers on {tgt.base_url}",
                    detail="Absent: " + ", ".join(item.missing_headers),
                    techniques=["T1595.002"],
                    severity=sev,
                    host=tgt.host,
                    port=tgt.port,
                    url=item.final_url or tgt.base_url,
                    category="headers",
                    evidence={"present": item.present_headers, "missing": item.missing_headers},
                )
            )
        if item.tls:
            if item.tls.get("verified") is False:
                findings.append(
                    Finding(
                        title=f"TLS certificate not trusted for {tgt.host}:{tgt.port}",
                        detail=item.tls.get("verify_error") or item.tls.get("error") or "Verification failed",
                        techniques=["T1595.002", "T1590"],
                        severity="low",
                        host=tgt.host,
                        port=tgt.port,
                        url=tgt.base_url,
                        category="tls",
                        evidence=item.tls,
                    )
                )
            elif item.tls.get("subject_cn") or item.tls.get("fingerprint_sha256"):
                findings.append(
                    Finding(
                        title=f"TLS certificate collected for {tgt.host}:{tgt.port}",
                        detail=json.dumps(
                            {k: item.tls[k] for k in ("subject_cn", "issuer_cn", "not_after", "protocol") if k in item.tls}
                        ),
                        techniques=["T1590", "T1592.002"],
                        host=tgt.host,
                        port=tgt.port,
                        url=tgt.base_url,
                        category="tls",
                        evidence=item.tls,
                    )
                )
        if item.robots:
            findings.append(
                Finding(
                    title=f"robots.txt available at {tgt.base_url}",
                    detail="Disallowed or listed paths may guide further authorized mapping.",
                    techniques=["T1594"],
                    host=tgt.host,
                    port=tgt.port,
                    url=urljoin(tgt.base_url, "robots.txt"),
                    category="robots",
                    evidence={"snippet": item.robots[:2000]},
                )
            )
        if item.sitemap:
            findings.append(
                Finding(
                    title=f"sitemap.xml available at {tgt.base_url}",
                    detail="Sitemap contents can reveal additional application paths.",
                    techniques=["T1594"],
                    host=tgt.host,
                    port=tgt.port,
                    url=urljoin(tgt.base_url, "sitemap.xml"),
                    category="sitemap",
                )
            )
        if item.discovered:
            findings.append(
                Finding(
                    title=f"Wordlist content discovery on {tgt.base_url}",
                    detail=f"{len(item.discovered)} interesting path(s) (status 2xx/3xx/401/403).",
                    techniques=["T1595.003", "T1594"],
                    host=tgt.host,
                    port=tgt.port,
                    url=tgt.base_url,
                    category="discovery",
                    evidence={"count": len(item.discovered)},
                )
            )
        for rec in item.discovered:
            if rec.get("sensitive_name") and rec.get("status") in {200, 201, 204}:
                findings.append(
                    Finding(
                        title=f"Potential exposure: {rec['path']} returned HTTP {rec['status']}",
                        detail=(
                            "A path whose name is commonly associated with secrets or source "
                            "control responded successfully. Contents were NOT retrieved into "
                            "the report. Treat as a potential exposure only — no exploit was attempted."
                        ),
                        techniques=["T1595.003", "T1190"],
                        severity="high",
                        host=tgt.host,
                        port=tgt.port,
                        url=rec.get("url", ""),
                        category="exposure",
                        potential_exposure=True,
                        evidence={"status": rec["status"], "length": rec["length"], "content_type": rec.get("content_type")},
                    )
                )
            elif rec.get("path") in {"/server-status", "/server-info", "/phpinfo.php", "/actuator", "/debug", "/console", "/manager/html"} and rec.get("status") == 200:
                findings.append(
                    Finding(
                        title=f"Potential exposure: {rec['path']} is reachable",
                        detail="A diagnostic or management endpoint returned HTTP 200. No exploit was attempted.",
                        techniques=["T1595.003", "T1190"],
                        severity="medium",
                        host=tgt.host,
                        port=tgt.port,
                        url=rec.get("url", ""),
                        category="exposure",
                        potential_exposure=True,
                    )
                )
        for tool_name, payload in item.optional_tools.items():
            tech = "T1592.002" if tool_name == "whatweb" else "T1595.002" if tool_name == "nikto" else "T1595.003"
            findings.append(
                Finding(
                    title=f"{tool_name} ran against {tgt.base_url}",
                    detail=f"Optional tool exit={payload.get('exit')}",
                    techniques=[tech],
                    host=tgt.host,
                    port=tgt.port,
                    url=tgt.base_url,
                    category="optional-tool",
                )
            )
    return findings


def coverage_from_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {tid: 0 for tid in ATTACK_CATALOG}
    notes: dict[str, list[str]] = {tid: [] for tid in ATTACK_CATALOG}
    for finding in findings:
        for tid in finding.techniques:
            if tid not in counts:
                counts[tid] = 0
                notes[tid] = []
            counts[tid] += 1
            if finding.title not in notes[tid] and len(notes[tid]) < 8:
                notes[tid].append(finding.title)
    rows = []
    for tid, meta in ATTACK_CATALOG.items():
        rows.append(
            {
                "id": tid,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "url": meta["url"],
                "count": counts.get(tid, 0),
                "used": counts.get(tid, 0) > 0,
                "examples": notes.get(tid, []),
                "potential_exposure_only": tid == "T1190",
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
def findings_to_json(findings: list[Finding]) -> list[dict[str, Any]]:
    rows = []
    for f in findings:
        rows.append(
            {
                "title": f.title,
                "detail": f.detail,
                "techniques": f.techniques,
                "technique_labels": [attack_label(t) for t in f.techniques],
                "severity": f.severity,
                "host": f.host,
                "port": f.port,
                "url": f.url,
                "category": f.category,
                "potential_exposure": f.potential_exposure,
                "evidence": f.evidence,
            }
        )
    return rows


def write_json_report(
    path: Path,
    ctx: RunContext,
    hosts: list[HostRecord],
    web: list[WebResult],
    findings: list[Finding],
    coverage: list[dict[str, Any]],
) -> None:
    payload = {
        "meta": asdict(ctx),
        "hosts": [
            {
                **asdict(h),
                "ports": [asdict(p) for p in h.ports],
            }
            for h in hosts
        ],
        "web": [
            {
                "target": asdict(w.target),
                "final_url": w.final_url,
                "status": w.status,
                "title": w.title,
                "headers": w.headers,
                "cookies": w.cookies,
                "technologies": w.technologies,
                "missing_headers": w.missing_headers,
                "present_headers": w.present_headers,
                "tls": w.tls,
                "robots": w.robots,
                "sitemap": w.sitemap,
                "discovered": w.discovered,
                "optional_tools": w.optional_tools,
                "errors": w.errors,
            }
            for w in web
        ],
        "findings": findings_to_json(findings),
        "attack_coverage": coverage,
    }
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def write_navigator_layer(path: Path, ctx: RunContext, coverage: list[dict[str, Any]]) -> dict[str, Any]:
    techniques = []
    max_score = max((row["count"] for row in coverage if row["used"]), default=1)
    for row in coverage:
        if not row["used"]:
            continue
        comment = "; ".join(row["examples"])
        if row["potential_exposure_only"]:
            comment = "POTENTIAL EXPOSURE ONLY — no exploit attempted. " + comment
        techniques.append(
            {
                "techniqueID": row["id"],
                "tactic": row["tactic"],
                "score": row["count"],
                "color": "",
                "comment": comment,
                "enabled": True,
                "metadata": [],
                "links": [{"label": "MITRE ATT&CK", "url": row["url"]}],
                "showSubtechniques": row["id"] in {"T1595", "T1590"} or row["id"].count(".") == 0,
            }
        )
        # If a sub-technique is used, also enable the parent so Navigator expands it.
        if "." in row["id"]:
            parent = row["id"].split(".")[0]
            if not any(t["techniqueID"] == parent and t.get("tactic") == row["tactic"] for t in techniques):
                parent_meta = ATTACK_CATALOG.get(parent, {"name": parent, "tactic": row["tactic"], "url": f"https://attack.mitre.org/techniques/{parent}/"})
                techniques.append(
                    {
                        "techniqueID": parent,
                        "tactic": parent_meta.get("tactic", row["tactic"]),
                        "score": 0,
                        "enabled": True,
                        "showSubtechniques": True,
                        "comment": f"Parent of used sub-technique(s); see {row['id']}",
                        "metadata": [],
                        "links": [{"label": "MITRE ATT&CK", "url": parent_meta.get("url", "")}],
                    }
                )
    layer = {
        "name": f"{TOOL_NAME} — {ctx.engagement}",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": NAVIGATOR_LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": (
            f"Authorized reconnaissance coverage for engagement '{ctx.engagement}' "
            f"by {ctx.operator} at {ctx.started_at} (America/Los_Angeles). "
            "T1190, if present, is a potential-exposure tag only; this layer is not evidence of exploitation."
        ),
        "filters": {
            "platforms": [
                "Windows",
                "Linux",
                "macOS",
                "Network",
                "PRE",
            ]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#d8f3dc", "#52b69a", "#1b4332"],
            "minValue": 0,
            "maxValue": max(max_score, 1),
        },
        "legendItems": [
            {"label": "Recon technique observed", "color": "#52b69a"},
            {"label": "T1190 = potential exposure only (not exploited)", "color": "#e07a5f"},
        ],
        "metadata": [
            {"name": "engagement", "value": ctx.engagement},
            {"name": "operator", "value": ctx.operator},
            {"name": "profile", "value": ctx.profile},
            {"name": "tool", "value": f"{TOOL_NAME} {__version__}"},
        ],
        "links": [
            {"label": "ATT&CK Navigator", "url": "https://mitre-attack.github.io/attack-navigator/"}
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
    path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    return layer


def write_markdown(
    path: Path,
    ctx: RunContext,
    hosts: list[HostRecord],
    web: list[WebResult],
    findings: list[Finding],
    coverage: list[dict[str, Any]],
) -> None:
    lines: list[str] = []
    a = lines.append
    a(f"# {TOOL_NAME} report — {ctx.engagement}")
    a("")
    a("**Authorized use only.** This report documents reconnaissance. No exploitation was performed.")
    a("")
    a("## Engagement")
    a("")
    a("| Field | Value |")
    a("| --- | --- |")
    a(f"| Engagement | {ctx.engagement} |")
    a(f"| Operator | {ctx.operator} |")
    a(f"| Profile | {ctx.profile} |")
    a(f"| Started | {ctx.started_at} (America/Los_Angeles) |")
    a(f"| Finished | {ctx.finished_at} (America/Los_Angeles) |")
    a(f"| Authorization | {ctx.authorization} |")
    a(f"| Targets | {', '.join(ctx.targets)} |")
    a(f"| Scope | {', '.join(ctx.scope_entries)} |")
    a(f"| Run directory | `{ctx.run_dir}` |")
    a("")
    a("## Summary")
    a("")
    open_ports = sum(1 for h in hosts for p in h.ports if p.state == "open")
    ups = sum(1 for h in hosts if h.state == "up")
    exposures = sum(1 for f in findings if f.potential_exposure)
    a(f"- Hosts reported: **{len(hosts)}** ({ups} up)")
    a(f"- Open ports: **{open_ports}**")
    a(f"- Web endpoints: **{len(web)}**")
    a(f"- Findings: **{len(findings)}**")
    a(f"- Potential exposures (T1190 tag only): **{exposures}**")
    a(f"- ATT&CK techniques observed: **{sum(1 for r in coverage if r['used'])}** / {len(coverage)}")
    a("")
    if ctx.skipped_tools:
        a("## Optional tools skipped")
        a("")
        for name, reason in ctx.skipped_tools.items():
            a(f"- `{name}`: {reason}")
        a("")
    a("## Hosts and ports")
    a("")
    a("| Host | Names | Port | Proto | State | Service | Product |")
    a("| --- | --- | --- | --- | --- | --- | --- |")
    if not any(h.ports for h in hosts):
        a("| — | — | — | — | — | — | — |")
    for host in hosts:
        names = ", ".join(host.hostnames) or "—"
        if not host.ports:
            a(f"| {host.address} | {names} | — | — | {host.state} | — | — |")
            continue
        for port in host.ports:
            product = " ".join(x for x in (port.product, port.version) if x) or "—"
            a(
                f"| {host.address} | {names} | {port.port} | {port.protocol} | "
                f"{port.state} | {port.service or '—'} | {product} |"
            )
    a("")
    a("## Web findings")
    a("")
    if not web:
        a("_No HTTP/HTTPS services were probed._")
        a("")
    for item in web:
        tgt = item.target
        a(f"### {tgt.base_url}")
        a("")
        a(f"- Status: `{item.status}`")
        a(f"- Final URL: {item.final_url or '—'}")
        a(f"- Title: {item.title or '—'}")
        a(f"- Technologies: {', '.join(item.technologies) or '—'}")
        a(f"- Missing security headers: {', '.join(item.missing_headers) or 'none'}")
        if item.tls:
            a(f"- TLS: verified={item.tls.get('verified')} protocol={item.tls.get('protocol')} CN={item.tls.get('subject_cn') or item.tls.get('fingerprint_sha256', '—')}")
        if item.robots:
            a("- robots.txt: present (see JSON report for full text)")
        if item.sitemap:
            a("- sitemap.xml: present")
        if item.discovered:
            a("")
            a("| Path | Status | Length | Title |")
            a("| --- | --- | --- | --- |")
            for rec in item.discovered:
                a(f"| `{rec['path']}` | {rec['status']} | {rec['length']} | {rec.get('title') or '—'} |")
        if item.errors:
            a("")
            a("Errors:")
            for err in item.errors:
                a(f"- {err}")
        a("")
    a("## ATT&CK technique coverage")
    a("")
    a("| ID | Name | Tactic | Count | Notes |")
    a("| --- | --- | --- | --- | --- |")
    for row in coverage:
        note = "potential exposure only" if row["potential_exposure_only"] else (", ".join(row["examples"][:3]) or "—")
        a(f"| [{row['id']}]({row['url']}) | {row['name']} | {row['tactic']} | {row['count']} | {note} |")
    a("")
    a("Import `attack-navigator.json` into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).")
    a("")
    a("## Finding log")
    a("")
    for f in findings:
        techs = ", ".join(f.techniques)
        flag = " **(potential exposure — not exploited)**" if f.potential_exposure else ""
        a(f"- **[{f.severity}]** {f.title}{flag} — {f.detail} — `{techs}`")
    a("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def write_html(
    path: Path,
    ctx: RunContext,
    hosts: list[HostRecord],
    web: list[WebResult],
    findings: list[Finding],
    coverage: list[dict[str, Any]],
    layer: dict[str, Any],
) -> None:
    open_ports = sum(1 for h in hosts for p in h.ports if p.state == "open")
    ups = sum(1 for h in hosts if h.state == "up")
    exposures = sum(1 for f in findings if f.potential_exposure)
    used = sum(1 for r in coverage if r["used"])
    host_rows = []
    for host in hosts:
        names = ", ".join(host.hostnames) or "—"
        if not host.ports:
            host_rows.append(
                f"<tr><td>{_esc(host.address)}</td><td>{_esc(names)}</td><td>—</td><td>—</td>"
                f"<td>{_esc(host.state)}</td><td>—</td><td>—</td></tr>"
            )
        for port in host.ports:
            product = " ".join(x for x in (port.product, port.version) if x) or "—"
            state_cls = "ok" if port.state == "open" else "muted"
            host_rows.append(
                "<tr>"
                f"<td>{_esc(host.address)}</td><td>{_esc(names)}</td>"
                f"<td>{port.port}</td><td>{_esc(port.protocol)}</td>"
                f"<td class='{state_cls}'>{_esc(port.state)}</td>"
                f"<td>{_esc(port.service or '—')}</td><td>{_esc(product)}</td>"
                "</tr>"
            )
    web_sections = []
    for item in web:
        tgt = item.target
        disc_rows = "".join(
            "<tr>"
            f"<td><code>{_esc(rec['path'])}</code></td>"
            f"<td>{_esc(rec['status'])}</td>"
            f"<td>{_esc(rec['length'])}</td>"
            f"<td>{_esc(rec.get('content_type') or '—')}</td>"
            f"<td>{_esc(rec.get('title') or '—')}</td>"
            "</tr>"
            for rec in item.discovered
        ) or "<tr><td colspan='5' class='muted'>No interesting paths (or discovery skipped).</td></tr>"
        hdr_list = "".join(f"<li><code>{_esc(h)}</code></li>" for h in item.missing_headers) or "<li class='ok'>None missing from the standard set.</li>"
        tech = ", ".join(item.technologies) or "—"
        tls_txt = "—"
        if item.tls:
            tls_txt = (
                f"verified={item.tls.get('verified')} "
                f"protocol={item.tls.get('protocol') or '—'} "
                f"CN={item.tls.get('subject_cn') or '—'} "
                f"issuer={item.tls.get('issuer_cn') or '—'}"
            )
        err = "".join(f"<li>{_esc(e)}</li>" for e in item.errors)
        web_sections.append(
            f"""
            <article class="card">
              <h3>{_esc(tgt.base_url)}</h3>
              <ul class="kv">
                <li><span>Status</span><code>{_esc(item.status)}</code></li>
                <li><span>Final URL</span><code>{_esc(item.final_url or '—')}</code></li>
                <li><span>Title</span>{_esc(item.title or '—')}</li>
                <li><span>Technologies</span>{_esc(tech)}</li>
                <li><span>TLS</span>{_esc(tls_txt)}</li>
                <li><span>robots.txt</span>{'present' if item.robots else 'not found'}</li>
                <li><span>sitemap.xml</span>{'present' if item.sitemap else 'not found'}</li>
              </ul>
              <h4>Missing security headers</h4>
              <ul>{hdr_list}</ul>
              <h4>Content discovery</h4>
              <table>
                <thead><tr><th>Path</th><th>Status</th><th>Length</th><th>Type</th><th>Title</th></tr></thead>
                <tbody>{disc_rows}</tbody>
              </table>
              {"<h4>Errors</h4><ul>" + err + "</ul>" if err else ""}
            </article>
            """
        )
    cov_rows = []
    for row in coverage:
        cls = "ok" if row["used"] else "muted"
        note = "potential exposure only — not exploited" if row["potential_exposure_only"] and row["used"] else (_esc("; ".join(row["examples"][:3])) or "—")
        cov_rows.append(
            "<tr>"
            f"<td><a href='{_esc(row['url'])}'>{_esc(row['id'])}</a></td>"
            f"<td>{_esc(row['name'])}</td>"
            f"<td>{_esc(row['tactic'])}</td>"
            f"<td class='{cls}'>{row['count']}</td>"
            f"<td>{note}</td>"
            "</tr>"
        )
    finding_items = []
    for f in findings:
        badges = "".join(f"<a class='tid' href='{_esc(ATTACK_CATALOG.get(t, {}).get('url', '#'))}'>{_esc(t)}</a>" for t in f.techniques)
        expo = " <span class='pill warn'>potential exposure</span>" if f.potential_exposure else ""
        finding_items.append(
            f"<li class='sev-{_esc(f.severity)}'><strong>[{_esc(f.severity)}]</strong> {_esc(f.title)}{expo}"
            f"<div class='muted'>{_esc(f.detail)}</div>{badges}</li>"
        )
    skipped = "".join(f"<li><code>{_esc(k)}</code> — {_esc(v)}</li>" for k, v in ctx.skipped_tools.items()) or "<li class='muted'>None recorded.</li>"
    layer_json = json.dumps(layer, indent=2)
    css = """
    :root { --bg:#0b1220; --card:#121b2f; --ink:#e8eefc; --muted:#93a0b8; --line:#243049;
            --accent:#5ec8ff; --ok:#3ecf8e; --warn:#e0b25d; --high:#e05d5d; --low:#7aa2f7; }
    * { box-sizing:border-box; }
    body { margin:0; font:15px/1.55 "Segoe UI", system-ui, sans-serif; background:var(--bg); color:var(--ink); }
    header { padding:32px 40px 16px; border-bottom:1px solid var(--line); background:linear-gradient(180deg,#15233c,var(--bg)); }
    header p { color:var(--muted); margin:6px 0 0; }
    h1 { margin:0; font-size:28px; letter-spacing:-.02em; }
    h2 { margin:32px 0 12px; font-size:20px; }
    h3 { margin:0 0 8px; }
    main { padding:24px 40px 64px; max-width:1200px; }
    .metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; }
    .metric { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; }
    .metric b { display:block; font-size:28px; }
    .metric span { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px 20px; margin:12px 0; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th,td { padding:8px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
    th { color:var(--muted); font-weight:600; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }
    a { color:var(--accent); text-decoration:none; }
    a:hover { text-decoration:underline; }
    .ok { color:var(--ok); } .muted { color:var(--muted); }
    .pill { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px; background:#3a2a12; color:var(--warn); }
    .tid { display:inline-block; margin:4px 6px 0 0; padding:1px 6px; border:1px solid var(--line); border-radius:6px; font-size:11px; }
    .kv { list-style:none; padding:0; margin:0 0 12px; }
    .kv li { margin:4px 0; } .kv span { display:inline-block; width:160px; color:var(--muted); }
    .sev-high { border-left:3px solid var(--high); padding-left:10px; margin:8px 0; }
    .sev-medium { border-left:3px solid var(--warn); padding-left:10px; margin:8px 0; }
    .sev-low { border-left:3px solid var(--low); padding-left:10px; margin:8px 0; }
    .sev-info { border-left:3px solid var(--line); padding-left:10px; margin:8px 0; }
    footer { color:var(--muted); font-size:12px; padding:20px 40px 40px; }
    button { background:#1e3a5f; color:var(--ink); border:1px solid var(--accent); border-radius:8px; padding:8px 14px; cursor:pointer; }
    """
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_esc(TOOL_NAME)} — {_esc(ctx.engagement)}</title>
  <style>{css}</style>
</head>
<body>
  <header>
    <h1>{_esc(TOOL_NAME)} report</h1>
    <p>Engagement <strong>{_esc(ctx.engagement)}</strong> · Operator {_esc(ctx.operator)} · Profile {_esc(ctx.profile)}
       · { _esc(ctx.started_at) } – { _esc(ctx.finished_at) } (America/Los_Angeles)</p>
    <p>Authorized reconnaissance only. No exploitation and no credential brute force were performed.</p>
  </header>
  <main>
    <section>
      <h2>Summary</h2>
      <div class="metrics">
        <div class="metric"><span>Hosts</span><b>{len(hosts)}</b><span>{ups} up</span></div>
        <div class="metric"><span>Open ports</span><b>{open_ports}</b></div>
        <div class="metric"><span>Web endpoints</span><b>{len(web)}</b></div>
        <div class="metric"><span>Findings</span><b>{len(findings)}</b></div>
        <div class="metric"><span>Potential exposures</span><b>{exposures}</b><span>T1190 tag only</span></div>
        <div class="metric"><span>ATT&amp;CK techniques</span><b>{used}</b><span>of {len(coverage)}</span></div>
      </div>
      <div class="card">
        <p><strong>Targets:</strong> {_esc(', '.join(ctx.targets))}<br>
           <strong>Scope:</strong> {_esc(', '.join(ctx.scope_entries))}<br>
           <strong>Authorization:</strong> {_esc(ctx.authorization)} · <strong>Run dir:</strong> <code>{_esc(ctx.run_dir)}</code></p>
      </div>
    </section>
    <section>
      <h2>Hosts and ports</h2>
      <div class="card">
        <table>
          <thead><tr><th>Host</th><th>Names</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product</th></tr></thead>
          <tbody>
            {''.join(host_rows) or '<tr><td colspan="7" class="muted">No hosts.</td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
    <section>
      <h2>Web findings</h2>
      {''.join(web_sections) or '<div class="card muted">No HTTP/HTTPS services were probed.</div>'}
    </section>
    <section>
      <h2>ATT&amp;CK technique coverage</h2>
      <div class="card">
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Count</th><th>Notes</th></tr></thead>
          <tbody>{''.join(cov_rows)}</tbody>
        </table>
        <p><button type="button" id="dl">Download ATT&amp;CK Navigator layer JSON</button>
           Import the file at <a href="https://mitre-attack.github.io/attack-navigator/">ATT&amp;CK Navigator</a>.</p>
      </div>
    </section>
    <section>
      <h2>Finding log</h2>
      <ul>{''.join(finding_items)}</ul>
    </section>
    <section>
      <h2>Optional tools skipped</h2>
      <ul>{skipped}</ul>
    </section>
  </main>
  <footer>Generated by {_esc(TOOL_NAME)} v{_esc(__version__)} for authorized engagements only.</footer>
  <script type="application/json" id="nav-layer">{layer_json}</script>
  <script>
    document.getElementById('dl').addEventListener('click', () => {{
      const data = document.getElementById('nav-layer').textContent;
      const blob = new Blob([data], {{type: 'application/json'}});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'attack-navigator.json';
      a.click();
      URL.revokeObjectURL(a.href);
    }});
  </script>
</body>
</html>
"""
    path.write_text(doc, encoding="utf-8")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
PROFILE_PHASES = {
    "quick": {"discover", "ports", "web"},
    "standard": {"discover", "ports", "web"},
    "full": {"discover", "ports", "web"},
}


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
    return slug or "engagement"


def make_run_dir(root: Path, engagement: str, started: datetime) -> Path:
    stamp = started.strftime("%Y%m%d-%H%M%S")
    path = root / f"{slugify(engagement)}_{stamp}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_state(run_dir: Path, ctx: RunContext, extra: dict[str, Any] | None = None) -> None:
    payload = {"meta": asdict(ctx), **(extra or {})}
    (run_dir / "state.json").write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def list_optional_tools() -> int:
    ui.banner()
    rows = []
    for name, path in detect_optional_tools().items():
        rows.append([name, path or "not installed", "available" if path else "will be skipped"])
    nmap = shutil.which("nmap")
    rows.insert(0, ["nmap", nmap or "not installed", "required" if nmap else "REQUIRED — install to scan"])
    rows.append(["rich", "installed" if HAS_RICH else "not installed", "progress UI" if HAS_RICH else "plain-text fallback"])
    rows.append(["requests", "installed" if HAS_REQUESTS else "not installed", "HTTP client" if HAS_REQUESTS else "urllib fallback"])
    ui.table("Tool availability", ["Tool", "Path / status", "Role"], rows)
    return 0 if nmap else 1


def render_reports(ctx: RunContext, run_dir: Path, hosts: list[HostRecord], web: list[WebResult], phases: set[str]) -> None:
    findings = collect_findings(ctx, hosts, web, phases)
    coverage = coverage_from_findings(findings)
    write_json_report(run_dir / "findings.json", ctx, hosts, web, findings, coverage)
    layer = write_navigator_layer(run_dir / "attack-navigator.json", ctx, coverage)
    write_markdown(run_dir / "report.md", ctx, hosts, web, findings, coverage)
    write_html(run_dir / "report.html", ctx, hosts, web, findings, coverage, layer)
    ui.ok(f"Wrote reports in {run_dir}")
    ui.muted("  nmap-discovery.xml / nmap-ports.xml  (raw nmap)")
    ui.muted("  findings.json")
    ui.muted("  report.md")
    ui.muted("  report.html")
    ui.muted("  attack-navigator.json")
    used = [row["id"] for row in coverage if row["used"]]
    ui.info("ATT&CK coverage: " + (", ".join(used) if used else "none"))


def run_scan(args: argparse.Namespace) -> int:
    ui.banner()
    scope = Scope.from_file(Path(args.scope).expanduser())
    targets = enforce_scope(scope, list(args.targets))
    operator = args.operator or getpass.getuser()
    engagement = args.engagement
    auth = require_authorization(
        flag_set=bool(args.i_have_authorization),
        engagement=engagement,
        operator=operator,
        targets=targets,
        scope_entries=scope.entries,
    )
    started = now_local()
    run_dir = Path(args.resume).expanduser() if args.resume else make_run_dir(Path(args.output_dir), engagement, started)
    run_dir.mkdir(parents=True, exist_ok=True)
    resume = bool(args.resume)
    ctx = RunContext(
        engagement=engagement,
        operator=operator,
        profile=args.profile,
        started_at=iso(started),
        targets=targets,
        scope_entries=scope.entries,
        authorization=auth,
        command=" ".join(sys.argv),
        run_dir=str(run_dir.resolve()),
    )
    write_audit(run_dir, ctx, "start", extra=f"profile={args.profile} targets={','.join(targets)} auth={auth}")
    save_state(run_dir, ctx)

    phases: set[str] = set(PROFILE_PHASES[args.profile])
    if args.skip_discover:
        phases.discard("discover")
    if args.skip_ports:
        phases.discard("ports")
    if args.skip_web:
        phases.discard("web")
    if args.only:
        only = {p.strip() for p in args.only.split(",") if p.strip()}
        unknown = only - {"discover", "ports", "web"}
        if unknown:
            raise SystemExit(f"Unknown --only phase(s): {', '.join(sorted(unknown))}")
        phases = only
    ctx.phases = sorted(phases)

    # Optional tools are off in quick/standard, on in full, unless explicitly toggled.
    use_optional = args.optional_tools
    if use_optional is None:
        use_optional = args.profile == "full"
    do_discovery = args.profile in {"standard", "full"} and "web" in phases
    if args.no_discovery:
        do_discovery = False
    if args.discovery:
        do_discovery = "web" in phases

    nmap = which_nmap() if phases & {"discover", "ports"} else ""
    hosts: list[HostRecord] = []

    try:
        if "discover" in phases:
            discovered = phase_host_discovery(nmap, targets, run_dir, args.timing, resume)
            hosts = merge_hosts(hosts, discovered)
            save_state(run_dir, ctx)

        # Port-scan the originally authorized tokens. If discovery reported
        # live hosts, prefer those addresses (still guaranteed in-scope).
        port_targets = targets
        live = [h.address for h in hosts if h.state == "up"]
        if live and "discover" in phases:
            port_targets = live
        elif "discover" in phases and not live:
            ui.warn("Discovery found no live hosts; port-scanning original targets with -Pn.")

        if "ports" in phases:
            scanned = phase_port_scan(
                nmap,
                port_targets,
                run_dir,
                args.timing,
                args.profile,
                args.ports,
                args.top_ports,
                resume,
            )
            hosts = merge_hosts(hosts, scanned)
            save_state(run_dir, ctx)

        web: list[WebResult] = []
        if "web" in phases:
            if not any(is_web_port(p) for h in hosts for p in h.ports):
                # If the operator skipped the port scan, synthesize targets from --ports
                # or well-known web ports so web recon can still run against in-scope hosts.
                if "ports" not in phases:
                    synth_ports = []
                    if args.ports:
                        for part in args.ports.split(","):
                            part = part.strip()
                            if part.isdigit():
                                synth_ports.append(int(part))
                    if not synth_ports:
                        synth_ports = [80, 443, 8080]
                    for token in targets:
                        try:
                            ip = str(ipaddress.ip_address(token))
                        except ValueError:
                            try:
                                resolved = scope.resolve_name(token)
                            except ValueError:
                                continue
                            if not resolved:
                                continue
                            ip = resolved[0]
                        rec = next((h for h in hosts if h.address == ip), None)
                        if rec is None:
                            rec = HostRecord(address=ip, state="up")
                            hosts.append(rec)
                        for p in synth_ports:
                            rec.ports.append(PortRecord(port=p, protocol="tcp", state="open", service="http"))
                    ui.warn("Port scan skipped; probing implied web ports on in-scope targets.")
            web = phase_web_recon(
                hosts,
                run_dir,
                profile=args.profile,
                timeout=args.timeout,
                rate=args.rate,
                threads=args.threads,
                wordlist_path=Path(args.wordlist) if args.wordlist else None,
                use_optional=use_optional,
                skipped_tools=ctx.skipped_tools,
                do_discovery=do_discovery,
            )
            # If optional tools were not requested, still record availability.
            if not use_optional:
                for name, path in detect_optional_tools().items():
                    if not path:
                        ctx.skipped_tools.setdefault(name, "not installed (shutil.which returned None)")
                    else:
                        ctx.skipped_tools.setdefault(name, "installed but not run (enable with --optional-tools or --profile full)")
        ctx.finished_at = iso()
        ctx.skipped_tools = dict(ctx.skipped_tools)
        write_audit(run_dir, ctx, "finish", extra=f"hosts={len(hosts)} web={len(web)}")
        save_state(run_dir, ctx)
        render_reports(ctx, run_dir, hosts, web, phases)
        return 0
    except KeyboardInterrupt:
        ctx.finished_at = iso()
        write_audit(run_dir, ctx, "aborted", extra="keyboard interrupt")
        save_state(run_dir, ctx)
        ui.err("Interrupted. Partial artifacts may still be in the run directory.")
        return 130


def build_parser() -> argparse.ArgumentParser:
    epilog = f"""
examples:
  # Show which optional tools are available
  python3 {TOOL_NAME}.py tools

  # Authorized lab scan (scope file required)
  python3 {TOOL_NAME}.py --scope scope.txt --engagement oscp-lab \\
      --operator "VP Roju" --i-have-authorization --profile standard 127.0.0.1

  # Fast path: host discovery + top 100 ports + headers/title only
  python3 {TOOL_NAME}.py --scope scope.txt --engagement lab --i-have-authorization \\
      --profile quick --ports 80,443,8080 127.0.0.1

  # Resume a previous run directory (reuses nmap XML when present)
  python3 {TOOL_NAME}.py --scope scope.txt --engagement lab --i-have-authorization \\
      --resume runs/oscp-lab_20261112-231500 127.0.0.1

authorized use only. Do not point this tool at systems you are not permitted to test.
"""
    parser = argparse.ArgumentParser(
        prog=f"{TOOL_NAME}.py",
        description=(
            "Authorized-use-only Nmap + web reconnaissance toolkit, "
            "with MITRE ATT&CK Enterprise mappings. "
            "Requires a --scope file and an authorization flag or interactive confirmation."
        ),
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("tools", help="List required and optional tool availability")
    scan = sub.add_parser("scan", help="Run an authorized reconnaissance engagement")
    scan.add_argument("targets", nargs="+", help="In-scope IPs, CIDRs, or hostnames to scan")
    scan.add_argument("--scope", required=True, help="File of authorized CIDRs, IPs, and hostnames (one per line)")
    scan.add_argument(
        "--i-have-authorization",
        action="store_true",
        dest="i_have_authorization",
        help="Confirm you have written authorization to test these targets",
    )
    scan.add_argument("--engagement", required=True, help="Engagement or lab name (used in logs and the run folder)")
    scan.add_argument("--operator", default="", help="Operator name (defaults to the current user)")
    scan.add_argument(
        "--profile",
        choices=("quick", "standard", "full"),
        default="standard",
        help="quick: top-100 + light web; standard: top-1000 -sV -sC + wordlist; full: all ports + optional tools",
    )
    scan.add_argument("--skip-discover", action="store_true", help="Skip nmap -sn host discovery")
    scan.add_argument("--skip-ports", action="store_true", help="Skip the nmap port/service scan")
    scan.add_argument("--skip-web", action="store_true", help="Skip HTTP/HTTPS recon")
    scan.add_argument("--only", default="", help="Comma-separated phase list: discover,ports,web")
    scan.add_argument("--ports", default=None, help="Explicit nmap port list (e.g. 80,443,8080). Overrides profile defaults.")
    scan.add_argument("--top-ports", type=int, dest="top_ports", default=None, help="Scan nmap's top N ports (overrides profile)")
    scan.add_argument("--timing", type=int, default=DEFAULT_TIMING, help="nmap timing 0-4 (default 3; capped at 4)")
    scan.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Content-discovery threads (default 6, max 16)")
    scan.add_argument("--rate", type=float, default=DEFAULT_RATE, help="Max HTTP requests per second (default 8)")
    scan.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request HTTP timeout in seconds")
    scan.add_argument("--wordlist", default=None, help="Optional path to a custom content-discovery wordlist")
    scan.add_argument("--discovery", action="store_true", help="Force bundled wordlist discovery even on --profile quick")
    scan.add_argument("--no-discovery", action="store_true", help="Disable bundled wordlist discovery")
    scan.add_argument("--optional-tools", action="store_true", dest="optional_tools", default=None, help="Run whatweb/nikto/ffuf/gobuster if installed")
    scan.add_argument("--no-optional-tools", action="store_false", dest="optional_tools", help="Do not run optional external tools")
    scan.add_argument("--output-dir", default="runs", help="Parent directory for run folders (default: ./runs)")
    scan.add_argument("--resume", default=None, help="Resume or reuse artifacts from an existing run directory")
    return parser


def _looks_like_scan(argv: list[str]) -> bool:
    if not argv:
        return False
    if argv[0] in {"scan", "tools", "-h", "--help", "--version"}:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if _looks_like_scan(argv):
        argv = ["scan", *argv]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "tools":
        return list_optional_tools()
    if args.command == "scan":
        return run_scan(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
