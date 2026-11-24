# reconmap

Authorized-use-only Nmap + web reconnaissance toolkit, with every action
and finding tagged to [MITRE ATT&CK](https://attack.mitre.org/) Enterprise
techniques.

Use this only on systems you have explicit permission to test: a contracted
engagement, an OSCP-style lab, or assets you own. The tool never exploits a
service, never brute-forces credentials, and never stores the body of a
potentially sensitive file (`.env`, `.git`, keys, backups, and similar).

## Requirements

- Python 3.10+
- [Nmap](https://nmap.org/) on `PATH` (7.x recommended)

Optional Python packages (progress UI and a slightly friendlier HTTP client):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If `rich` or `requests` are missing, reconmap falls back to plain-text output
and the standard-library `urllib` client.

Optional external tools, used only when present (`shutil.which`) and only
with `--profile full` or `--optional-tools`. Each one is skipped otherwise:

| Tool | Role |
| --- | --- |
| whatweb | Technology fingerprint |
| nikto | Interesting-file checks (`-Tuning 1` only) |
| ffuf | Wordlist content discovery (preferred if both exist) |
| gobuster | Wordlist content discovery (used when ffuf is absent) |

## Quick start

```bash
# 1. Declare the authorized scope (CIDRs, IPs, or hostnames, one per line)
printf '127.0.0.1/32\n' > scope.txt

# 2. Run a scan — the authorization flag is required (or confirm interactively)
python3 reconmap.py --scope scope.txt --engagement oscp-lab \
    --operator "VP Roju" --i-have-authorization --profile standard \
    127.0.0.1

# 3. Open the reports under runs/<engagement>_<timestamp>/
```

The `scan` subcommand is optional. These are equivalent:

```bash
python3 reconmap.py scan --scope scope.txt --engagement lab --i-have-authorization 127.0.0.1
python3 reconmap.py      --scope scope.txt --engagement lab --i-have-authorization 127.0.0.1
```

List local tool availability:

```bash
python3 reconmap.py tools
```

## Scope and authorization

`--scope` is required. Every target must be fully contained in that file:

- An IP must sit inside a listed CIDR (or be listed itself).
- A CIDR target must be a subset of a listed CIDR — a wider target than the
  authorized range is refused, not silently trimmed.
- A hostname is allowed when it is listed, or when every address it resolves
  to is in a listed CIDR.

Targets outside scope abort the run. There is no override.

You must also pass `--i-have-authorization`, or type `I HAVE AUTHORIZATION`
at the prompt. Non-interactive runs without the flag are refused. The
engagement name, operator, targets, scope, and timestamps are written to
`audit.log` in the run directory (America/Los_Angeles).

## Profiles and phases

| Profile | Host discovery | Port scan | Web recon |
| --- | --- | --- | --- |
| `quick` | `nmap -sn` | top 100 ports, `-sV` | headers, title, TLS, robots/sitemap |
| `standard` (default) | `nmap -sn` | top 1000 ports, `-sV -sC` | plus bundled wordlist discovery |
| `full` | `nmap -sn` | all TCP ports, `-sV -sC` | wordlist discovery + optional tools |

Safe defaults: nmap timing `-T3` (capped at `-T4`), rate-limited HTTP
(8 requests/second, 6 threads), no exploitation, no credential guessing.

Useful flags:

```
--ports 80,443,8080     # explicit ports (overrides the profile)
--top-ports 100         # nmap's top N ports
--skip-discover / --skip-ports / --skip-web
--only discover,ports,web
--timing 3              # 0–4, default 3
--threads 6 --rate 8 --timeout 8
--wordlist path.txt     # replace the bundled short list
--discovery / --no-discovery
--optional-tools / --no-optional-tools
--output-dir runs
--resume runs/<dir>     # reuse existing nmap XML when present
```

## MITRE ATT&CK mapping

Technique IDs and names were verified against the official Enterprise matrix.

| ID | Official name | How reconmap uses it |
| --- | --- | --- |
| T1595.001 | Active Scanning: Scanning IP Blocks | Host discovery and port scans |
| T1595.002 | Active Scanning: Vulnerability Scanning | Security-header / TLS audit; optional nikto |
| T1595.003 | Active Scanning: Wordlist Scanning | Bundled (or custom) content discovery; optional ffuf/gobuster |
| T1590 | Gather Victim Network Information | Hosts, ports, certificate metadata |
| T1592.002 | Gather Victim Host Information: Software | nmap `-sV`, banners, tech fingerprinting, whatweb |
| T1594 | Search Victim-Owned Websites | Site title, robots.txt, sitemap.xml, discovered paths |
| T1046 | Network Service Discovery | nmap service/port enumeration |
| T1018 | Remote System Discovery | nmap `-sn` live-host list |
| T1190 | Exploit Public-Facing Application | **Potential exposure tag only** — for example a reachable `.env` or `/phpinfo.php`. The tool does not exploit. |

Each finding carries its technique IDs. The HTML and Markdown reports include
a coverage table, and `attack-navigator.json` can be imported into
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## Outputs

Every run writes `runs/<engagement>_<YYYYMMDD-HHMMSS>/`:

| File | Contents |
| --- | --- |
| `nmap-discovery.xml` / `.nmap` | Raw host-discovery results |
| `nmap-ports.xml` / `.nmap` | Raw port/service scan (`-oX` parsed with `xml.etree`) |
| `findings.json` | Structured hosts, web results, findings, coverage |
| `report.md` | Markdown report |
| `report.html` | Self-contained HTML report (metrics, hosts/ports, web findings, ATT&CK table, Navigator download) |
| `attack-navigator.json` | ATT&CK Navigator layer (v4.5) |
| `audit.log` | Engagement, operator, timestamps, start/finish |
| `state.json` | Resume-friendly run metadata |

## Safety

- Scope guard and authorization gate are mandatory.
- Timing is capped; HTTP is rate-limited.
- NSE is limited to the default safe scripts (`-sC`) on standard/full profiles.
- Optional nikto is invoked with `-Tuning 1` (interesting files) only.
- Sensitive paths are recorded by status/length only; bodies are not stored.
- T1190 is a *potential exposure* label, never a claim that something was exploited.

## License / use

For authorized defensive testing and study only. You are responsible for
having permission before you run a scan.
