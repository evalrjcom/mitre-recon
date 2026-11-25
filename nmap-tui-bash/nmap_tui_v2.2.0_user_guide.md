# nmap_tui_v2.2.0 — User Guide

`nmap_tui_v2.2.0.sh` is a keyboard-driven terminal front-end for nmap (pure bash 4.4+). Only scan networks you own or are authorised to test.

## Run
```
bash nmap_tui_v2.2.0.sh            # needs a real terminal and nmap
bash nmap_tui_v2.2.0.sh --version  # "nmap_tui_v2.2.0.sh 2.2.0"
bash nmap_tui_v2.2.0.sh --help
```
| Environment variable | Effect |
|---|---|
| `NMAP_TUI_OUTDIR` | where saves, reports, history and auto-saved scans go (default `.`) |
| `NMAP_TUI_MAX_LINES` | max output lines kept per scan (default 200000) |
| `NMAP_TUI_SCOPE` | file of authorised targets; out-of-scope targets are refused (see below) |
| `NMAP_TUI_AUTOSAVE` | `1` = also write nmap `-oA` files (`.nmap/.gnmap/.xml`) for every scan |

Minimum terminal 80x24; live resize is supported.

## Workflow
1. **Menu** → `1` New Scan.
2. **Target**: host, CIDR, range, hostname, several space-separated, or `-iL /path/hosts.txt`. Backspace works; empty Enter cancels. A rejected target now shows its reason.
3. **Profile**: ↑↓/Enter or `1`-`9`; `0` = Custom flags (empty Enter cancels).
4. **Confirm** (new): shows the exact command, ~address count and warnings. `Enter` runs. Keys: `A` toggle auto-save, `T` unprivileged fallback, `B` back, `Q` menu.
   - Scans of ≥ 4096 addresses show **LARGE SCAN** and need `Y` (Enter is ignored).
   - `T` rewrites `-sS`→`-sT` and drops `-O` when you are not root. UDP/FIN/Xmas etc. have no unprivileged equivalent and are refused.
5. **Scanning**: `C` cancels (partial output kept); Ctrl+C quits.
6. **Results**: ↑↓/PgUp/PgDn/g/G scroll · `/` find, `.` next, `,` previous · `S` save · `R` Markdown report · `N` new scan · `Q` menu.

## Scope allow-list
Set `NMAP_TUI_SCOPE=/path/scope.txt`, one entry per line (`#` comments):
```
10.0.0.0/24
scanme.nmap.org
*.lab.example.com
```
- Targets must lie inside an IPv4 address/CIDR entry, or match a hostname / `*.domain` entry. `-iL` files are checked line by line, again at launch time.
- IPv4 ranges (`1.1.1.1-50`) and IPv6 cannot be proven in scope and are refused.
- **Custom flags are disabled** (they can contain targets).
- Fail-closed: a missing/unreadable file stops startup; an empty file allows nothing.

## Files written (all mode 0600, never overwritten; collisions get `_2`, `_3`…)
- `nmap_<time>_<target>.txt` – save (`S`): header with command and exit status, plain text.
- `nmap_<time>_<target>_report.md` – report (`R`): one table of open ports per host; remote strings are escaped.
- `nmap_<time>_<target>_<random>.{nmap,gnmap,xml}` – auto-save.
- `.nmap_tui_history` – tab-separated history, re-validated on load, capped at 1 MiB.

## History
Menu → 2. Newest first, persists across sessions. Keys `1`-`9` re-run that scan through the Confirm screen (scope re-checked).

## Keys
| Key | Action |
|---|---|
| ↑ ↓ / j k, PgUp PgDn, Home End, g G | move / scroll |
| Enter | select / run (Confirm) |
| `/` `.` `,` | pager search / next / previous |
| C | cancel running scan |
| Q / Esc | back / quit |
| Ctrl+Z | suspend; `fg` resumes and redraws |

## What changed since v2.1.0
Confirm screen, scope, `T` fallback, auto-save, persistent history + re-run, search, report; fixed: rejected-target reason vanishing, box border erased in prompts, banner clipping, private umask for nmap's own files. Scans no longer start straight from the profile screen.
