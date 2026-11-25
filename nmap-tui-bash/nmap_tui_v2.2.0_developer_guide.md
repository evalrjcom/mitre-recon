# nmap_tui_v2.2.0 — Developer Guide

## Layout of `nmap_tui_v2.2.0.sh`
ANSI helpers → size/terminal state → draw primitives → state → input (`read_key`, `prompt_line`) → validation, scope, argv, sanitise, write_unique, report, history → `pager` → screens → signals → `main`.

Phases: 0 menu · 1 target · 2 profile · **13 confirm** · 3 scan · 4 results · 10 history · 11 guide · 12 about. A scan can only start from 13 (profile and history re-run both go there).

## Invariants
- No `set -e`; use `x=$((x+1))`. Bash ≥ 4.4 (empty arrays under `set -u`).
- Never `eval`. Scans: `nmap "${SCAN_ARGV[@]}" >tmp 2>&1 </dev/null &`; hosts after `--`, file targets as `-iL "$path"`, optional `-oA` before them.
- Raw tty except `prompt_line` (icanon+echo). Prompts blank their field with spaces (never `EL` inside a box).
- Scan output → `sanitize_output` (C locale; strips C0/DEL/C1) before display/save/report.
- All creates go through `write_unique` (noclobber ⇒ O_EXCL, umask 077). Auto-save names are random and checked free (nmap itself would follow a planted symlink). `umask 077` is process-wide.
- Scope: `scope_load` fails closed; `validate_target` = format check then `scope_check_target`; re-checked at launch; Custom disabled when `SCOPE_ON`. Only IPv4 addr/CIDR and plain hostnames are provable.
- `cidr_range` uses `_`-prefixed locals because it assigns caller variables by name (`printf -v`).
- History lines are untrusted: `hist_load` regex-validates every field and re-runs `validate_target`; `hist_append` refuses symlinks and >1 MiB.
- `pager_find` relies on dynamic scoping (`offset`, `total`, `msg` are `pager` locals).
- `get_size` must use `$(stty size)` (process substitution is stale inside the WINCH trap). `read_key` polls with `-t 0.5` so traps run.
- All name/version strings derive from `SCRIPT_VERSION`; `--version` also checks the filename.

## Versioning checklist
Copy to `nmap_tui_vX.Y.Z.sh`; bump `SCRIPT_VERSION`, header, changelog; rename and retitle both guides to the same version; archive the previous set; grep for the old version string.

## Testing (run before release)
- `bash -n`; `LC_ALL=C.UTF-8 shellcheck -S style` – clean.
- Unit tests of helpers (51): CIDR maths, scope match/deny incl. fail-closed, address counts, fallback, report escaping, `write_unique` collision + symlink, history validation/permissions/symlink.
- PTY regression with pexpect + pyte against real nmap 7.94 (42): layouts at 80x24/120x40, confirm preview, large-scan guard, `-iL`, search, report, save, history persistence and re-run, auto-save files and modes, `A`/`T`, scope (deny, range, Custom off, missing file), Ctrl+C inside a prompt, escape injection, cancel without keystroke theft, banner at 80/100 cols, resize on confirm, Ctrl+Z/`fg`, version consistency.

## Changelog
See the header of the script (grep `[v2.2.0`).

## Not yet implemented (ideas)
XML parsing and scan diff, NSE script picker, scan queue/background runs, JSON export, CVE cross-reference, timing/rate knobs on the Confirm screen, open-port-only filter, history trimming.
