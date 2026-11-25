# Zenmap TUI v1 — Developer Guide

Internals, data flow, and the correctness/security constraints this script is built around. Read this before modifying `zenmap-tui_v1.sh`.

## Design constraints (do not violate these)

1. **No `tput`.** It fails hard when `$TERM` is unset, which is common in minimal/containerized environments. All cursor/screen control goes through raw ANSI/VT100 escape sequences (`$CSI`, defined at the top of the file).
2. **No `dialog`, no external TUI library.** Everything is `printf` + `stty raw` + single-byte `read`.
3. **No `set -e`.** Arithmetic expressions like `(( x-- ))` return exit status 1 when the result is 0 — `set -e` would kill the script the first time a counter hits zero. `set -u` is used instead, to catch unset-variable typos without that hazard.
4. **No `eval`.** Every place that used to build a command as a string and `eval` it (the dependency installer) now builds a bash array and executes it directly: `"${ARGV[@]}"`. This closes a command-injection path and is non-negotiable for any future feature that shells out.
5. **Never interpolate a variable directly into a `printf` format string.** Always `printf '%s' "$var"`, never `printf "...${var}..."`. `$TARGET` is attacker/user-controlled; a target string like `%n` would otherwise be interpreted by `printf` as a conversion specifier.
6. **`nmap` is invoked via an argv array, never a word-split string.** See `get_profile_argv()` and the final `nmap "${PROFILE_ARGV[@]}" "$TARGET"` call. This guarantees a target containing spaces or shell metacharacters is passed as one argument, not split or re-interpreted.

## Cross-process state — the one thing to get right

`run_scan` is launched as a background job (`run_scan &`). **A background subshell cannot mutate the parent shell's variables.** Any state the main loop needs to observe — "is a scan running," "how many seconds have elapsed" — must be communicated through files in `$TMPD`, not bash variables:

| File                    | Written by          | Read by                         | Meaning                          |
|-------------------------|----------------------|----------------------------------|-----------------------------------|
| `$TMPD/scanning.flag`   | `run_scan` (touch/rm) | `main` loop, `draw_title`        | Existence = a scan is in progress |
| `$TMPD/elapsed.txt`     | ticker subshell inside `run_scan` | `draw_title`, `draw_scaninfo_pane` | Seconds elapsed in current/last scan |
| `$TMPD/output.txt`      | `run_scan`            | `draw_output_pane`               | Raw nmap stdout, line-by-line     |
| `$TMPD/hosts.txt`       | `run_scan`            | `draw_sidebar`, `draw_details_pane`, `draw_topology_pane`, `draw_statusbar` | `ip\|status\|open_count\|hostname\|os\|mac` per line |
| `$TMPD/ports.txt`       | `run_scan`            | `draw_ports_pane`, `draw_details_pane`, `draw_statusbar` | `ip\|port\|state\|proto\|service\|version` per line |

If you add new state that the scanner subshell needs to report, **add a file, not a variable.** This was the single largest class of bugs in earlier drafts of this script (scan progress silently never appearing, "stop" never actually stopping anything).

### Why process substitution, not a pipe, feeds the parser

```bash
while IFS= read -r line; do ... done < <(nmap "${PROFILE_ARGV[@]}" "$TARGET" 2>&1)
```

A trailing pipe (`nmap ... | while read line; do ...; done`) runs the `while` loop in *its own* subshell in default bash — any variable set inside it (`current_ip`) is lost the instant the loop ends, and is never visible even within the rest of `run_scan`. Process substitution (`< <(...)`) keeps the `while` loop in the *same* shell as the rest of `run_scan`, so `current_ip` persists correctly across lines for the whole scan. This matters because port lines arrive *after* the host line that introduces them, and every port record needs to know which host it belongs to.

### Why host/port records are mutated via `awk`, not `sed`

Updating a single field (marking a host "down," setting its OS, bumping its open-port count) is done with:

```bash
awk -F'|' -v ip="$current_ip" 'BEGIN{OFS="|"} $1==ip{$N="newvalue"} {print}' "$FILE" > "$TMPD/tmp" && mv -- "$TMPD/tmp" "$FILE"
```

A pipe-delimited `sed` substitution for this is fragile — the delimiter character collides with the field separator and is easy to get structurally wrong (an earlier draft of this did exactly that and silently never updated anything). `awk -F'|'` operates on fields, not raw substrings, so it can't misfire the same way.

## Signal handling and cleanup

There is exactly **one** cleanup path:

```bash
_CLEANED_UP=0
_cleanup() {
  (( _CLEANED_UP )) && return
  _CLEANED_UP=1
  # kill the scanner's whole process group, restore stty, restore screen, rm -rf $TMPD, exit 0
}
trap _cleanup EXIT INT TERM HUP
```

Do not add a second `trap ... EXIT` anywhere, and do not register a different cleanup function. A second `EXIT` trap that itself calls `exit 0` can trigger the first one again in some bash builds, leading to double-execution of cleanup logic (double `rm -rf`, double `kill`, etc.). The `_CLEANED_UP` guard makes `_cleanup` idempotent as defense-in-depth, but the real fix is: **one trap registration, period.**

The `WINCH` trap (terminal resize) is separate and fine to coexist — it's a different signal and only triggers a redraw, never an exit.

### Process-group kill, not single-PID kill

```bash
set -m; run_scan & SCAN_PID=$!; set +m
...
kill -- "-$SCAN_PID" 2>/dev/null || kill "$SCAN_PID" 2>/dev/null || true
```

`set -m` (job control) gives the backgrounded `run_scan` its own process group. Killing `-$SCAN_PID` (negative PID) sends the signal to the whole group — including the actual `nmap` child process, which is a *grandchild* of the main script and would otherwise be orphaned and keep running after "Stop" is pressed.

## Terminal I/O

- `stty -g` is captured once at the top of `main()` into `$STTY_SAVE` and restored verbatim in `_cleanup`. Never use `stty sane` as a substitute — it resets to generic defaults and discards the user's actual terminal configuration (custom erase keys, etc.).
- All `read` calls use `</dev/tty` explicitly. If stdout/stdin are ever redirected or piped by the caller, `read` without this would silently stop receiving keystrokes.
- Arrow keys arrive as a 3-byte escape sequence (`ESC [ A/B/C/D`). `read_key()` reads the first byte, and only if it's `ESC` does it attempt to read two more with a short timeout (`-t 0.05`) — long enough to catch a real escape sequence, short enough that a bare `Esc` keypress doesn't hang the UI.
- While a scan is running, `read_key` uses `read -t 0.5` so the main loop can poll every half-second and redraw the elapsed-time clock, live output, and sidebar — without a key being pressed.

## Layout and rendering

- `recalc_layout()` enforces `MIN_ROWS=12` / `MIN_COLS=50` and clamps `CONTENT_H`/`CONTENT_W` to at least 1. Never let either go to 0 or negative — `printf '%*s'` with a negative width is undefined behavior.
- Every draw function (`draw_*_pane`) is expected to fully repaint its region on every call, including blanking any now-unused trailing rows (`clear_eol` / the trailing `while (( r <= end_r ))` loops). Partial updates that don't clear stale content will leave visual garbage on screen after scrolling or resizing.
- `clear_eol()` (ANSI `\033[K`, erase-to-end-of-line) is used instead of manually computing and printing padding spaces — simpler and always correct regardless of what was previously on that line.
- `repeat_char()` builds a string of N repeated characters in pure bash (`printf -v` + parameter-expansion substitution) rather than forking `tr`. Horizontal rules are drawn on every redraw, so avoiding a process fork here measurably helps responsiveness over high-latency (SSH) connections.

## Extending the script

- **New scan profile:** add an entry to `PROFILE_LABELS`, `PROFILE_ARGS_STR` (display-only), and a `case` arm in `get_profile_argv()`. Never add a profile as a plain string that gets word-split at call time.
- **New field to track per host:** extend the `ip|status|open_count|hostname|os|mac` schema in `hosts.txt` — pick the next field number, update every `awk` writer that touches that file, and update every `IFS='|' read -r ...` consumer to match the new field count.
- **New tab:** add to the `TABS` array, add a `draw_*_pane` function following the existing pattern (always fully repaint, always respect `CONTENT_TOP`/`CONTENT_H`/`CONTENT_W`), and add a case arm in `redraw()`.
- **New dependency:** add a `"binary|apt_pkg|brew_pkg|dnf_pkg|pacman_pkg"` entry to `REQUIRED_BINS`. The preflight installer already handles detection, display, and installation via `build_install_argv` — no `eval`, so no new entry can introduce a shell-injection path as long as you don't bypass the argv-array pattern.

## Versioning convention

This script and its companion guides are versioned together. If `zenmap-tui_v1.sh` becomes `zenmap-tui_v2.sh`, update in the same change:

- The filenames of both guides (`zenmap-tui_v2_user_guide.md`, `zenmap-tui_v2_developer_guide.md`)
- Every in-file reference to the script's own name/version (header comment, any future `VERSION=` variable, usage/banner text)
- The title headings inside both guides

None should be left stale pointing at the old version.
