#!/usr/bin/env bash
# =============================================================================
#  nmap_tui_v2.2.0.sh — Ethical Hacker's Network Mapping TUI
#  Pure bash: ANSI escape codes + stty/awk/sed/wc. No dialog / tput / Python.
#
#  Usage:  bash nmap_tui_v2.2.0.sh [--help | --version]
#  Env:    NMAP_TUI_OUTDIR     directory for saved scans      (default: .)
#          NMAP_TUI_MAX_LINES  max output lines kept per scan (default: 200000)
#          NMAP_TUI_SCOPE      file of authorised targets (CIDR / host / *.domain);
#                              when set, out-of-scope targets are refused
#          NMAP_TUI_AUTOSAVE   1 = also write nmap -oA (.nmap/.gnmap/.xml) per scan
#
#  CHANGELOG
#    2.2.0  Audit pass 3 + the suggested features from the v2.1.0 review.
#           - NEW  confirm screen: exact command preview, address count, large-
#                  scan guard (>= 4096 addresses needs an explicit Y)
#           - NEW  scope allow-list (NMAP_TUI_SCOPE), fail-closed; Custom flags are
#                  disabled while it is active (they can smuggle in targets)
#           - NEW  non-root fallback (T): -sS -> -sT, drops -O; refuses UDP/FIN/etc.
#           - NEW  optional -oA auto-save with unpredictable, symlink-checked names
#           - NEW  persistent history (<outdir>/.nmap_tui_history, 0600) + re-run
#                  of the 9 newest scans with keys 1-9
#           - NEW  pager search ( / find, . next, , previous ) and Markdown
#                  report export (R) built from the open-port lines
#           - FIX  rejected-target reason was erased the instant it was drawn
#           - FIX  prompt rows erased the box's right border (EL); stale text on profile screen
#           - FIX  banner clipped/mis-centred at widths other than 90 columns
#           - FIX  umask 077 now process-wide (nmap -oN/-oA files from Custom
#                  flags were created world-readable)
#           - FIX  bash >= 4.4 required (empty-array expansion under `set -u`)
#           - FIX  dead code removed from main loop
#    2.1.0  Audit pass 2 (every item below was reproduced before being fixed).
#           - FIX  documented `-iL <file>` target was broken against real nmap
#           - SEC  hostile scan output could hijack the terminal (ESC injection)
#           - SEC  `-iL` validator accepted extra options (-oN/-oX file writes)
#           - SEC  saved-file creation followed pre-planted symlinks (TOCTOU)
#           - FIX  nmap inherited the TTY and stole keystrokes during a scan
#           - FIX  saved file contained raw ANSI codes after a non-zero exit
#           - FIX  Backspace / line editing broken in Target + Custom prompts
#           - FIX  layout broke at the advertised 80x24 minimum; guide clipped
#           - NEW  live resize, Ctrl+Z suspend/resume, cancel a scan with `C`
#           - PERF no per-keystroke forks in the render path; one-pass awk colour
#           - NEW  code deliverable is versioned in its filename (this file)
#    2.0.0  Security/correctness audit pass 1 (eval removal, trap fixes, ...).
#    1.0.0  Initial release.
#
#  Change tags used in comments (grep for "[v2.1.0"):
#    [v2.1.0 FIX] correctness   [v2.1.0 SEC] security   [v2.1.0 ROBUST] edge case
#    [v2.1.0 PERF] efficiency   [v2.1.0 UX]  usability  [v2.1.0 NEW]    feature
# =============================================================================

# ── Strict mode ──────────────────────────────────────────────────────────────
# Deliberately NOT `set -e`: a bare `(( x ))` whose *value* is 0 returns failure,
# which under errexit silently kills a TUI built on guard-and-act idioms.
# (Verified in the v2.0.0 audit.)  nounset + pipefail are kept.
set -uo pipefail
shopt -s extglob

SCRIPT_VERSION="2.2.0"
SCRIPT_FILE="nmap_tui_v${SCRIPT_VERSION}.sh"

# ── Guard: bash 4+ (associative arrays, mapfile) ──────────────────────────────
# [v2.2.0 FIX] 4.4+: before 4.4, expanding an EMPTY array under `set -u` aborts
# ("unbound variable"), which several code paths (no flags, no targets) hit.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  echo "Requires bash 4.4+. On macOS: brew install bash" >&2; exit 1
fi

# ── CLI: handled before any terminal/nmap checks so they work in pipes/CI ────
usage(){
  printf '%s\n' \
    "${SCRIPT_FILE} v${SCRIPT_VERSION} — keyboard-driven TUI for nmap" \
    "" \
    "Usage: bash ${SCRIPT_FILE} [--help | --version]" \
    "" \
    "Environment:" \
    "  NMAP_TUI_OUTDIR     directory for saved scans (default: current dir)" \
    "  NMAP_TUI_MAX_LINES  max output lines kept per scan (default: 200000)" \
    "  NMAP_TUI_SCOPE      file of authorised targets (CIDR/host/*.domain); enforced if set" \
    "  NMAP_TUI_AUTOSAVE   1 = also save nmap -oA files for every scan" \
    "" \
    "Only scan networks you own or are explicitly authorised to test."
}
case "${1:-}" in
  -h|--help)    usage; exit 0;;
  -V|--version)
    printf '%s %s\n' "$SCRIPT_FILE" "$SCRIPT_VERSION"
    # [v2.1.0 NEW] self-check: a file named nmap_tui_vX.Y.Z.sh must carry X.Y.Z
    # internally, so a renamed/stale copy is caught instead of silently trusted.
    _base=${0##*/}
    if [[ $_base =~ ^nmap_tui_v([0-9]+\.[0-9]+\.[0-9]+)\.sh$ && ${BASH_REMATCH[1]} != "$SCRIPT_VERSION" ]]; then
      printf 'WARNING: file name says v%s but internal version is v%s\n' \
        "${BASH_REMATCH[1]}" "$SCRIPT_VERSION" >&2
      exit 2
    fi
    exit 0;;
  "") ;;
  *)  echo "Unknown option: $1" >&2; usage >&2; exit 2;;
esac

# ── Guard: nmap must be installed ─────────────────────────────────────────────
if ! command -v nmap &>/dev/null; then
  echo "nmap is not installed. Install it and re-run." >&2; exit 1
fi

# ── Guard: interactive terminal on both ends (else read loops spin) ──────────
if [[ ! -t 0 || ! -t 1 ]]; then
  echo "${SCRIPT_FILE} requires an interactive terminal (stdin and stdout must be a tty)." >&2
  exit 1
fi

# ── [v2.1.0 ROBUST] force a UTF-8 locale ─────────────────────────────────────
# Under LANG unset / LC_ALL=C, ${#str} counts BYTES, so every box title and
# padded column that contains a multi-byte glyph mis-aligned.
ensure_utf8(){
  local cur=${LC_ALL:-${LC_CTYPE:-${LANG:-}}} cand
  case $cur in *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) return 0;; esac
  for cand in C.UTF-8 en_US.UTF-8 en_GB.UTF-8; do
    # shellcheck disable=SC2016  # single quotes intentional: expanded by the child bash
    if [[ $(LC_ALL=$cand "$BASH" -c 'printf %s "${#1}"' _ 'é' 2>/dev/null) == 1 ]]; then
      export LC_ALL=$cand
      return 0
    fi
  done
  return 0
}
ensure_utf8

# =============================================================================
# ANSI ESCAPE HELPERS
# =============================================================================
ESC=$'\033'
CSI="${ESC}["
R="${CSI}0m"
B="${CSI}1m"
EL="${CSI}K"       # erase to end of line
EL2="${CSI}2K"     # erase whole line

cur_hide()    { printf '%s?25l' "$CSI"; }
cur_show()    { printf '%s?25h' "$CSI"; }
cur_goto()    { printf '%s%s;%sH' "$CSI" "$1" "$2"; }     # row col
clear_screen(){ printf '%s2J%s1;1H' "$CSI" "$CSI"; }
# [v2.1.0 NEW] alternate screen: the user's scrollback is untouched and scan data
# does not linger in it after exit.  Autowrap OFF: an over-long line is clipped
# instead of wrapping (a wrapped write on the last row scrolls the whole UI).
alt_on()  { printf '%s?1049h%s?7l' "$CSI" "$CSI"; }
alt_off() { printf '%s?7h%s?1049l' "$CSI" "$CSI"; }
# mv ROW COL -> $MV  (no fork; for building whole frames in one string)
mv(){ printf -v MV '%s%s;%sH' "$CSI" "$1" "$2"; }

# [v2.1.0 PERF] colours precomputed once. v2.0.0 forked a subshell ($(fg N)) for
# every colour use, dozens per redraw, on every keypress.
mkfg(){ printf -v "$1" '%s38;5;%sm' "$CSI" "$2"; }
mkbg(){ printf -v "$1" '%s48;5;%sm' "$CSI" "$2"; }
# shellcheck disable=SC2034,SC2153  # F_*/B_* are assigned via printf -v in mkfg/mkbg
mkfg F_BORDER 238; mkfg F_TITLE 214; mkfg F_HEAD 39;  mkfg F_GOOD 82
mkfg F_WARN 220;   mkfg F_DANGER 196; mkfg F_MUTED 245; mkfg F_KEY 111
mkfg F_TXT 252;    mkfg F_WHITE 231
mkbg B_PANEL 234;  mkbg B_SEL 27

# strip_ansi STR VAR -> VAR = STR without SGR sequences (pure bash, no fork)
strip_ansi(){ local s=$1; printf -v "$2" '%s' "${s//$'\e'\[*([0-9;])m/}"; }
# fit VAR TEXT MAXW -> VAR = TEXT truncated to MAXW columns with an ellipsis
fit(){
  local s=$2 w=$3
  if (( w < 1 )); then w=1; fi
  if (( ${#s} > w )); then s="${s:0:w-1}…"; fi
  printf -v "$1" '%s' "$s"
}
# repeat_char N CHAR -> N copies, no fork
repeat_char(){
  local n=$1 ch=$2 out=""
  if (( n <= 0 )); then return 0; fi
  printf -v out '%*s' "$n" ''
  printf '%s' "${out// /$ch}"
}

# =============================================================================
# TERMINAL SIZE / STATE
# =============================================================================
ROWS=24
COLS=80
MIN_COLS=80
MIN_ROWS=24
NEED_REDRAW=0     # set by SIGWINCH / resume-from-suspend; consumed by read_key
FULL_CLEAR=1      # next screen draw must clear the whole screen first
TTY_ACTIVE=0
OLD_STTY=""
CLEANUP_DONE=0

# [v2.1.0 ROBUST] a tty that reports 0x0 (or no size) used to give ROWS=0 and
# block forever on "too small"; keep the last good size instead.
get_size(){
  local sz r c
  # [v2.1.0 FIX] $(...) rather than `read < <(stty size)`: from inside the WINCH
  # trap the process-substitution form returned the stale size (resize was only
  # picked up after the next keypress; found by the pty regression, T09).
  sz=$(stty size 2>/dev/null) || return 0
  r=${sz% *}; c=${sz#* }
  if [[ $r =~ ^[0-9]+$ && $c =~ ^[0-9]+$ ]] && (( r > 0 && c > 0 )); then
    ROWS=$r; COLS=$c
  fi
}

begin_screen(){ if (( FULL_CLEAR )); then clear_screen; FULL_CLEAR=0; fi; }

tty_raw() { stty -echo -icanon min 1 time 0 2>/dev/null || true; }
# [v2.1.0 FIX] text prompts need the kernel line discipline (icanon+echo) so
# Backspace / Ctrl-U / Ctrl-W work. v2.0.0 only toggled `echo`, leaving
# -icanon on, so Backspace arrived as a literal ^? and corrupted the input.
tty_line(){ stty echo icanon 2>/dev/null || true; }
term_restore(){
  cur_show
  if [[ -n $OLD_STTY ]]; then stty "$OLD_STTY" 2>/dev/null || true; fi
  alt_off
}
tty_setup(){ tty_raw; alt_on; cur_hide; }

ensure_min_terminal_size(){
  get_size
  if (( COLS >= MIN_COLS && ROWS >= MIN_ROWS )); then return 0; fi
  local k=""
  while (( COLS < MIN_COLS || ROWS < MIN_ROWS )); do
    clear_screen
    cur_goto 1 1
    printf '%s%sTerminal too small (%sx%s). Need at least %sx%s.%s' \
      "$F_WARN" "$B" "$COLS" "$ROWS" "$MIN_COLS" "$MIN_ROWS" "$R"
    cur_goto 2 1
    printf '%sResize your terminal, or press Q to quit.%s' "$F_MUTED" "$R"
    k=""
    read -rs -n1 -t 0.3 k 2>/dev/null
    if [[ $k == [qQ] ]]; then exit 0; fi
    get_size
  done
  NEED_REDRAW=0
  FULL_CLEAR=1
}

# =============================================================================
# DRAW PRIMITIVES
# =============================================================================

# draw_box ROW COL H W [TITLE]   (TITLE is plain text; coloured here)
draw_box(){
  local row=$1 col=$2 h=$3 w=$4 title=${5-}
  local r tlen lpad rpad
  if (( h < 3 )); then h=3; fi
  if (( w < 6 )); then w=6; fi
  cur_goto "$row" "$col"
  printf '%s╔' "$F_BORDER"
  if [[ -n $title ]]; then
    if (( ${#title} > w - 4 )); then title="${title:0:w-5}…"; fi
    tlen=${#title}
    lpad=$(( (w - 2 - tlen) / 2 ))
    rpad=$(( w - 2 - tlen - lpad ))
    repeat_char "$lpad" '═'
    # shellcheck disable=SC2153
    printf '%s%s%s%s%s' "$F_TITLE" "$B" "$title" "$R" "$F_BORDER"
    repeat_char "$rpad" '═'
  else
    repeat_char $(( w - 2 )) '═'
  fi
  printf '╗%s' "$R"
  for (( r=row+1; r<row+h-1; r++ )); do
    cur_goto "$r" "$col"
    printf '%s║%s' "$F_BORDER" "$R"
    repeat_char $(( w - 2 )) ' '
    printf '%s║%s' "$F_BORDER" "$R"
  done
  cur_goto $(( row+h-1 )) "$col"
  printf '%s╚' "$F_BORDER"
  repeat_char $(( w - 2 )) '═'
  printf '╝%s' "$R"
}

draw_hline(){   # ROW COL WIDTH
  cur_goto "$1" "$2"
  printf '%s' "$F_BORDER"
  repeat_char "$3" '─'
  printf '%s' "$R"
}

# status_bar TEXT — bottom row. [v2.1.0 ROBUST] never longer than the terminal:
# over-long text is truncated (colour dropped) instead of wrapping/scrolling.
status_bar(){
  local text=$1 plain
  strip_ansi "$text" plain
  if (( ${#plain} > COLS - 2 )); then text="${plain:0:COLS-3}…"; fi
  cur_goto "$ROWS" 1
  printf '%s%s%s %s%s' "$B_PANEL" "$F_KEY" "$EL2" "$text" "$R"
}

# hints KEY LABEL [KEY LABEL ...] -> $HINTS  (re-applies the panel bg after each
# reset so the whole bar keeps its background)
HINTS=""
hints(){
  HINTS=""
  while (( $# >= 2 )); do
    HINTS+="${F_KEY}$1${R}${B_PANEL}${F_TXT} $2   "
    shift 2
  done
}

# =============================================================================
# STATE
# =============================================================================
TARGET=""
TARGET_KIND="hosts"    # hosts | file
TARGET_FILE=""
SCAN_PROFILE=""
SCAN_RESULTS=""
SCAN_RC=0
SCAN_CANCELLED=0
SCAN_TRUNC=0
SCAN_CMD=""
SCAN_PID=""            # in-flight nmap PID (cleanup() kills it)
SCAN_TMPFILE=""        # in-flight temp file (cleanup() removes it)
declare -a SCAN_ARGV=()
PHASE=0                # 0 menu 1 target 2 profile 3 scanning 4 results 10 history 11 guide 12 about
LAST_PHASE=-1
REJECT_REASON=""
KEY=""
REPLY_LINE=""
MENU_SEL=1
PROFILE_SEL=1
NMAP_VERSION="unknown"
MAX_LINES=${NMAP_TUI_MAX_LINES:-200000}
if [[ ! $MAX_LINES =~ ^[0-9]+$ ]] || (( MAX_LINES < 100 )); then MAX_LINES=200000; fi

# name|description (<=32 cols)|flags|needs-root
declare -A PROFILES
PROFILES[1]="Host Discovery|Ping sweep - find live hosts|-sn|n"
PROFILES[2]="Quick Scan|Top 100 ports, SYN|-sS -F --open|y"
PROFILES[3]="Comprehensive|Top 1000 ports + OS + versions|-sS -sV -O --open|y"
PROFILES[4]="Service Version|Banner-grab open ports|-sV --version-intensity 5|n"
PROFILES[5]="OS Fingerprint|Active OS detection|-O --osscan-guess|y"
PROFILES[6]="UDP Scan|Top 20 UDP ports (slow)|-sU --top-ports 20|y"
PROFILES[7]="Vuln Scripts|NSE vulnerability scripts|-sV --script vuln|n"
PROFILES[8]="Stealth Slow|IDS-evasive FIN scan, slow|-sF -T1|y"
PROFILES[9]="Full Port|All 65535 ports, SYN|-sS -p- --open -T4|y"
PROFILES[10]="Custom|Enter your own nmap flags|CUSTOM|n"
NPROFILES=${#PROFILES[@]}

# [v2.1.0 FIX] history held as parallel arrays; v2.0.0 packed it into one
# '|'-delimited string, which a custom flag containing '|' would mis-split.
declare -a HIST_TS=() HIST_TGT=() HIST_CMD=() HIST_NOTE=() HIST_FLAGS=()

# [v2.2.0 NEW] feature state
OUTDIR=${NMAP_TUI_OUTDIR:-.}
HIST_FILE="$OUTDIR/.nmap_tui_history"
SCOPE_FILE=${NMAP_TUI_SCOPE:-}
SCOPE_ON=0
declare -a SCOPE_ENTRIES=()
AUTO_OA=0; if [[ ${NMAP_TUI_AUTOSAVE:-0} == 1 ]]; then AUTO_OA=1; fi
OA_BASE=""            # chosen -oA base for the scan in flight ("" => shown as <auto>)
SCAN_OA_NOTE=""
ADDR_COUNT=1
LARGE_ADDR=4096       # at or above this many addresses a scan needs an explicit Y
PG_PAT=""             # last pager search pattern

# =============================================================================
# INPUT
# =============================================================================
# read_key -> $KEY, one of: a literal single key, ENTER, ESC, RESIZE, or a
# normalised escape sequence ($'\x1b[A' etc).
#
# [v2.1.0 FIX/ROBUST]
#  * Polls with a 0.5 s timeout.  A trapped signal runs immediately during a
#    `read -t`, but is DEFERRED during a plain blocking read; polling is what
#    makes live resize and Ctrl+Z resume work.
#  * Checks read's status.  EOF returns 1 with an empty key, which v2.0.0 could
#    not tell apart from Enter (`read` also returns "" for the newline).
#  * Parses SS3 (ESC O A) arrow keys, which some terminals send.
read_key(){
  local k="" rc seq ch
  while true; do
    IFS= read -rs -n1 -t 0.5 k; rc=$?
    if (( rc == 0 )); then break; fi
    if (( rc > 128 )); then                    # timeout (or woken by a trap)
      if (( NEED_REDRAW )); then
        NEED_REDRAW=0; FULL_CLEAR=1; KEY="RESIZE"; return 0
      fi
      k=""; continue
    fi
    exit 129                                   # EOF / I-O error: terminal is gone
  done
  if [[ -z $k || $k == $'\r' ]]; then KEY="ENTER"; return 0; fi
  if [[ $k == $'\x1b' ]]; then
    seq=""
    while IFS= read -rs -n1 -t 0.05 ch; do
      seq+=$ch
      if (( ${#seq} == 1 )); then
        if [[ $ch != '[' && $ch != 'O' ]]; then break; fi   # Alt+<key>
        continue
      fi
      if [[ ${seq:0:1} == 'O' ]]; then break; fi            # SS3: ESC O <final>
      if [[ $ch == [A-Za-z~] ]]; then break; fi             # CSI final byte
      if (( ${#seq} >= 8 )); then break; fi                 # malformed: bail out
    done
    if [[ -z $seq ]]; then KEY="ESC"; return 0; fi
    if [[ ${seq:0:1} == 'O' ]]; then seq="[${seq:1}"; fi    # SS3 -> CSI
    KEY="${ESC}${seq}"
    return 0
  fi
  KEY=$k
}

# prompt_line ROW COL LABEL -> $REPLY_LINE  (kernel-edited line; EOF => empty)
# [v2.2.0 FIX] optional 4th arg W = field width: the field is blanked with spaces
# instead of `erase to end of line`, which also wiped the box's right border.
prompt_line(){
  local row=$1 col=$2 label=$3 w=${4:-0}
  cur_goto "$row" "$col"
  printf '%s%s%s%s › ' "$F_HEAD" "$B" "$label" "$R"
  if (( w > 0 )); then
    printf '%*s' $(( w - ${#label} - 3 )) ''
    cur_goto "$row" $(( col + ${#label} + 3 ))
  else
    printf '%s' "$EL"
  fi
  tty_line
  cur_show
  REPLY_LINE=""
  IFS= read -r REPLY_LINE || REPLY_LINE=""      # Ctrl-D at an empty line = cancel
  cur_hide
  tty_raw
}

# =============================================================================
# VALIDATION, ARGV, OUTPUT SANITISING, SAVING
# =============================================================================

# validate_target RAW -> 0/1.  On success sets TARGET, TARGET_KIND, TARGET_FILE.
# [v2.1.0 SEC] the `-iL` branch used to accept ANYTHING after the path except a
# few shell characters, i.e. `-iL f -oN ~/.bashrc` passed validation.  It now
# takes exactly ONE path token from a strict class, must not start with '-',
# and must be a readable regular file.  Every other token must not start with '-'.
validate_target_fmt(){
  local t=$1 path tok
  local -a toks
  REJECT_REASON=""
  t="${t#"${t%%[![:space:]]*}"}"
  t="${t%"${t##*[![:space:]]}"}"
  if [[ -z $t ]]; then REJECT_REASON="Target cannot be empty."; return 1; fi
  if (( ${#t} > 512 )); then REJECT_REASON="Target string is too long."; return 1; fi

  if [[ $t == -iL || $t == -iL[[:space:]]* ]]; then
    if [[ $t =~ ^-iL[[:space:]]+([A-Za-z0-9._/@:+,=-]+)$ ]]; then
      path=${BASH_REMATCH[1]}
      if [[ $path == -* ]]; then REJECT_REASON="File name can't start with '-'."; return 1; fi
      if [[ ! -f $path || ! -r $path ]]; then REJECT_REASON="Can't read file: $path"; return 1; fi
      TARGET=$t; TARGET_KIND="file"; TARGET_FILE=$path
      return 0
    fi
    REJECT_REASON="Use: -iL <file>  (one path; letters, digits and . _ / - only)"
    return 1
  fi
  if [[ $t == -* ]]; then
    REJECT_REASON="Target can't start with '-' (looks like a flag). Use Custom for that."
    return 1
  fi
  if [[ ! $t =~ ^[A-Za-z0-9.:/,_-]+([[:space:]]+[A-Za-z0-9.:/,_-]+)*$ ]]; then
    REJECT_REASON="Target contains characters that aren't allowed."
    return 1
  fi
  read -ra toks <<< "$t"
  for tok in "${toks[@]}"; do
    if [[ $tok == -* ]]; then REJECT_REASON="Target words can't start with '-'."; return 1; fi
  done
  TARGET=$t; TARGET_KIND="hosts"; TARGET_FILE=""
  return 0
}

# ── [v2.2.0 NEW] IPv4 helpers, scope allow-list, address counting ───────────
# ip2int IP VAR -> VAR = 32-bit value; rc 1 if not a dotted quad
ip2int(){
  local ip=$1
  if [[ ! $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then return 1; fi
  local a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]} c=${BASH_REMATCH[3]} d=${BASH_REMATCH[4]}
  if (( 10#$a > 255 || 10#$b > 255 || 10#$c > 255 || 10#$d > 255 )); then return 1; fi
  printf -v "$2" '%d' $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}
# cidr_range TOKEN LOVAR HIVAR -> inclusive integer range of a.b.c.d[/n]
# (callers must not pass variable names that clash with this function's locals)
cidr_range(){
  local _t=$1 _ip _n=32 _base _size
  _ip=${_t%%/*}
  if [[ $_t == */* ]]; then _n=${_t#*/}; fi
  if [[ ! $_n =~ ^[0-9]{1,2}$ ]] || (( 10#$_n > 32 )); then return 1; fi
  _n=$(( 10#$_n ))
  ip2int "$_ip" _base || return 1
  _size=$(( 1 << (32 - _n) ))
  _base=$(( _base & ~(_size - 1) & 0xFFFFFFFF ))
  printf -v "$2" '%d' "$_base"
  printf -v "$3" '%d' $(( _base + _size - 1 ))
}

# scope_load: fail CLOSED - an unreadable/empty scope file authorises nothing.
scope_load(){
  local line
  SCOPE_ENTRIES=(); SCOPE_ON=0
  if [[ -z $SCOPE_FILE ]]; then return 0; fi
  SCOPE_ON=1
  if [[ ! -f $SCOPE_FILE || ! -r $SCOPE_FILE ]]; then return 1; fi
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%%#*}; line=${line//[[:space:]]/}
    if [[ -n $line ]]; then SCOPE_ENTRIES+=("${line,,}"); fi
  done < "$SCOPE_FILE"
  return 0
}

# scope_check_token TOK -> rc 0 if inside scope. Only IPv4 addr/CIDR and plain
# hostnames can be proven; ranges, IPv6 and anything else are refused.
scope_check_token(){
  local tok=${1,,} e lo hi slo shi
  if cidr_range "$tok" lo hi; then
    for e in "${SCOPE_ENTRIES[@]}"; do
      if cidr_range "$e" slo shi && (( lo >= slo && hi <= shi )); then return 0; fi
    done
  elif [[ $tok =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && $tok == *[a-z]* ]]; then
    for e in "${SCOPE_ENTRIES[@]}"; do
      if [[ $e == "$tok" ]]; then return 0; fi
      if [[ $e == \*.* && $tok == *"${e#\*}" ]]; then return 0; fi
    done
  else
    REJECT_REASON="Can't verify '$1' against scope (ranges and IPv6 aren't supported while scope is on)."
    return 1
  fi
  REJECT_REASON="'$1' is outside the authorised scope (${SCOPE_FILE})."
  return 1
}

# scope_check_target: every host token (or every token inside an -iL file).
scope_check_target(){
  local tok line n=0
  local -a toks
  if (( ! SCOPE_ON )); then return 0; fi
  if [[ $TARGET_KIND == file ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      n=$(( n + 1 ))
      if (( n > 10000 )); then REJECT_REASON="Target file too large to verify against scope."; return 1; fi
      line=${line%%#*}; read -ra toks <<< "$line"
      for tok in "${toks[@]}"; do
        scope_check_token "$tok" || return 1
      done
    done < "$TARGET_FILE"
    return 0
  fi
  read -ra toks <<< "$TARGET"
  for tok in "${toks[@]}"; do
    scope_check_token "$tok" || return 1
  done
  return 0
}

# validate_target RAW: format check, then scope check (clears TARGET on refusal)
validate_target(){
  if ! validate_target_fmt "$1"; then return 1; fi
  if ! scope_check_target; then TARGET=""; TARGET_FILE=""; return 1; fi
  return 0
}

# addr_count -> ADDR_COUNT: estimated number of addresses (for the large-scan guard)
addr_count(){
  local tok lo hi n=0 m
  local -a toks
  if [[ $TARGET_KIND == file ]]; then
    m=$(wc -l < "$TARGET_FILE" 2>/dev/null); ADDR_COUNT=$(( ${m:-0} + 0 )); return 0
  fi
  read -ra toks <<< "$TARGET"
  for tok in "${toks[@]}"; do
    if cidr_range "$tok" lo hi; then
      n=$(( n + hi - lo + 1 ))
    elif [[ $tok == */* && $tok == *:* ]]; then
      m=${tok#*/}
      if [[ $m =~ ^[0-9]+$ ]] && (( m <= 112 )); then n=$(( n + 1000000 )); else n=$(( n + 1 )); fi
    elif [[ $tok =~ ^[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+)-([0-9]+)$ ]]; then
      m=$(( 10#${BASH_REMATCH[2]} - 10#${BASH_REMATCH[1]} + 1 ))
      if (( m < 1 )); then m=1; fi
      n=$(( n + m ))
    elif [[ $tok == *.*.*.* && $tok == *-* ]]; then
      n=$(( n + 65536 ))          # multi-octet ranges: assume large
    else
      n=$(( n + 1 ))
    fi
  done
  ADDR_COUNT=$n
}

# flags_need_root FLAGS -> rc 0 if any flag needs raw sockets
flags_need_root(){
  local t
  local -a fl
  read -ra fl <<< "$1"
  for t in "${fl[@]}"; do
    case $t in
      -sS|-sU|-sF|-sN|-sX|-sA|-sW|-sM|-sY|-sZ|-O|--osscan-guess|--osscan-limit) return 0;;
    esac
  done
  return 1
}
# nonroot_fallback: rewrite SCAN_PROFILE for an unprivileged run (SYN -> connect,
# drop OS detection). rc 1 when the scan type has no unprivileged equivalent.
nonroot_fallback(){
  local t
  local -a fl out=()
  read -ra fl <<< "$SCAN_PROFILE"
  for t in "${fl[@]}"; do
    case $t in
      -sS) out+=(-sT);;
      -O|--osscan-guess|--osscan-limit) ;;
      -sU|-sF|-sN|-sX|-sA|-sW|-sM|-sY|-sZ) return 1;;
      *) out+=("$t");;
    esac
  done
  if (( ${#out[@]} == 0 )); then return 1; fi
  SCAN_PROFILE="${out[*]}"
  return 0
}

# pick_oa_base -> OA_BASE: unpredictable name in OUTDIR, none of the three
# output files may exist (nmap itself would follow a pre-planted symlink).
pick_oa_base(){
  local dir=$OUTDIR slug ts cand
  OA_BASE=""
  ( umask 077; mkdir -p -- "$dir" ) 2>/dev/null
  if [[ ! -d $dir || ! -w $dir ]]; then return 1; fi
  if [[ $dir == -* ]]; then dir="./$dir"; fi
  slug=$(sanitize_slug "$TARGET"); ts=$(date +%Y%m%d_%H%M%S)
  for _ in 1 2 3 4 5; do
    cand="$dir/nmap_${ts}_${slug}_${RANDOM}${RANDOM}"
    if [[ ! -e $cand.nmap && ! -L $cand.nmap && ! -e $cand.gnmap && ! -L $cand.gnmap \
       && ! -e $cand.xml && ! -L $cand.xml ]]; then OA_BASE=$cand; return 0; fi
  done
  return 1
}

# build_scan_argv -> SCAN_ARGV, SCAN_CMD.
# [v2.1.0 FIX] v2.0.0 always put `--` before the target words, which turned the
# documented `-iL file` form into two hostnames ("-iL", "<file>") — real nmap
# answers `Failed to resolve "-iL"`.  File targets are now passed as an option.
build_scan_argv(){
  local tok all6=1
  local -a flags=() targets=()
  read -ra flags <<< "$SCAN_PROFILE"
  SCAN_ARGV=("${flags[@]}")
  # [v2.2.0 NEW] optional -oA; must precede `--`. "<auto>" is a preview placeholder.
  if (( AUTO_OA )); then SCAN_ARGV+=(-oA "${OA_BASE:-<auto>}"); fi
  if [[ $TARGET_KIND == file ]]; then
    SCAN_ARGV+=(-iL "$TARGET_FILE")
  else
    read -ra targets <<< "$TARGET"
    # [v2.1.0 ROBUST] IPv6 literals need -6, or nmap reports "Failed to resolve".
    for tok in "${targets[@]}"; do [[ $tok == *:* ]] || all6=0; done
    if (( all6 )) && [[ " ${flags[*]} " != *" -6 "* ]]; then SCAN_ARGV+=(-6); fi
    SCAN_ARGV+=(-- "${targets[@]}")
  fi
  SCAN_CMD="nmap ${SCAN_ARGV[*]}"
}

# sanitize_output FILE MAXLINES -> stdout.
# [v2.1.0 SEC] Scan output carries bytes controlled by the *remote* side
# (banners, DNS names, NSE script output).  Raw ESC sequences could clear or
# redraw the screen, set the title, or fake UI.  Strip every C0 control (incl.
# ESC, CR, DEL) and C1 controls (UTF-8 C2 80..9F) in the C locale; tabs -> 4
# spaces; `q` is the LAST sed command so the final kept line is sanitised too.
sanitize_output(){
  local tab c2 lo hi
  tab=$(printf '\t'); c2=$(printf '\302'); lo=$(printf '\200'); hi=$(printf '\237')
  LC_ALL=C sed -e "s/${tab}/    /g" \
               -e 's/[[:cntrl:]]//g' \
               -e "s/${c2}[${lo}-${hi}]//g" \
               -e "${2}q" "$1"
}

# colorize: stdin -> stdout, one awk pass (v2.0.0 used 9 chained sed expressions
# that also coloured "open" inside words and arbitrary banner text).
colorize(){
  awk -v G="${F_GOOD}${B}" -v D="$F_DANGER" -v Y="$F_WARN" -v H="${F_HEAD}${B}" \
      -v T="${F_TITLE}${B}" -v Z="$R" '
    /^[0-9]+\/(tcp|udp|sctp)[ \t]/ {
      st = $2; c = Y
      if (st == "open") c = G; else if (st == "closed") c = D
      p = index($0, st)
      print substr($0, 1, p - 1) c st Z substr($0, p + length(st)); next
    }
    /^Nmap scan report for/        { print H $0 Z; next }
    /^Host is up/                  { print G $0 Z; next }
    /^Host seems down/             { print D $0 Z; next }
    /^(OS details|Service Info|Running|Aggressive OS guesses):/ { print T $0 Z; next }
    /VULNERABLE/                   { gsub(/VULNERABLE/, D "&" Z); print; next }
    { print }'
}

# sanitize_slug STR -> [A-Za-z0-9_] only, max 40 chars (filenames only)
sanitize_slug(){ local s=$1; s="${s//[^A-Za-z0-9]/_}"; printf '%s' "${s:0:40}"; }

# write_unique SUFFIX EXT BODY -> prints the file written (rc 0) or nothing (rc 1).
# [v2.1.0 SEC] v2.0.0 checked `[[ -e ]]` then wrote with `>`: a dangling symlink
# planted at the predictable name passed the check and the write followed it to
# an attacker-chosen path (and two instances could race).  Now the create itself
# is the atomic test: noclobber => O_EXCL, which refuses existing files AND
# symlinks; on collision the next suffix is tried.  Mode 0600, dir 0700 if new.
# [v2.1.0 NEW] collision suffix is _2, _3 (not _vN) so it can't be mistaken for
# the tool version in nmap_tui_vX.Y.Z.sh.
# [v2.2.0 REFACTOR] generalised so the .txt record and the .md report share it.
write_unique(){
  local suffix=$1 ext=$2 body=$3 dir=$OUTDIR slug ts base cand n=1
  ( umask 077; mkdir -p -- "$dir" ) 2>/dev/null
  if [[ ! -d $dir || ! -w $dir ]]; then return 1; fi
  slug=$(sanitize_slug "$TARGET")
  ts=$(date +%Y%m%d_%H%M%S)
  base="nmap_${ts}_${slug}${suffix}"
  while (( n <= 999 )); do
    if (( n == 1 )); then cand="$dir/${base}.${ext}"; else cand="$dir/${base}_${n}.${ext}"; fi
    if ( set -o noclobber; umask 077; printf '%s\n' "$body" > "$cand" ) 2>/dev/null; then
      printf '%s' "$cand"; return 0
    fi
    # Failed. A collision (file or symlink exists) => try next suffix; anything
    # else (permissions, disk full) => give up instead of looping.
    if [[ ! -e $cand && ! -L $cand ]]; then return 1; fi
    n=$(( n + 1 ))
  done
  return 1
}

save_results(){
  local header
  header=$(printf '# nmap-tui scan record\n# Saved: %s\n# Target: %s\n# Command: %s\n# nmap exit status: %s%s\n# Generated by: %s (v%s)\n# ----------------------------------------' \
    "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$TARGET" "$SCAN_CMD" "$SCAN_RC" \
    "$( (( SCAN_CANCELLED )) && printf ' (cancelled by user)' )" "$SCRIPT_FILE" "$SCRIPT_VERSION")
  write_unique "" txt "${header}"$'\n\n'"${SCAN_RESULTS}"
}

# [v2.2.0 NEW] make_report -> Markdown on stdout: header + one table per host of
# its open ports.  Remote-controlled strings (host names, banners) are
# backslash-escaped so they can't inject Markdown/HTML into the report.
make_report(){
  # shellcheck disable=SC2016  # backticks are literal Markdown, not command substitution
  printf '# nmap scan report\n\n- **Target:** `%s`\n- **Command:** `%s`\n- **Date:** %s\n- **nmap exit status:** %s\n- **Generated by:** %s (v%s)\n' \
    "$TARGET" "$SCAN_CMD" "$(date '+%Y-%m-%d %H:%M:%S')" "$SCAN_RC" "$SCRIPT_FILE" "$SCRIPT_VERSION"
  printf '%s\n' "$SCAN_RESULTS" | awk '
    function esc(x) { gsub(/[|`<>\\]/, "\\\\&", x); return x }
    function endhost() { if (inhost && !rows) print "_No open ports reported._"; }
    /^Nmap scan report for/ { endhost(); print "\n## " esc(substr($0, 22)) "\n"; hdr = 0; rows = 0; inhost = 1; next }
    /^[0-9]+\/(tcp|udp|sctp)[ \t]+open/ {
      if (!hdr) { print "| Port | State | Service | Detail |"; print "|---|---|---|---|"; hdr = 1 }
      d = ""; for (i = 4; i <= NF; i++) d = d (i > 4 ? " " : "") $i
      print "| " $1 " | " esc($2) " | " esc($3) " | " esc(d) " |"; rows++; next }
    /^(OS details|Service Info|Running|Aggressive OS guesses):/ { print "\n**" esc($0) "**" }
    END { endhost() }'
}

# [v2.2.0 NEW] persistent history.  One TSV line per scan; fields are re-validated
# on load (a tampered file can't inject targets/flags); symlinks are refused;
# appends stop at 1 MiB so loading stays cheap.
hist_append(){      # ts note target flags
  local f=$HIST_FILE sz
  if [[ -L $f ]]; then return 1; fi
  ( umask 077; mkdir -p -- "$OUTDIR" ) 2>/dev/null
  if [[ -f $f ]]; then
    sz=$(wc -c < "$f" 2>/dev/null); if (( ${sz:-0} > 1048576 )); then return 1; fi
  fi
  ( umask 077; printf '%s\t%s\t%s\t%s\n' "$1" "$2" "${3//[[:cntrl:]]/}" "${4//[[:cntrl:]]/ }" >> "$f" ) 2>/dev/null
}
hist_load(){
  local f=$HIST_FILE ts note tgt flags cmd n start
  local sv_t=$TARGET sv_k=$TARGET_KIND sv_f=$TARGET_FILE
  local -a lines
  if [[ ! -f $f || -L $f || ! -r $f ]]; then return 0; fi
  mapfile -t lines < "$f"
  start=$(( ${#lines[@]} - 200 )); if (( start < 0 )); then start=0; fi
  for (( n=start; n<${#lines[@]}; n++ )); do
    ts="" note="" tgt="" flags=""
    IFS=$'\t' read -r ts note tgt flags <<< "${lines[n]}"
    if [[ ! $ts =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9:]{8}$ ]]; then continue; fi
    if [[ ! $note =~ ^(ok|cancelled|exit\ [0-9]+)$ ]]; then continue; fi
    if [[ ! $flags =~ ^[A-Za-z0-9\ ._,:/=@+%-]*$ ]]; then continue; fi
    if ! validate_target "$tgt"; then continue; fi
    if [[ $TARGET_KIND == file ]]; then cmd="nmap $flags $TARGET"; else cmd="nmap $flags -- $TARGET"; fi
    HIST_TS+=("$ts"); HIST_TGT+=("$TARGET"); HIST_CMD+=("$cmd"); HIST_NOTE+=("$note"); HIST_FLAGS+=("$flags")
  done
  TARGET=$sv_t; TARGET_KIND=$sv_k; TARGET_FILE=$sv_f
  return 0
}

# =============================================================================
# PAGER (shared by results, history, methodology guide)
# =============================================================================
# [v2.1.0 FIX] v2.0.0 drew the guide and history with absolute cursor moves and
# no scrolling: on a 40-row terminal PHASE 6 of the guide was never visible, and
# history overflowed the box after ~15 scans.
PG_LINES=()
PG_TITLE=""
PG_HINTS=""
PG_HOOK=""      # function(key): rc 0 = keep paging, rc 1 = leave the pager

# [v2.2.0 NEW] pager_find DIR INCLUSIVE: move `offset` to the next/previous line
# containing PG_PAT (case-insensitive, literal).  Uses pager()'s locals (offset,
# total, msg) via bash dynamic scoping.
pager_find(){
  local dir=$1 incl=$2 i plain pat=${PG_PAT,,}
  if [[ -z $pat ]]; then return 0; fi
  for (( i = offset + (1 - incl) * dir; i >= 0 && i < total; i += dir )); do
    strip_ansi "${PG_LINES[i]}" plain
    if [[ ${plain,,} == *"$pat"* ]]; then offset=$i; msg="match at line $(( i + 1 )) - "; return 0; fi
  done
  msg="no more matches for '${PG_PAT}' - "
}

pager(){
  local total=${#PG_LINES[@]} offset=0 page_h max_off i end pct buf title full=1 rc msg=""
  while true; do
    if (( full )); then clear_screen; full=0; fi
    page_h=$(( ROWS - 2 )); if (( page_h < 1 )); then page_h=1; fi
    max_off=$(( total - page_h )); if (( max_off < 0 )); then max_off=0; fi
    if (( offset > max_off )); then offset=$max_off; fi
    end=$(( offset + page_h )); if (( end > total )); then end=$total; fi

    # One write per frame (v2.0.0: ~40 small writes per keystroke).
    fit title "$PG_TITLE" $(( COLS - 2 ))
    mv 1 1
    buf="${MV}${B_PANEL}${F_TITLE}${B}${EL2} ${title}${R}"
    for (( i=offset; i<end; i++ )); do
      mv $(( i - offset + 2 )) 1
      buf+="${MV}${R}${EL2}${PG_LINES[i]}${R}"
    done
    for (( i=end-offset; i<page_h; i++ )); do
      mv $(( i + 2 )) 1
      buf+="${MV}${R}${EL2}"
    done
    printf '%s' "$buf"
    pct=100; if (( total > 0 )); then pct=$(( end * 100 / total )); fi
    status_bar "${msg}${PG_HINTS}Lines $(( offset + 1 ))-${end}/${total} [${pct}%]"
    msg=""

    read_key
    case $KEY in
      "${ESC}[A"|k)         if (( offset > 0 )); then offset=$(( offset - 1 )); fi;;
      "${ESC}[B"|j|ENTER)   if (( offset < max_off )); then offset=$(( offset + 1 )); fi;;
      "${ESC}[5~"|b)        offset=$(( offset - (page_h - 1) )); if (( offset < 0 )); then offset=0; fi;;
      "${ESC}[6~"|' '|f)    offset=$(( offset + (page_h - 1) )); if (( offset > max_off )); then offset=$max_off; fi;;
      "${ESC}[H"|"${ESC}[1~"|g)  offset=0;;
      "${ESC}[F"|"${ESC}[4~"|G)  offset=$max_off;;
      RESIZE)               ensure_min_terminal_size; full=1;;
      '/')                  prompt_line "$ROWS" 1 "find"
                            if [[ -n $REPLY_LINE ]]; then PG_PAT=$REPLY_LINE; pager_find 1 1; fi
                            full=1;;
      '.')                  pager_find 1 0;;
      ',')                  pager_find -1 0;;
      q|Q|ESC)              return 0;;
      *)
        if [[ -n $PG_HOOK ]]; then
          "$PG_HOOK" "$KEY"; rc=$?
          if (( rc != 0 )); then return 0; fi
        fi;;
    esac
  done
}

# =============================================================================
# SCREENS
# =============================================================================

# [v2.2.0 FIX] centred from COLS; v2.1.0 passed a fixed column 8, so the 74-column
# banner was clipped on terminals narrower than ~82 and off-centre on wider ones.
draw_banner(){   # 8 rows starting at row 2
  local col=$(( (COLS - 74) / 2 )) row=2 l
  if (( col < 1 )); then col=1; fi
  local -a lines=(
    "${F_TITLE}${B} ███╗   ██╗███╗   ███╗ █████╗ ██████╗     ████████╗██╗   ██╗██╗${R}"
    "${F_TITLE}${B} ████╗  ██║████╗ ████║██╔══██╗██╔══██╗       ██╔══╝██║   ██║██║${R}"
    "${F_TITLE}${B} ██╔██╗ ██║██╔████╔██║███████║██████╔╝       ██║   ██║   ██║██║${R}"
    "${F_TITLE}${B} ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝        ██║   ██║   ██║██║${R}"
    "${F_TITLE}${B} ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║            ██║   ╚██████╔╝██║${R}"
    "${F_TITLE}${B} ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝            ╚═╝    ╚═════╝ ╚═╝${R}"
    ""
    "${F_MUTED}        Ethical Hacker's Network Mapping Terminal - bash TUI  v${SCRIPT_VERSION}${R}"
  )
  for l in "${lines[@]}"; do
    cur_goto "$row" "$col"; printf '%s%s' "$l" "$EL"
    row=$(( row + 1 ))
  done
}

# ── Main menu ─────────────────────────────────────────────────────────────────
# [v2.1.0 FIX] v2.0.0 hard-coded rows (box 11..24, strip at 23): at the
# advertised 80x24 minimum the box overlapped the strip and the status bar.
# Layout is now derived from ROWS; short terminals get a compact title.
screen_menu(){
  local mw=52 mcol mrow gap h i ir strip
  local -a items=("1  New Scan" "2  Scan History" "3  Methodology Guide" "4  About / Legal Notice" "Q  Quit")
  begin_screen
  mcol=$(( (COLS - mw) / 2 ))
  if (( ROWS >= 30 )); then
    draw_banner; mrow=11; gap=2
  else
    cur_goto 2 3
    printf '%s%sNMAP-TUI%s %sv%s - Ethical Hacker'"'"'s Network Mapping Terminal%s%s' \
      "$F_TITLE" "$B" "$R" "$F_MUTED" "$SCRIPT_VERSION" "$R" "$EL"
    mrow=4; gap=1
  fi
  h=$(( 2 + 2 + 5 + 4 * (gap - 1) ))
  draw_box "$mrow" "$mcol" "$h" "$mw" " MAIN MENU "
  ir=$(( mrow + 2 ))
  for (( i=0; i<${#items[@]}; i++ )); do
    cur_goto $(( ir + i * gap )) $(( mcol + 3 ))
    if (( i + 1 == MENU_SEL )); then
      printf '%s%s%s %-44s %s' "$B_SEL" "$F_WHITE" "$B" "${items[i]}" "$R"
    else
      printf ' %s%-44s%s ' "$F_TXT" "${items[i]}" "$R"
    fi
  done
  strip=$(( mrow + h + 1 ))
  cur_goto "$strip" 3
  printf '%sMethodology: %sRECON → DISCOVERY → PORT SCAN → SVC ENUM → VULN MAP → REPORT%s%s' \
    "$F_MUTED" "$F_HEAD" "$R" "$EL"
  hints "↑↓" "navigate" "Enter" "select" "Q" "quit"
  status_bar "$HINTS"
}

# ── Target input ──────────────────────────────────────────────────────────────
screen_target(){
  local bw=70 bcol brow bh=17 r input_row error_row ex input
  local -a examples=(
    "Single host :  192.168.1.1"
    "CIDR range  :  192.168.1.0/24"
    "Range       :  192.168.1.1-50"
    "Hostname    :  scanme.nmap.org"
    "Input file  :  -iL /path/to/hosts.txt"
  )
  begin_screen
  bcol=$(( (COLS - bw) / 2 ))
  brow=$(( (ROWS - bh) / 3 )); if (( brow < 2 )); then brow=2; fi
  draw_box "$brow" "$bcol" "$bh" "$bw" " STEP 1 — DEFINE TARGET "
  r=$(( brow + 2 ))
  cur_goto "$r" $(( bcol + 3 ))
  printf '%s%sSpecify your target%s' "$F_HEAD" "$B" "$R"
  r=$(( r + 2 ))
  for ex in "${examples[@]}"; do
    cur_goto "$r" $(( bcol + 3 ))
    printf '  %s%s%s' "$F_MUTED" "$ex" "$R"
    r=$(( r + 1 ))
  done
  r=$(( r + 1 ))
  cur_goto "$r" $(( bcol + 3 ))
  printf '%s⚠  Scan only networks you own or are authorised to test.%s' "$F_WARN" "$R"
  r=$(( r + 2 ))
  draw_hline "$r" $(( bcol + 1 )) $(( bw - 2 ))
  input_row=$(( r + 1 )); error_row=$(( r + 2 ))
  hints "Enter" "accept" "Backspace" "edit" "empty+Enter" "cancel"
  status_bar "$HINTS"

  while true; do
    prompt_line "$input_row" $(( bcol + 3 )) "Target" $(( bw - 6 ))
    input=$REPLY_LINE
    # [v2.2.0 FIX] the old error was erased BEFORE the prompt, i.e. immediately
    # after being printed, so a rejected target never showed its reason.  Clear it
    # only once the user has answered; the new verdict is drawn after validation.
    cur_goto "$error_row" $(( bcol + 3 )); repeat_char $(( bw - 6 )) ' '
    if [[ -z ${input//[[:space:]]/} ]]; then TARGET=""; PHASE=0; return; fi
    if validate_target "$input"; then return; fi
    cur_goto "$error_row" $(( bcol + 3 ))
    printf '%s%s%s' "$F_DANGER" "$REJECT_REASON" "$R"
  done
}

# ── Profile selector ──────────────────────────────────────────────────────────
PROFILE_MSG_ROW=0
screen_profile(){
  local bw=74 bcol brow bh i r name desc flags root tag tgt
  begin_screen
  bcol=$(( (COLS - bw) / 2 ))
  bh=$(( NPROFILES + 7 ))
  brow=2; if (( ROWS >= 30 )); then brow=3; fi
  draw_box "$brow" "$bcol" "$bh" "$bw" " STEP 2 — SELECT SCAN PROFILE "
  fit tgt "$TARGET" $(( bw - 14 ))
  cur_goto $(( brow + 2 )) $(( bcol + 3 ))
  printf '%sTarget: %s%s%s%s' "$F_MUTED" "$F_TXT" "$B" "$tgt" "$R"
  r=$(( brow + 4 ))
  for (( i=1; i<=NPROFILES; i++ )); do
    IFS='|' read -r name desc flags root <<< "${PROFILES[$i]}"
    tag="    "; if [[ $root == y ]]; then tag="root"; fi
    cur_goto "$r" $(( bcol + 2 ))
    if (( i == PROFILE_SEL )); then
      printf '%s%s%s %2d  %-22s  %-32s %-4s %s' "$B_SEL" "$F_WHITE" "$B" "$i" "$name" "$desc" "$tag" "$R"
    else
      printf ' %s%2d%s  %s%s%-22s%s  %s%-32s%s %s%-4s%s ' \
        "$F_KEY" "$i" "$R" "$F_TXT" "$B" "$name" "$R" "$F_MUTED" "$desc" "$R" "$F_WARN" "$tag" "$R"
    fi
    r=$(( r + 1 ))
  done
  PROFILE_MSG_ROW=$(( r + 1 ))
  # [v2.2.0 FIX] blank the message row first: text left by the Custom prompt or an
  # earlier message used to linger, and `erase to EOL` would eat the border.
  cur_goto "$PROFILE_MSG_ROW" $(( bcol + 3 )); repeat_char 68 ' '
  cur_goto "$PROFILE_MSG_ROW" $(( bcol + 3 ))
  # [v2.1.0 UX] unhandled edge case: root-only scan types fail with a cryptic
  # nmap error when run unprivileged; flag them up front.
  if (( EUID != 0 )); then
    printf '%s"root" profiles need sudo (SYN/UDP/OS) - not running as root.%s' "$F_WARN" "$R"
  fi
  hints "↑↓" "navigate" "Enter" "run" "0-9" "quick pick" "B" "back" "Q" "menu"
  status_bar "$HINTS"
}

# prompt_custom_flags -> rc 0 and SCAN_PROFILE set; rc 1 if cancelled (empty)
# [v2.1.0 FIX] v2.0.0 re-prompted forever on empty input (only Ctrl+C escaped).
prompt_custom_flags(){
  local bcol=$(( (COLS - 74) / 2 ))
  cur_goto "$PROFILE_MSG_ROW" $(( bcol + 3 )); repeat_char 68 ' '
  prompt_line "$PROFILE_MSG_ROW" $(( bcol + 3 )) "nmap flags" 68
  if [[ -z ${REPLY_LINE//[[:space:]]/} ]]; then return 1; fi
  SCAN_PROFILE=$REPLY_LINE
  return 0
}

# launch_profile N -> sets SCAN_PROFILE and moves to the confirm screen (PHASE 13),
# or stays on the profile screen.  [v2.2.0] was PHASE=3 (ran immediately).
launch_profile(){
  local n=$1 name desc flags root bcol
  IFS='|' read -r name desc flags root <<< "${PROFILES[$n]}"
  PROFILE_SEL=$n
  if [[ $flags == CUSTOM ]]; then
    if (( SCOPE_ON )); then
      # Custom flags may contain targets (e.g. `10.0.0.0/8`) that the scope check
      # can't see, so they are disabled while a scope file is active.
      bcol=$(( (COLS - 74) / 2 ))
      cur_goto "$PROFILE_MSG_ROW" $(( bcol + 3 )); repeat_char 68 ' '
      printf '%sCustom is off while a scope file is active.%s (press any key)' "$F_DANGER" "$R"
      read_key
      return 1
    fi
    prompt_custom_flags || return 1
  else
    SCAN_PROFILE=$flags
  fi
  PHASE=13
}

# ── Confirm screen [v2.2.0 NEW] ───────────────────────────────────────────────
# Shows exactly what will run, the size of the job, root/scope status; the only
# place a scan can be started.
screen_confirm(){
  local bw=76 bcol brow=2 i r k w=70 need_y cmd off len tgt
  local -a L
  FULL_CLEAR=1; begin_screen
  while true; do
    ensure_min_terminal_size
    bcol=$(( (COLS - bw) / 2 ))
    build_scan_argv; addr_count
    need_y=0; L=()
    fit tgt "$TARGET" $(( w - 10 ))
    L+=("${F_MUTED}Target:   ${F_TXT}${B}${tgt}${R}")
    L+=("${F_MUTED}Command:${R}")
    cmd=$SCAN_CMD; off=0; len=${#cmd}
    while (( off < len && ${#L[@]} < 9 )); do
      L+=("  ${F_TXT}${B}${cmd:off:w-2}${R}"); off=$(( off + w - 2 ))
    done
    if (( off < len )); then L[${#L[@]}-1]="  ${F_TXT}${B}…(truncated; see History)${R}"; fi
    L+=("")
    L+=("${F_MUTED}Addresses: ${F_TXT}~${ADDR_COUNT}${R}")
    if (( ADDR_COUNT >= LARGE_ADDR )); then
      need_y=1
      L+=("${F_DANGER}${B}LARGE SCAN${R}${F_DANGER}: this will probe a very large number of hosts - press Y to confirm.${R}")
    fi
    if (( SCOPE_ON )); then L+=("${F_GOOD}Scope:   all targets inside ${SCOPE_FILE}${R}")
    else L+=("${F_MUTED}Scope:   not enforced (set NMAP_TUI_SCOPE to a file of authorised targets)${R}"); fi
    if (( AUTO_OA )); then L+=("${F_GOOD}Auto-save: ON  - nmap -oA files go to ${OUTDIR}${R}")
    else L+=("${F_MUTED}Auto-save: off (A to toggle: also keeps nmap .xml/.gnmap files)${R}"); fi
    if (( EUID != 0 )) && flags_need_root "$SCAN_PROFILE"; then
      L+=("${F_WARN}Needs root and you are not root: nmap will likely refuse. T = unprivileged fallback.${R}")
    fi
    draw_box "$brow" "$bcol" $(( ${#L[@]} + 4 )) "$bw" " CONFIRM SCAN "
    for (( i=0; i<${#L[@]}; i++ )); do
      cur_goto $(( brow + 2 + i )) $(( bcol + 3 )); printf '%s' "${L[i]}"
    done
    r=$(( brow + 2 + ${#L[@]} + 1 ))
    cur_goto "$r" $(( bcol + 3 ))
    printf '%sAuthorised targets only.%s' "$F_WARN" "$R"
    if (( need_y )); then hints "Y" "run (large scan)" "A" "auto-save" "B" "back" "Q" "menu"
    else hints "Enter" "run" "A" "auto-save" "T" "no-root" "B" "back" "Q" "menu"; fi
    status_bar "$HINTS"

    read_key
    case $KEY in
      ENTER)    if (( ! need_y )); then k=run; fi;;
      y|Y)      k=run;;
      a|A)      if (( AUTO_OA )); then AUTO_OA=0; else AUTO_OA=1; fi; k="";;
      t|T)      if ! nonroot_fallback; then
                  status_bar "${F_DANGER}No unprivileged equivalent for this scan type.${R}  (press any key)"; read_key
                fi; k="";;
      b|B|ESC)  PHASE=2; return 0;;
      q|Q)      PHASE=0; return 0;;
      RESIZE)   FULL_CLEAR=1; begin_screen; k="";;
      *)        k="";;
    esac
    if [[ ${k:-} == run ]]; then
      # Re-verify scope at the moment of launch (an -iL file may have changed).
      if ! scope_check_target; then
        status_bar "${F_DANGER}${REJECT_REASON}${R}  (press any key)"; read_key
        PHASE=1; return 0
      fi
      PHASE=3; return 0
    fi
    k=""
  done
}

# ── Scanning screen ────────────────────────────────────────────────────────────
scan_draw(){
  local bw=72 bcol brow=4 tgt cmd
  bcol=$(( (COLS - bw) / 2 ))
  draw_box "$brow" "$bcol" 12 "$bw" " SCANNING… "
  fit tgt "$TARGET" $(( bw - 14 ))
  fit cmd "$SCAN_CMD" $(( bw - 14 ))
  cur_goto $(( brow + 2 )) $(( bcol + 3 ))
  printf '%sTarget:  %s%s%s%s' "$F_MUTED" "$F_TXT" "$B" "$tgt" "$R"
  cur_goto $(( brow + 3 )) $(( bcol + 3 ))
  printf '%sCommand: %s%s%s%s' "$F_MUTED" "$F_TXT" "$B" "$cmd" "$R"
  cur_goto $(( brow + 9 )) $(( bcol + 3 ))
  printf '%sPress %sC%s%s to cancel this scan.  Ctrl+C quits the program.%s' \
    "$F_MUTED" "$F_KEY" "$R" "$F_MUTED" "$R"
  hints "C" "cancel scan" "Ctrl+C" "quit"
  status_bar "$HINTS"
}

screen_scanning(){
  local tmpout pid t0=$SECONDS el=0 i=0 key rc nlines note=""
  local spinner='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' bcol
  local oa_wanted=$AUTO_OA
  SCAN_RESULTS=""; SCAN_RC=0; SCAN_CANCELLED=0; SCAN_TRUNC=0; SCAN_OA_NOTE=""; OA_BASE=""
  if (( AUTO_OA )) && ! pick_oa_base; then
    AUTO_OA=0; SCAN_OA_NOTE="Auto-save skipped: ${OUTDIR} is not writable."
  fi
  build_scan_argv
  FULL_CLEAR=1; begin_screen; scan_draw
  bcol=$(( (COLS - 72) / 2 ))

  if ! tmpout=$(mktemp 2>/dev/null); then
    status_bar "${F_DANGER}Could not create a temp file for scan output.${R}  (press any key)"
    read_key; PHASE=2; return
  fi
  SCAN_TMPFILE=$tmpout

  # [v2.1.0 FIX] stdin </dev/null.  nmap otherwise inherits the TTY and reads
  # the keyboard for its runtime-interaction keys (v/d/p/...): keys typed during
  # a scan changed nmap's verbosity/packet-trace (writing "Verbosity Increased"
  # into the results) and were stolen from the TUI.
  nmap "${SCAN_ARGV[@]}" >"$tmpout" 2>&1 </dev/null &
  pid=$!
  SCAN_PID=$pid

  while kill -0 "$pid" 2>/dev/null; do
    el=$(( SECONDS - t0 ))
    cur_goto $(( 4 + 6 )) $(( bcol + 3 ))
    printf '%s%s%s  Scanning…  %02d:%02d%s%s' "$F_HEAD" "$B" "${spinner:i%${#spinner}:1}" \
      $(( el / 60 )) $(( el % 60 )) "$R" "$EL"
    i=$(( i + 1 ))
    key=""
    # The read doubles as the 100 ms frame delay AND swallows keys typed during
    # the scan (v2.0.0 left them queued for the results screen).
    IFS= read -rs -n1 -t 0.1 key; rc=$?
    if (( rc > 0 && rc <= 128 )); then exit 129; fi          # tty gone
    if [[ $key == [cC] ]]; then
      SCAN_CANCELLED=1; kill "$pid" 2>/dev/null; break
    fi
    if (( NEED_REDRAW )); then
      NEED_REDRAW=0; ensure_min_terminal_size; FULL_CLEAR=1; begin_screen; scan_draw
      bcol=$(( (COLS - 72) / 2 ))
    fi
  done
  wait "$pid" 2>/dev/null
  SCAN_RC=$?
  SCAN_PID=""

  # [v2.1.0 ROBUST] bound memory: count with wc, keep at most MAX_LINES.
  nlines=$(wc -l < "$tmpout" 2>/dev/null); nlines=$(( ${nlines:-0} + 0 ))
  if (( nlines > MAX_LINES )); then SCAN_TRUNC=1; fi
  SCAN_RESULTS=$(sanitize_output "$tmpout" "$MAX_LINES")
  rm -f "$tmpout"; SCAN_TMPFILE=""
  if [[ -n $OA_BASE ]]; then
    if [[ -e $OA_BASE.xml || -e $OA_BASE.nmap ]]; then SCAN_OA_NOTE="Raw nmap files: ${OA_BASE}.{nmap,gnmap,xml}"; fi
  fi
  AUTO_OA=$oa_wanted; OA_BASE=""

  if (( SCAN_CANCELLED )); then note="cancelled"
  elif (( SCAN_RC != 0 )); then note="exit ${SCAN_RC}"
  else note="ok"; fi
  HIST_TS+=("$(date '+%Y-%m-%d %H:%M:%S')")
  HIST_TGT+=("$TARGET")
  HIST_CMD+=("$SCAN_CMD")
  HIST_NOTE+=("$note")
  HIST_FLAGS+=("$SCAN_PROFILE")
  hist_append "${HIST_TS[-1]}" "$note" "$TARGET" "$SCAN_PROFILE" || true   # [v2.2.0] persist
}

# ── Results viewer ─────────────────────────────────────────────────────────────
# [v2.1.0 FIX] the "nmap exited with code N" banner used to be prepended to
# SCAN_RESULTS itself, so Save wrote raw ANSI escapes into the file (the docs
# claimed plain text).  SCAN_RESULTS now stays plain; the banner is a display-
# only line and the exit status goes into the saved header instead.
results_hook(){
  local f
  case $1 in
    s|S)
      if f=$(save_results); then
        status_bar "${F_GOOD}Saved → ${f}${R}   (press any key)"
      else
        status_bar "${F_DANGER}Save failed - check permissions for ${OUTDIR}${R}   (press any key)"
      fi
      read_key
      return 0;;
    r|R)      # [v2.2.0 NEW] Markdown report
      if f=$(write_unique "_report" md "$(make_report)"); then
        status_bar "${F_GOOD}Report → ${f}${R}   (press any key)"
      else
        status_bar "${F_DANGER}Report failed - check permissions for ${OUTDIR}${R}   (press any key)"
      fi
      read_key
      return 0;;
    n|N) PHASE=1; return 1;;
  esac
  return 0
}

screen_results(){
  local -a colored=()
  PG_LINES=()
  if (( SCAN_CANCELLED )); then
    PG_LINES+=("${F_WARN}${B}Scan cancelled by user - partial output (if any) below.${R}")
  elif (( SCAN_RC != 0 )); then
    PG_LINES+=("${F_DANGER}${B}nmap exited with status ${SCAN_RC} - output below may be incomplete or an error.${R}")
  fi
  if [[ -n $SCAN_OA_NOTE ]]; then PG_LINES+=("${F_GOOD}${SCAN_OA_NOTE}${R}"); fi
  if (( SCAN_TRUNC )); then
    PG_LINES+=("${F_WARN}Output truncated at ${MAX_LINES} lines. Use Custom with -oA for the full record.${R}")
  fi
  if [[ -n $SCAN_RESULTS ]]; then
    mapfile -t colored < <(printf '%s\n' "$SCAN_RESULTS" | colorize)
    PG_LINES+=("${colored[@]}")
  else
    PG_LINES+=("(no output)")
  fi
  PG_TITLE="nmap RESULTS — ${TARGET}"
  hints "↑↓" "scroll" "/" "find" "S" "save" "R" "report" "N" "new" "Q" "menu"
  PG_HINTS=$HINTS
  PG_HOOK=results_hook
  PHASE=0
  pager
  PG_HOOK=""
}

# ── History ────────────────────────────────────────────────────────────────────
# [v2.2.0 NEW] newest first, persisted across sessions; keys 1-9 re-run that scan
# (through the confirm screen, with scope re-checked by validate_target).
history_hook(){
  local d=$1 idx
  if [[ ! $d =~ ^[1-9]$ ]]; then return 0; fi
  idx=$(( ${#HIST_TS[@]} - d ))
  if (( idx < 0 )); then return 0; fi
  if ! validate_target "${HIST_TGT[idx]}"; then
    status_bar "${F_DANGER}${REJECT_REASON}${R}  (press any key)"; read_key; return 0
  fi
  SCAN_PROFILE=${HIST_FLAGS[idx]}
  PHASE=13
  return 1
}

screen_history(){
  local i line c rank=0
  PG_LINES=()
  if (( ${#HIST_TS[@]} == 0 )); then
    PG_LINES+=("" "  ${F_MUTED}No scans yet.${R}")
  else
    PG_LINES+=("  ${F_HEAD}${B}$(printf '%-3s %-19s  %-9s  %s' '#' Time Result Command)${R}" "")
    for (( i=${#HIST_TS[@]}-1; i>=0; i-- )); do
      rank=$(( rank + 1 ))
      c=$F_GOOD
      case ${HIST_NOTE[i]} in ok) c=$F_GOOD;; cancelled) c=$F_WARN;; *) c=$F_DANGER;; esac
      printf -v line '  %s%-3s%s %s%-19s%s  %s%-9s%s  %s%s%s' \
        "$F_KEY" "$(( rank <= 9 ? rank : 0 ))" "$R" "$F_MUTED" "${HIST_TS[i]}" "$R" "$c" "${HIST_NOTE[i]}" "$R" "$F_TXT" "${HIST_CMD[i]}" "$R"
      if (( rank > 9 )); then line=${line/${F_KEY}0  /${F_KEY}-  }; fi
      PG_LINES+=("$line")
    done
  fi
  PG_TITLE="SCAN HISTORY (newest first)"
  hints "↑↓" "scroll" "/" "find" "1-9" "re-run" "Q" "back"
  PG_HINTS=$HINTS
  PG_HOOK=history_hook
  PHASE=0
  pager
  PG_HOOK=""
}

# ── Methodology guide ──────────────────────────────────────────────────────────
mh(){ PG_LINES+=("${F_HEAD}${B}━━ $1 ━━${R}" ""); }
mi(){ PG_LINES+=("  ${F_TITLE}•${R} $1"); }
mn(){ PG_LINES+=("    ${F_MUTED}$1${R}"); }
mb(){ PG_LINES+=(""); }

screen_methodology(){
  PG_LINES=()
  mh "PHASE 1 — PASSIVE RECON  (no packets to target)"
  mi "OSINT: WHOIS, DNS records, Shodan, Censys, certificates (crt.sh)"
  mi "Enumerate subdomains via subfinder / amass before touching the wire"
  mi "Map ASN, IP ranges, BGP peers - know the address space"
  mn "Goal: understand the attack surface without alerting defenders"
  mb
  mh "PHASE 2 — HOST DISCOVERY  (nmap -sn)"
  mi "Ping sweep CIDR: nmap -sn 192.168.1.0/24"
  mi "ARP scan on LAN (fast, hard to filter): nmap -sn -PR"
  mi "ICMP echo + timestamp + netmask: nmap -sn -PE -PP -PM"
  mi "TCP/UDP probes for firewalled hosts: nmap -sn -PS80,443 -PA80 -PU53"
  mn "Output: list of live hosts -> feed into phase 3"
  mb
  mh "PHASE 3 — PORT SCANNING  (identify listening services)"
  mi "SYN scan (fast, less logged): nmap -sS --top-ports 1000 --open"
  mi "Full port sweep: nmap -sS -p- -T4  (takes time)"
  mi "UDP top-20 (SNMP, DNS, TFTP): nmap -sU --top-ports 20"
  mi "Firewall evasion: fragment packets (-f), decoys (-D), slow (-T1)"
  mn "Common mistakes: skipping UDP; not scanning all 65535 ports on key hosts"
  mb
  mh "PHASE 4 — SERVICE & VERSION ENUMERATION"
  mi "Banner grab: nmap -sV --version-intensity 5"
  mi "Default scripts for extra intel: nmap -sC"
  mi "Combined: nmap -sS -sV -sC -O  (the classic 'full enum' sweep)"
  mi "Identifies: web servers, SSH versions, SMB dialects, RDP, databases"
  mn "Version info feeds vulnerability matching in phase 5"
  mb
  mh "PHASE 5 — OS DETECTION & VULNERABILITY MAPPING"
  mi "OS fingerprint: nmap -O --osscan-guess  (needs root)"
  mi "NSE vuln scripts: nmap -sV --script vuln"
  mi "Targeted scripts: --script smb-vuln-ms17-010 (EternalBlue)"
  mi "Cross-ref versions with NVD / ExploitDB / Metasploit module list"
  mn "NEVER run exploit code on systems without explicit written permission"
  mb
  mh "PHASE 6 — DOCUMENTATION & REPORTING"
  mi "Save all output: nmap -oA scan_\$(date +%Y%m%d)  (XML + grepable + normal)"
  mi "Map topology: hosts -> ports -> services -> risk rating"
  mi "Produce findings report: severity, CVSS, remediation steps"
  mn "Retain proof of authorisation throughout - scope creep = crime"
  PG_TITLE="ETHICAL HACKER METHODOLOGY — NETWORK MAPPING"
  hints "↑↓/PgUp/PgDn" "scroll" "g/G" "top/end" "Q" "back"
  PG_HINTS=$HINTS
  PG_HOOK=""
  PHASE=0
  pager
}

# ── About / legal ──────────────────────────────────────────────────────────────
screen_about(){
  local bw=72 bcol brow r c
  begin_screen
  bcol=$(( (COLS - bw) / 2 ))
  brow=2; if (( ROWS >= 28 )); then brow=4; fi
  draw_box "$brow" "$bcol" 20 "$bw" " ABOUT & LEGAL NOTICE "
  r=$(( brow + 2 )); c=$(( bcol + 4 ))
  about_p(){ cur_goto "$r" "$c"; r=$(( r + 1 )); printf '%s' "$1"; }
  about_p "${F_DANGER}${B}⚠  IMPORTANT — READ BEFORE SCANNING${R}"
  about_p ""
  about_p "${F_TXT}This tool is a front-end for nmap, the Network Mapper.${R}"
  about_p "${F_TXT}nmap is free software by Insecure.Com LLC (Gordon Lyon).${R}"
  about_p ""
  about_p "${F_WARN}${B}AUTHORISATION${R}"
  about_p "${F_TXT}Scanning networks without written permission is illegal in most${R}"
  about_p "${F_TXT}jurisdictions (UK CMA 1990, US CFAA, EU Directive 2013/40/EU).${R}"
  about_p "${F_TXT}Only use this tool on:${R}"
  about_p "  ${F_GOOD}✓${R} ${F_TXT}Your own infrastructure${R}"
  about_p "  ${F_GOOD}✓${R} ${F_TXT}Networks with explicit written authorisation${R}"
  about_p "  ${F_GOOD}✓${R} ${F_TXT}Lab environments (VMs, Hack The Box, TryHackMe)${R}"
  about_p "  ${F_GOOD}✓${R} ${F_TXT}scanme.nmap.org (Nmap's official free test target)${R}"
  about_p ""
  about_p "${F_MUTED}${SCRIPT_FILE} (v${SCRIPT_VERSION}) - pure bash, no Python/dialog/tput.${R}"
  about_p "${F_MUTED}bash ${BASH_VERSION}  |  nmap ${NMAP_VERSION}  |  $( (( EUID == 0 )) && echo root || echo unprivileged )${R}"
  unset -f about_p
  hints "Any key" "back"
  status_bar "$HINTS"
  read_key
  PHASE=0
}

# =============================================================================
# SIGNALS / LIFECYCLE
# =============================================================================
cleanup(){
  if (( CLEANUP_DONE )); then return 0; fi
  CLEANUP_DONE=1
  # Kill an in-flight scan (never leave an orphaned nmap) and drop its temp file.
  if [[ -n $SCAN_PID ]] && kill -0 "$SCAN_PID" 2>/dev/null; then
    kill "$SCAN_PID" 2>/dev/null || true
    wait "$SCAN_PID" 2>/dev/null || true
  fi
  if [[ -n $SCAN_TMPFILE && -f $SCAN_TMPFILE ]]; then rm -f "$SCAN_TMPFILE"; fi
  if (( TTY_ACTIVE )); then
    clear_screen
    term_restore
    printf '%sGoodbye.%s\n' "$F_TITLE$B" "$R"
  fi
}

# [v2.1.0 NEW] live resize: the trap runs promptly because read_key polls.
on_winch(){ NEED_REDRAW=1; get_size; }

# [v2.1.0 FIX] Ctrl+Z used to stop the process with the cursor still hidden,
# raw tty modes and the alternate screen active.  Restore the terminal, stop
# ourselves, and re-enter the TUI (and redraw) when resumed with `fg`.
on_tstp(){
  term_restore
  kill -STOP $$
  tty_setup
  get_size
  NEED_REDRAW=1
}

# =============================================================================
# MAIN LOOP
# =============================================================================
main(){
  # [v2.2.0 FIX] process-wide umask: files nmap writes for Custom -oN/-oX/-oA flags
  # are private too (before, only our own saves were).
  umask 077
  # [v2.2.0 NEW] scope fails closed: a set-but-unreadable file aborts startup.
  if ! scope_load; then
    echo "NMAP_TUI_SCOPE is set but '${SCOPE_FILE}' is not a readable file - refusing to start." >&2
    exit 1
  fi
  hist_load
  OLD_STTY=$(stty -g 2>/dev/null || true)
  NMAP_VERSION=$(nmap --version 2>/dev/null | awk 'NR==1{print $3}')
  if [[ -z $NMAP_VERSION ]]; then NMAP_VERSION="unknown"; fi

  # EXIT is separate from INT/TERM/HUP: a trap alone does not terminate bash,
  # so the signal handlers must exit explicitly (the v2.0.0 Ctrl+C bug).
  trap cleanup EXIT
  trap 'cleanup; exit 130' INT
  trap 'cleanup; exit 143' TERM
  trap 'cleanup; exit 129' HUP
  trap on_winch WINCH
  trap on_tstp TSTP

  get_size
  tty_setup
  TTY_ACTIVE=1

  while true; do
    ensure_min_terminal_size
    if (( PHASE != LAST_PHASE )); then FULL_CLEAR=1; LAST_PHASE=$PHASE; fi

    case $PHASE in
      0)  # Main menu
        screen_menu
        read_key
        case $KEY in
          "${ESC}[A"|k) if (( MENU_SEL > 1 )); then MENU_SEL=$(( MENU_SEL - 1 )); fi;;
          "${ESC}[B"|j) if (( MENU_SEL < 5 )); then MENU_SEL=$(( MENU_SEL + 1 )); fi;;
          ENTER)
            case $MENU_SEL in
              1) PHASE=1;; 2) PHASE=10;; 3) PHASE=11;; 4) PHASE=12;; 5) exit 0;;
            esac;;
          1) PHASE=1;; 2) PHASE=10;; 3) PHASE=11;; 4) PHASE=12;;
          q|Q) exit 0;;
        esac;;

      1)  # Target input
        screen_target
        if [[ -n $TARGET && $PHASE == 1 ]]; then PHASE=2; else PHASE=0; fi;;

      2)  # Profile selection
        screen_profile
        read_key
        case $KEY in
          "${ESC}[A"|k) if (( PROFILE_SEL > 1 )); then PROFILE_SEL=$(( PROFILE_SEL - 1 )); fi;;
          "${ESC}[B"|j) if (( PROFILE_SEL < NPROFILES )); then PROFILE_SEL=$(( PROFILE_SEL + 1 )); fi;;
          ENTER)        launch_profile "$PROFILE_SEL" || true;;
          [1-9])        launch_profile "$KEY" || true;;
          0)            launch_profile 10 || true;;       # [v2.1.0 FIX] profile 10 had no quick key
          b|B|ESC)      PHASE=1;;
          q|Q)          PHASE=0;;
        esac;;

      3)  # Scanning
        screen_scanning
        if [[ $PHASE == 3 ]]; then PHASE=4; fi;;

      4)  screen_results;;
      13) screen_confirm;;
      10) screen_history;;
      11) screen_methodology;;
      12) screen_about;;
      *)  PHASE=0;;
    esac
  done
}

main "$@"
