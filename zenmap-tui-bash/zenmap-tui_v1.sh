#!/usr/bin/env bash
# zenmap-tui.sh — Pure-bash Zenmap-style nmap TUI. No dialog, no tput, no external TUI libs.
# Requires: bash 4+, nmap. Optional: awk, sed (preflight offers to install).
#
# SECURITY / CORRECTNESS NOTES (see audit):
#   - All variable expansions in printf format strings avoided (BUG-07 fix).
#   - nmap invoked with an argv array, never word-split (BUG-06 fix).
#   - No `eval` anywhere; installer commands run as argv arrays (BUG-17 fix).
#   - Cross-process state (scan running / elapsed / done) communicated via
#     sentinel files, not shell variables, because the scanner runs in a
#     background subshell and cannot mutate the parent's variables (BUG-01/02/11 fix).
#   - Single cleanup path: one function, one trap registration (BUG-04/05 fix).

set -u   # catch unset-variable typos; NOT -e (arithmetic (( )) returning 0 must not kill the script)
umask 077   # scan output may reveal internal network topology — keep temp files private

# ── ANSI escape helpers (no tput; works with unset $TERM) ────────────────────
ESC=$'\033'
CSI="${ESC}["

cur_hide()  { printf '%s' "${CSI}?25l"; }
cur_show()  { printf '%s' "${CSI}?25h"; }
cur_move()  { printf '%s' "${CSI}${1};${2}H"; }         # row col (1-based)
screen_alt()   { printf '%s' "${CSI}?1049h"; }
screen_main()  { printf '%s' "${CSI}?1049l"; }
screen_clear() { printf '%s' "${CSI}2J${CSI}H"; }
line_clear_to_eol() { printf '%s' "${CSI}K"; }           # erase from cursor to end of line

RST="${CSI}0m"; BOLD="${CSI}1m"; DIM="${CSI}2m"
RED="${CSI}31m"; GREEN="${CSI}32m"; YELLOW="${CSI}33m"
MAGENTA="${CSI}35m"; CYAN="${CSI}36m"; WHITE="${CSI}37m"
BG_DARK="${CSI}40m"; BG_ROW="${CSI}48;5;234m"

# ── terminal size, with sane minimums (BUG-15 fix) ────────────────────────────
MIN_ROWS=12
MIN_COLS=50

get_term_size() {
  local sz
  if sz=$(stty size </dev/tty 2>/dev/null) && [[ -n "$sz" ]]; then
    ROWS=${sz%% *}
    COLS=${sz##* }
  else
    ROWS=40; COLS=120
  fi
  (( ROWS < MIN_ROWS )) && ROWS=$MIN_ROWS
  (( COLS < MIN_COLS )) && COLS=$MIN_COLS
}

# ── layout ────────────────────────────────────────────────────────────────────
SIDEBAR_W=26
MENU_ROW=4
TAB_ROW=5
DIVIDER_ROW=6
CONTENT_TOP=7
STATUS_ROW=0
CONTENT_H=0
CONTENT_LEFT=$(( SIDEBAR_W + 2 ))
CONTENT_W=0

recalc_layout() {
  get_term_size
  STATUS_ROW=$ROWS
  CONTENT_H=$(( ROWS - CONTENT_TOP - 1 ))
  CONTENT_W=$(( COLS - CONTENT_LEFT ))
  (( CONTENT_H < 1 )) && CONTENT_H=1     # guard against negative width/height (BUG-15)
  (( CONTENT_W < 1 )) && CONTENT_W=1
}

# ── state ─────────────────────────────────────────────────────────────────────
TARGET="192.168.1.0/24"
PROFILE="regular"
ACTIVE_TAB=0            # 0=Output 1=Ports 2=Details 3=Topology 4=Info
SELECTED_HOST=0
SCAN_PID=""
ELAPSED=0
SCROLL_OUT=0
SCROLL_PORTS=0
STTY_SAVE=""

# Profiles stored as arrays, never as a single word-split string (BUG-06 fix)
declare -A PROFILE_LABELS=(
  [quick]="Quick Scan"    [regular]="Regular"     [intense]="Intense Scan"
  [ping]="Ping Scan"      [udp]="UDP Scan"        [os]="OS Detection"
)
declare -A PROFILE_ARGS_STR=(     # human-readable, shown in UI only — never executed directly
  [quick]="nmap -T4 -F"           [regular]="nmap -sV -T4"   [intense]="nmap -T4 -A -v"
  [ping]="nmap -sn"               [udp]="nmap -sU -T4"       [os]="nmap -O"
)
get_profile_argv() {   # populate global array PROFILE_ARGV with actual argv (no word-splitting of target)
  case "$1" in
    quick)   PROFILE_ARGV=(-T4 -F) ;;
    regular) PROFILE_ARGV=(-sV -T4) ;;
    intense) PROFILE_ARGV=(-T4 -A -v) ;;
    ping)    PROFILE_ARGV=(-sn) ;;
    udp)     PROFILE_ARGV=(-sU -T4) ;;
    os)      PROFILE_ARGV=(-O) ;;
    *)       PROFILE_ARGV=(-sV -T4) ;;
  esac
}

# ── temp workspace (created with restrictive perms via umask above) ──────────
TMPD=$(mktemp -d) || { echo "FATAL: mktemp failed" >&2; exit 1; }
OUT_FILE="$TMPD/output.txt"
HOSTS_FILE="$TMPD/hosts.txt"
PORTS_FILE="$TMPD/ports.txt"
SCANNING_FLAG="$TMPD/scanning.flag"    # existence = scan in progress (cross-process signal, BUG-01 fix)
ELAPSED_FILE="$TMPD/elapsed.txt"       # scanner subshell writes elapsed seconds here
: > "$OUT_FILE"; : > "$HOSTS_FILE"; : > "$PORTS_FILE"; printf '0' > "$ELAPSED_FILE"

# ── single, idempotent cleanup path (BUG-04 / BUG-05 fix) ────────────────────
_CLEANED_UP=0
_cleanup() {
  (( _CLEANED_UP )) && return
  _CLEANED_UP=1
  # kill scanner's whole process group, not just the immediate child (BUG-16 fix)
  if [[ -n "$SCAN_PID" ]]; then
    kill -- "-$SCAN_PID" 2>/dev/null || kill "$SCAN_PID" 2>/dev/null || true
  fi
  [[ -n "$STTY_SAVE" ]] && stty "$STTY_SAVE" </dev/tty 2>/dev/null || true
  cur_show
  screen_main
  printf '%s\n' "$RST"
  rm -rf -- "$TMPD"
  exit 0
}
trap _cleanup EXIT INT TERM HUP

# ── string helpers ────────────────────────────────────────────────────────────
trunc() {                          # trunc str maxlen  → never over-read multibyte-unsafe but adequate for ASCII UI chrome
  local s=$1 n=$2
  (( ${#s} > n )) && printf '%s' "${s:0:$n}" || printf '%s' "$s"
}
pad() { printf '%-*s' "$2" "$1"; }  # pad str width

# clear_eol replaces the old ad-hoc rpad() arithmetic (BUG-18 fix) — cheaper and always correct
clear_eol() { line_clear_to_eol; }

# repeat_char without forking `tr` (BUG-19 fix) — pure bash brace-free implementation
repeat_char() {                    # repeat_char char n
  local c=$1 n=$2 out=""
  (( n <= 0 )) && return
  printf -v out '%*s' "$n" ''
  printf '%s' "${out// /$c}"
}

hline() { cur_move "$1" "$2"; printf '%s%s%s' "$DIM" "$(repeat_char "${4:-─}" "$3")" "$RST"; }
vline_col() {
  local c=$1 r
  for (( r=$2; r<=$3; r++ )); do cur_move "$r" "$c"; printf '%s│%s' "$DIM" "$RST"; done
}

# ── title bar ─────────────────────────────────────────────────────────────────
draw_title() {
  cur_move 1 1
  printf '%s%s%s ▐▌ ZENMAP TUI%s%s%s  Network Exploration & Security Scanner%s' \
    "$BG_DARK" "$BOLD" "$GREEN" "$RST" "$BG_DARK" "$DIM" "$RST"
  clear_eol

  cur_move 2 1
  local scanning=0
  [[ -e "$SCANNING_FLAG" ]] && scanning=1
  local elapsed; elapsed=$(<"$ELAPSED_FILE")
  # printf "%s" for every dynamic field — never interpolate into the format string (BUG-07 fix)
  printf ' Target: %s%s%s' "$CYAN" "$(trunc "$TARGET" 22)" "$RST"
  printf '  Profile: %s%s%s' "$MAGENTA" "$(trunc "${PROFILE_LABELS[$PROFILE]}" 14)" "$RST"
  if (( scanning )); then
    printf '  %s● SCANNING  %ss%s' "$YELLOW" "$elapsed" "$RST"
  else
    printf '  %s○ idle%s' "$DIM" "$RST"
  fi
  clear_eol

  cur_move 3 1
  printf '%s%s%s' "$DIM" "$(repeat_char '─' "$COLS")" "$RST"
}

draw_menu() {
  cur_move "$MENU_ROW" 1
  printf '%s [S]%sScan   [T]%sTarget   [P]%sProfile   ←→%sTabs   ↑↓%sScroll   [Q]%sQuit' \
    "$DIM" "$RST$DIM" "$RST$DIM" "$RST$DIM" "$RST$DIM" "$RST$DIM" "$RST"
  clear_eol
}

# ── sidebar ───────────────────────────────────────────────────────────────────
draw_sidebar() {
  cur_move "$TAB_ROW" 1
  local cnt=0
  [[ -s "$HOSTS_FILE" ]] && cnt=$(wc -l < "$HOSTS_FILE")
  printf '%s%s HOSTS%s%s (%s)%s' "$BOLD" "$DIM" "$RST" "$DIM" "$cnt" "$RST"
  clear_eol

  hline $(( TAB_ROW + 1 )) 1 "$SIDEBAR_W" '─'

  local r=$(( TAB_ROW + 2 )) bot=$(( STATUS_ROW - 1 )) idx=0
  local -a hosts=()
  [[ -s "$HOSTS_FILE" ]] && mapfile -t hosts < "$HOSTS_FILE"

  if (( ${#hosts[@]} == 0 )); then
    cur_move "$r" 1; printf '%s no hosts yet%s' "$DIM" "$RST"; clear_eol
    (( r++ ))
  else
    local entry ip status open_count hostname os mac
    for entry in "${hosts[@]}"; do
      (( r > bot )) && break
      IFS='|' read -r ip status open_count hostname os mac <<< "$entry"
      cur_move "$r" 1
      local icon color
      if [[ "$status" == "up" ]]; then icon='◉'; color=$GREEN; else icon='○'; color=$DIM; fi
      local label; label=$(trunc "${hostname:-$ip}" $(( SIDEBAR_W - 4 )))
      if (( idx == SELECTED_HOST && ACTIVE_TAB == 2 )); then
        printf '%s%s▶%s%s %s%s' "$BG_ROW" "$CYAN" "$icon" "$RST$BG_ROW$CYAN" "$(pad "$label" $(( SIDEBAR_W - 3 )))" "$RST"
      else
        printf ' %s%s%s %s' "$color" "$icon" "$RST" "$(pad "$label" $(( SIDEBAR_W - 3 )))"
      fi
      clear_eol
      (( r++ )); (( idx++ ))
    done
  fi

  while (( r <= bot )); do cur_move "$r" 1; clear_eol; (( r++ )); done
  vline_col $(( SIDEBAR_W + 1 )) "$TAB_ROW" $(( STATUS_ROW - 1 ))
}

# ── tabs ──────────────────────────────────────────────────────────────────────
TABS=("Nmap Output" "Ports" "Host Details" "Topology" "Scan Info")

draw_tabs() {
  cur_move "$TAB_ROW" "$CONTENT_LEFT"
  local i=0 tab
  for tab in "${TABS[@]}"; do
    if (( i == ACTIVE_TAB )); then
      printf '%s%s[%s]%s ' "$BOLD" "$CYAN" "$tab" "$RST"
    else
      printf '%s %s %s' "$DIM" "$tab" "$RST"
    fi
    (( i++ ))
  done
  clear_eol
  hline "$DIVIDER_ROW" "$CONTENT_LEFT" "$CONTENT_W" '─'
}

# ── status bar ────────────────────────────────────────────────────────────────
draw_statusbar() {
  local up=0 op=0
  # Field-exact counts via awk instead of substring grep (BUG-20 fix)
  [[ -s "$HOSTS_FILE" ]] && up=$(awk -F'|' '$2=="up"{c++} END{print c+0}' "$HOSTS_FILE")
  [[ -s "$PORTS_FILE" ]] && op=$(awk -F'|' '$3=="open"{c++} END{print c+0}' "$PORTS_FILE")

  cur_move "$STATUS_ROW" 1
  printf '%s─%s Hosts up: %s%s%s  Open ports: %s%s%s  Tab:%s←→%s  Scroll:%s↑↓%s' \
    "$DIM" "$RST" "$GREEN" "$up" "$RST" "$CYAN" "$op" "$RST" "$DIM" "$RST" "$DIM" "$RST"
  clear_eol
}

# ── pane: nmap output ─────────────────────────────────────────────────────────
draw_output_pane() {
  local -a lines=()
  [[ -s "$OUT_FILE" ]] && mapfile -t lines < "$OUT_FILE"
  local total=${#lines[@]} visible=$CONTENT_H
  local max_scroll=$(( total > visible ? total - visible : 0 ))
  (( SCROLL_OUT > max_scroll )) && SCROLL_OUT=$max_scroll   # clamp (BUG-13 fix)
  local start=$(( total - visible - SCROLL_OUT ))
  (( start < 0 )) && start=0

  local r=$CONTENT_TOP end_r=$(( CONTENT_TOP + visible - 1 )) i ln out
  for (( i=start; i<start+visible && i<total; i++ )); do
    cur_move "$r" "$CONTENT_LEFT"
    ln="${lines[$i]}"
    out=$(trunc "$ln" "$CONTENT_W")
    local color=$DIM
    case "$ln" in
      "Nmap scan report"*) color="${BOLD}${WHITE}" ;;
      *"Nmap done"*)        color="${BOLD}${GREEN}" ;;
      *" open "*)           color=$GREEN ;;
      *" filtered "*)       color=$YELLOW ;;
      *" closed "*)         color=$RED ;;
      "Starting:"*|*"latency"*) color=$CYAN ;;
      *"OS:"*|*"MAC"*)      color=$MAGENTA ;;
    esac
    printf '%s%s%s' "$color" "$(pad "$out" "$CONTENT_W")" "$RST"
    (( r++ ))
  done
  while (( r <= end_r )); do cur_move "$r" "$CONTENT_LEFT"; clear_eol; (( r++ )); done

  if (( total > visible )); then
    cur_move "$CONTENT_TOP" $(( COLS - 1 )); printf '%s↑%s' "$DIM" "$RST"
    cur_move $(( CONTENT_TOP + visible - 1 )) $(( COLS - 1 )); printf '%s↓%s' "$DIM" "$RST"
  fi
}

# ── pane: ports table ─────────────────────────────────────────────────────────
draw_ports_pane() {
  local hdr_r=$CONTENT_TOP
  cur_move "$hdr_r" "$CONTENT_LEFT"
  printf '%s%s%s%s%s%s%s' "$BOLD$DIM" "$(pad HOST 18)" "$(pad PORT 8)" "$(pad STATE 11)" \
    "$(pad PROTO 7)" "$(pad SERVICE 14)" "$RST"
  clear_eol
  hline $(( hdr_r + 1 )) "$CONTENT_LEFT" "$CONTENT_W" '─'

  local -a lines=()
  [[ -s "$PORTS_FILE" ]] && mapfile -t lines < "$PORTS_FILE"
  local total=${#lines[@]} visible=$(( CONTENT_H - 2 ))
  (( visible < 1 )) && visible=1
  local max_scroll=$(( total > visible ? total - visible : 0 ))
  (( SCROLL_PORTS > max_scroll )) && SCROLL_PORTS=$max_scroll
  (( SCROLL_PORTS < 0 )) && SCROLL_PORTS=0
  local start=$SCROLL_PORTS

  local r=$(( hdr_r + 2 )) end_r=$(( CONTENT_TOP + CONTENT_H - 1 )) i
  if (( total == 0 )); then
    cur_move "$r" "$CONTENT_LEFT"; printf '%sNo port data — run a scan.%s' "$DIM" "$RST"; clear_eol
    (( r++ ))
  else
    local host port state proto service version sc
    for (( i=start; i<start+visible && i<total; i++ )); do
      IFS='|' read -r host port state proto service version <<< "${lines[$i]}"
      cur_move "$r" "$CONTENT_LEFT"
      case "$state" in
        open)     sc=$GREEN ;;
        filtered) sc=$YELLOW ;;
        *)        sc=$RED ;;
      esac
      printf '%s%s%s%s%s%s%s%s%s%s%s%s' \
        "$DIM"     "$(pad "$(trunc "$host" 17)" 18)" "$RST" \
        "$CYAN"    "$(pad "$port" 8)"                "$RST" \
        "$sc"      "$(pad "$state" 11)"               "$RST" \
        "$DIM"     "$(pad "$proto" 7)"                "$RST"
      printf '%s%s%s%s%s%s' \
        "$MAGENTA" "$(pad "$service" 14)" "$RST" \
        "$DIM"     "$(trunc "$version" $(( CONTENT_W - 58 > 0 ? CONTENT_W - 58 : 10 )))" "$RST"
      clear_eol
      (( r++ ))
    done
  fi
  while (( r <= end_r )); do cur_move "$r" "$CONTENT_LEFT"; clear_eol; (( r++ )); done
}

# ── pane: host details ────────────────────────────────────────────────────────
kv_line() {   # kv_line row label value_with_color  → returns nothing, caller advances row
  cur_move "$1" "$CONTENT_LEFT"
  printf '%s%s%s%b' "$DIM" "$(pad "$2" 16)" "$RST" "$3"
  clear_eol
}

draw_details_pane() {
  local r=$CONTENT_TOP end_r=$(( CONTENT_TOP + CONTENT_H - 1 ))

  if [[ ! -s "$HOSTS_FILE" ]]; then
    cur_move "$r" "$CONTENT_LEFT"; printf '%sNo hosts — run a scan first.%s' "$DIM" "$RST"; clear_eol
    return
  fi

  local -a hosts=(); mapfile -t hosts < "$HOSTS_FILE"
  if (( SELECTED_HOST >= ${#hosts[@]} )); then
    cur_move "$r" "$CONTENT_LEFT"; printf '%sNo host selected. Use ↑↓ in this tab.%s' "$DIM" "$RST"; clear_eol
    return
  fi

  local ip status open_count hostname os mac
  IFS='|' read -r ip status open_count hostname os mac <<< "${hosts[$SELECTED_HOST]}"

  cur_move "$r" "$CONTENT_LEFT"
  printf '%s%sHost: %s%s' "$BOLD" "$CYAN" "$ip" "$RST"; clear_eol; (( r++ ))
  hline "$r" "$CONTENT_LEFT" "$CONTENT_W" '─'; (( r++ ))

  kv_line "$r" "IP Address:" "${CYAN}${ip}${RST}"; (( r++ ))
  kv_line "$r" "Hostname:"   "${WHITE}${hostname:-N/A}${RST}"; (( r++ ))
  local status_disp; [[ "$status" == up ]] && status_disp="${GREEN}up${RST}" || status_disp="${RED}down${RST}"
  kv_line "$r" "Status:" "$status_disp"; (( r++ ))
  kv_line "$r" "OS:"  "${MAGENTA}${os:-Unknown}${RST}"; (( r++ ))
  kv_line "$r" "MAC:" "${DIM}${mac:-N/A}${RST}"; (( r++ ))
  kv_line "$r" "Open ports:" "${GREEN}${open_count}${RST}"; (( r++ ))

  (( r++ ))
  if (( r <= end_r )); then
    cur_move "$r" "$CONTENT_LEFT"; printf '%s%sOpen Services:%s' "$BOLD" "$DIM" "$RST"; clear_eol; (( r++ ))
  fi
  if (( r <= end_r )); then hline "$r" "$CONTENT_LEFT" "$CONTENT_W" '─'; (( r++ )); fi

  if [[ -s "$PORTS_FILE" ]]; then
    local h port state proto service version
    while IFS='|' read -r h port state proto service version; do
      [[ "$h" == "$ip" && "$state" == "open" ]] || continue
      (( r > end_r )) && break
      cur_move "$r" "$CONTENT_LEFT"
      printf '%s%s%s%s%s%s%s%s%s' \
        "$CYAN" "$(pad "$port" 8)" "$RST" \
        "$MAGENTA" "$(pad "$service" 16)" "$RST" \
        "$DIM" "$(trunc "$version" $(( CONTENT_W - 26 > 0 ? CONTENT_W - 26 : 10 )))" "$RST"
      clear_eol
      (( r++ ))
    done < "$PORTS_FILE"
  fi

  while (( r <= end_r )); do cur_move "$r" "$CONTENT_LEFT"; clear_eol; (( r++ )); done
}

# ── pane: topology ────────────────────────────────────────────────────────────
draw_topology_pane() {
  local r=$CONTENT_TOP end_r=$(( CONTENT_TOP + CONTENT_H - 1 ))
  local ctr=$(( CONTENT_LEFT + CONTENT_W / 2 ))

  cur_move "$r" $(( ctr - 5 )); printf '%s%s[ GATEWAY ]%s' "$BOLD" "$GREEN" "$RST"; (( r++ ))
  cur_move "$r" "$ctr"; printf '%s│%s' "$DIM" "$RST"; (( r++ ))

  if [[ ! -s "$HOSTS_FILE" ]]; then
    cur_move "$r" "$CONTENT_LEFT"; printf '%sRun a scan to see topology.%s' "$DIM" "$RST"; clear_eol
    return
  fi

  local -a hosts=(); mapfile -t hosts < "$HOSTS_FILE"
  local count=${#hosts[@]} i=0 entry ip status open_count hostname os mac connector col icon
  for entry in "${hosts[@]}"; do
    (( r > end_r - 1 )) && break
    IFS='|' read -r ip status open_count hostname os mac <<< "$entry"
    cur_move "$r" "$ctr"
    if (( i == count - 1 )); then connector='└──'; else connector='├──'; fi
    if [[ "$status" == up ]]; then icon='◉'; col=$GREEN; else icon='○'; col=$DIM; fi
    printf '%s%s%s%s%s %s%s%s%s%s' \
      "$DIM" "$connector" "$RST" "$col" "$icon" "$RST" \
      "$CYAN" "$(pad "$ip" 16)" "$RST" "$(pad "${hostname:-}" 16)"
    if [[ "$status" == up ]]; then printf '%s%s open%s' "$GREEN" "$open_count" "$RST"
    else printf '%sdown%s' "$RED" "$RST"; fi
    clear_eol
    (( r++ )); (( i++ ))
  done
  while (( r <= end_r )); do cur_move "$r" "$CONTENT_LEFT"; clear_eol; (( r++ )); done
}

# ── pane: scan info ───────────────────────────────────────────────────────────
draw_scaninfo_pane() {
  local r=$CONTENT_TOP end_r=$(( CONTENT_TOP + CONTENT_H - 1 ))
  cur_move "$r" "$CONTENT_LEFT"; printf '%sScan Information%s' "$BOLD" "$RST"; clear_eol; (( r++ ))
  hline "$r" "$CONTENT_LEFT" "$CONTENT_W" '─'; (( r++ ))

  local elapsed; elapsed=$(<"$ELAPSED_FILE")
  get_profile_argv "$PROFILE"
  local cmd_display="nmap ${PROFILE_ARGV[*]} $TARGET"

  kv_line "$r" "Target:"  "${CYAN}${TARGET}${RST}"; (( r++ ))
  kv_line "$r" "Profile:" "${MAGENTA}${PROFILE_LABELS[$PROFILE]}${RST}"; (( r++ ))
  kv_line "$r" "Command:" "${YELLOW}${cmd_display}${RST}"; (( r++ ))
  kv_line "$r" "Elapsed:" "${GREEN}${elapsed}s${RST}"; (( r++ ))
  (( r++ ))

  if [[ -s "$HOSTS_FILE" ]]; then
    local up total
    up=$(awk -F'|' '$2=="up"{c++} END{print c+0}' "$HOSTS_FILE")
    total=$(wc -l < "$HOSTS_FILE")
    kv_line "$r" "Hosts up:"    "${GREEN}${up}${RST}"; (( r++ ))
    kv_line "$r" "Hosts down:"  "${RED}$(( total - up ))${RST}"; (( r++ ))
    kv_line "$r" "Total hosts:" "${CYAN}${total}${RST}"; (( r++ ))
  fi
  (( r++ ))

  if [[ -s "$PORTS_FILE" ]]; then
    local op fp cp
    op=$(awk -F'|' '$3=="open"{c++} END{print c+0}'     "$PORTS_FILE")
    fp=$(awk -F'|' '$3=="filtered"{c++} END{print c+0}' "$PORTS_FILE")
    cp=$(awk -F'|' '$3=="closed"{c++} END{print c+0}'   "$PORTS_FILE")
    kv_line "$r" "Open ports:"     "${GREEN}${op}${RST}"; (( r++ ))
    kv_line "$r" "Filtered ports:" "${YELLOW}${fp}${RST}"; (( r++ ))
    kv_line "$r" "Closed ports:"   "${RED}${cp}${RST}"; (( r++ ))
  fi

  while (( r <= end_r )); do cur_move "$r" "$CONTENT_LEFT"; clear_eol; (( r++ )); done
}

# ── full redraw ───────────────────────────────────────────────────────────────
redraw() {
  recalc_layout
  draw_title
  draw_menu
  draw_sidebar
  draw_tabs
  draw_statusbar
  case "$ACTIVE_TAB" in
    0) draw_output_pane ;;
    1) draw_ports_pane ;;
    2) draw_details_pane ;;
    3) draw_topology_pane ;;
    4) draw_scaninfo_pane ;;
  esac
}

# ── scanner (background subshell) ─────────────────────────────────────────────
# Runs in `run_scan &`. Cannot mutate parent variables — all state communicated
# via files in $TMPD (BUG-01/02/11 fix). current_ip is local to this subshell,
# which is fine because we never need it outside.
run_scan() {
  : > "$OUT_FILE"; : > "$HOSTS_FILE"; : > "$PORTS_FILE"
  : > "$ELAPSED_FILE"
  touch -- "$SCANNING_FLAG"

  if ! command -v nmap &>/dev/null; then
    printf 'ERROR: nmap not found. Please install nmap.\n' >> "$OUT_FILE"
    rm -f -- "$SCANNING_FLAG"
    return
  fi

  get_profile_argv "$PROFILE"
  local start_ts=$SECONDS current_ip=""

  {
    printf 'Starting: nmap %s %s\n\n' "${PROFILE_ARGV[*]}" "$TARGET"
  } >> "$OUT_FILE"

  # Background a lightweight ticker so ELAPSED_FILE updates even on slow scans;
  # avoids relying on line-arrival timing to update the clock.
  ( while [[ -e "$SCANNING_FLAG" ]]; do
      printf '%s' "$(( SECONDS - start_ts ))" > "$ELAPSED_FILE"
      sleep 1
    done ) &
  local ticker_pid=$!

  # Process substitution instead of a trailing pipe — the while loop then runs
  # in *this* subshell's own scope rather than a further nested subshell, so
  # `current_ip` updates are visible for the whole scan (BUG-11 fix).
  while IFS= read -r line; do
    printf '%s\n' "$line" >> "$OUT_FILE"

    if [[ "$line" == "Nmap scan report for "* ]]; then
      local raw=${line#Nmap scan report for }
      if [[ "$raw" =~ \(([0-9.]+)\)$ ]]; then
        current_ip=${BASH_REMATCH[1]}
        local hn=${raw%% (*}
        printf '%s|up|0|%s||\n' "$current_ip" "$hn" >> "$HOSTS_FILE"
      else
        current_ip=$raw
        printf '%s|up|0|%s||\n' "$current_ip" "$raw" >> "$HOSTS_FILE"
      fi
      continue
    fi

    if [[ "$line" == *"Host is up"* && -n "$current_ip" ]]; then
      continue   # status already recorded as "up" at discovery time
    fi

    if [[ "$line" == *"Host seems down"* && -n "$current_ip" ]]; then
      # Correct field-targeted update via awk (BUG-03 fix — old sed was structurally broken)
      awk -F'|' -v ip="$current_ip" 'BEGIN{OFS="|"} $1==ip{$2="down"} {print}' \
        "$HOSTS_FILE" > "$TMPD/hosts.tmp" && mv -- "$TMPD/hosts.tmp" "$HOSTS_FILE"
      continue
    fi

    if [[ "$line" =~ ^OS:\ (.+) ]] && [[ -n "$current_ip" ]]; then
      awk -F'|' -v ip="$current_ip" -v os="${BASH_REMATCH[1]}" \
        'BEGIN{OFS="|"} $1==ip{$5=os} {print}' "$HOSTS_FILE" > "$TMPD/hosts.tmp" \
        && mv -- "$TMPD/hosts.tmp" "$HOSTS_FILE"
      continue
    fi

    if [[ "$line" =~ ^MAC\ Address:\ ([0-9A-Fa-f:]+) ]] && [[ -n "$current_ip" ]]; then
      awk -F'|' -v ip="$current_ip" -v mac="${BASH_REMATCH[1]}" \
        'BEGIN{OFS="|"} $1==ip{$6=mac} {print}' "$HOSTS_FILE" > "$TMPD/hosts.tmp" \
        && mv -- "$TMPD/hosts.tmp" "$HOSTS_FILE"
      continue
    fi

    if [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+(open|closed|filtered)[[:space:]]+([^[:space:]]+)(.*) ]]; then
      local port=${BASH_REMATCH[1]} proto=${BASH_REMATCH[2]} state=${BASH_REMATCH[3]}
      local service=${BASH_REMATCH[4]} version=${BASH_REMATCH[5]}
      version=${version#"${version%%[![:space:]]*}"}   # strip ALL leading whitespace, not just one char
      printf '%s|%s|%s|%s|%s|%s\n' "$current_ip" "$port" "$state" "$proto" "$service" "$version" >> "$PORTS_FILE"

      if [[ "$state" == open ]]; then
        local cnt
        cnt=$(awk -F'|' -v ip="$current_ip" '$1==ip && $3=="open"{c++} END{print c+0}' "$PORTS_FILE")
        awk -F'|' -v ip="$current_ip" -v c="$cnt" 'BEGIN{OFS="|"} $1==ip{$3=c} {print}' \
          "$HOSTS_FILE" > "$TMPD/hosts.tmp" && mv -- "$TMPD/hosts.tmp" "$HOSTS_FILE"
      fi
    fi
  done < <(nmap "${PROFILE_ARGV[@]}" "$TARGET" 2>&1)   # argv-safe invocation (BUG-06 fix)

  kill "$ticker_pid" 2>/dev/null || true
  printf '%s' "$(( SECONDS - start_ts ))" > "$ELAPSED_FILE"
  rm -f -- "$SCANNING_FLAG"
}

# ── inline input (bottom of screen) ──────────────────────────────────────────
read_input() {
  local label=$1 default=$2 result=""
  # Restore the user's real terminal settings (not `stty sane`, which discards
  # any custom modes) so backspace/line-editing behave normally (BUG-12 fix).
  [[ -n "$STTY_SAVE" ]] && stty "$STTY_SAVE" </dev/tty 2>/dev/null
  cur_move "$STATUS_ROW" 1
  clear_eol
  printf '%s%s%s [%s]: ' "$CYAN" "$BOLD" "$label" "$default"
  cur_show
  IFS= read -r result </dev/tty
  cur_hide
  [[ -n "$STTY_SAVE" ]] && stty -echo raw </dev/tty 2>/dev/null
  printf '%s' "${result:-$default}"
}

# ── profile picker ────────────────────────────────────────────────────────────
pick_profile() {
  local -a keys=(quick regular intense ping udp os)
  local sel=0 i=0 k
  for k in "${keys[@]}"; do [[ "$k" == "$PROFILE" ]] && { sel=$i; break; }; (( i++ )); done

  while true; do
    local r=$(( CONTENT_TOP + 1 ))
    cur_move "$r" "$CONTENT_LEFT"
    printf '%sSelect Profile  %s↑↓ navigate  Enter confirm  q cancel%s' "$BOLD" "$DIM" "$RST"
    clear_eol; (( r++ ))
    hline "$r" "$CONTENT_LEFT" 40 '─'; (( r++ ))

    local j=0
    for k in "${keys[@]}"; do
      cur_move "$r" "$CONTENT_LEFT"
      if (( j == sel )); then
        printf '%s%s▶ %s%s' "$BG_ROW" "$CYAN" "$(pad "${PROFILE_LABELS[$k]}" 20)" "$RST"
      else
        printf '  %s%s%s' "$DIM" "$(pad "${PROFILE_LABELS[$k]}" 20)" "$RST"
      fi
      clear_eol; (( r++ )); (( j++ ))
    done

    local pk="" ps=""
    IFS= read -rsn1 pk </dev/tty
    if [[ "$pk" == $'\x1b' ]]; then
      IFS= read -rsn2 -t 0.05 ps </dev/tty 2>/dev/null || true
    fi
    if   [[ "$ps" == "[A" ]]; then (( sel > 0 )) && (( sel-- ))
    elif [[ "$ps" == "[B" ]]; then (( sel < ${#keys[@]}-1 )) && (( sel++ ))
    elif [[ -z "$pk" ]];      then PROFILE=${keys[$sel]}; return 0
    elif [[ "$pk" == [qQ] ]]; then return 1
    fi
  done
}

switch_tab() { ACTIVE_TAB=$1; SCROLL_OUT=0; SCROLL_PORTS=0; redraw; }

# ── main loop ─────────────────────────────────────────────────────────────────
main() {
  STTY_SAVE=$(stty -g </dev/tty 2>/dev/null) || STTY_SAVE=""
  [[ -n "$STTY_SAVE" ]] && stty -echo raw </dev/tty

  screen_alt; cur_hide; recalc_layout; screen_clear; redraw
  trap 'recalc_layout; screen_clear; redraw' WINCH

  KEY=""; SEQ=""
  read_key() {
    KEY=""; SEQ=""
    if [[ -e "$SCANNING_FLAG" ]]; then
      # Non-blocking poll while a scan runs — redraw ticks the clock/output/sidebar
      IFS= read -rsn1 -t 0.5 KEY </dev/tty 2>/dev/null || {
        draw_title; draw_output_pane; draw_sidebar; draw_statusbar   # BUG-14 fix: sidebar now updates live
        return 1
      }
    else
      IFS= read -rsn1 KEY </dev/tty
    fi
    if [[ "$KEY" == $'\x1b' ]]; then
      IFS= read -rsn2 -t 0.05 SEQ </dev/tty 2>/dev/null || true
    fi
    return 0
  }

  while true; do
    read_key || continue

    if   [[ "$KEY" == $'\x1b' && "$SEQ" == "[D" ]]; then
      (( ACTIVE_TAB > 0 )) && switch_tab $(( ACTIVE_TAB - 1 ))

    elif [[ "$KEY" == $'\x1b' && "$SEQ" == "[C" ]]; then
      (( ACTIVE_TAB < 4 )) && switch_tab $(( ACTIVE_TAB + 1 ))

    elif [[ "$KEY" == $'\x1b' && "$SEQ" == "[A" ]]; then
      case "$ACTIVE_TAB" in
        0) (( SCROLL_OUT++ )); draw_output_pane ;;
        1) (( SCROLL_PORTS > 0 )) && (( SCROLL_PORTS-- )); draw_ports_pane ;;
        2) (( SELECTED_HOST > 0 )) && (( SELECTED_HOST-- )); draw_sidebar; draw_details_pane ;;
      esac

    elif [[ "$KEY" == $'\x1b' && "$SEQ" == "[B" ]]; then
      case "$ACTIVE_TAB" in
        0) (( SCROLL_OUT > 0 )) && (( SCROLL_OUT-- )); draw_output_pane ;;
        1) (( SCROLL_PORTS++ )); draw_ports_pane ;;
        2)
          local hc=0
          [[ -s "$HOSTS_FILE" ]] && hc=$(wc -l < "$HOSTS_FILE")
          (( SELECTED_HOST < hc - 1 )) && (( SELECTED_HOST++ ))
          draw_sidebar; draw_details_pane ;;
      esac

    elif [[ "$KEY" == [sS] ]]; then
      if [[ -e "$SCANNING_FLAG" ]]; then
        rm -f -- "$SCANNING_FLAG"
        [[ -n "$SCAN_PID" ]] && { kill -- "-$SCAN_PID" 2>/dev/null || kill "$SCAN_PID" 2>/dev/null || true; }
        printf '\nScan stopped by user.\n' >> "$OUT_FILE"
        redraw
      else
        SCROLL_OUT=0; ACTIVE_TAB=0
        set -m                       # enable job control so run_scan gets its own process group (BUG-16 support)
        run_scan &
        SCAN_PID=$!
        set +m
        redraw
      fi

    elif [[ "$KEY" == [tT] ]]; then
      TARGET=$(read_input "Target" "$TARGET")
      redraw

    elif [[ "$KEY" == [pP] ]]; then
      pick_profile; redraw

    elif [[ "$KEY" == [rR] ]]; then
      screen_clear; redraw

    elif [[ "$KEY" == [qQ] ]]; then
      exit 0

    elif [[ "$KEY" == $'\t' ]]; then
      switch_tab $(( (ACTIVE_TAB + 1) % 5 ))

    elif [[ "$KEY" == "1" ]]; then switch_tab 0
    elif [[ "$KEY" == "2" ]]; then switch_tab 1
    elif [[ "$KEY" == "3" ]]; then switch_tab 2
    elif [[ "$KEY" == "4" ]]; then switch_tab 3
    elif [[ "$KEY" == "5" ]]; then switch_tab 4
    fi
  done
}

# ── dependency preflight (runs in cooked/normal terminal mode, before raw mode) ─
REQUIRED_BINS=(
  "nmap|nmap|nmap|nmap|nmap"
  "awk|gawk|gawk|gawk|gawk"
  "stty|coreutils|coreutils|coreutils|coreutils"
  "mktemp|coreutils|coreutils|coreutils|coreutils"
  "wc|coreutils|coreutils|coreutils|coreutils"
)

_R=$'\033[0m'; _B=$'\033[1m'; _D=$'\033[2m'
_RD=$'\033[31m'; _GN=$'\033[32m'; _YL=$'\033[33m'; _CY=$'\033[36m'; _WH=$'\033[37m'

detect_pkgmgr() {
  local mgr
  for mgr in apt-get dnf yum pacman brew pkg apk zypper; do
    command -v "$mgr" &>/dev/null && { printf '%s' "$mgr"; return; }
  done
  printf 'unknown'
}

# Returns an argv array in global INSTALL_ARGV — no eval, no string concatenation (BUG-17 fix)
build_install_argv() {          # build_install_argv mgr pkg1 pkg2 ...
  local mgr=$1; shift
  case "$mgr" in
    apt-get) INSTALL_ARGV=(sudo apt-get install -y "$@") ;;
    dnf)     INSTALL_ARGV=(sudo dnf install -y "$@") ;;
    yum)     INSTALL_ARGV=(sudo yum install -y "$@") ;;
    pacman)  INSTALL_ARGV=(sudo pacman -S --noconfirm "$@") ;;
    brew)    INSTALL_ARGV=(brew install "$@") ;;
    pkg)     INSTALL_ARGV=(sudo pkg install -y "$@") ;;
    apk)     INSTALL_ARGV=(sudo apk add "$@") ;;
    zypper)  INSTALL_ARGV=(sudo zypper install -y "$@") ;;
    *)       INSTALL_ARGV=() ;;
  esac
}

field_for_mgr() {
  local entry=$1 mgr=$2 f_apt f_brew f_dnf f_pac _b
  IFS='|' read -r _b f_apt f_brew f_dnf f_pac <<< "$entry"
  case "$mgr" in
    apt-get|apk|zypper|pkg) printf '%s' "$f_apt" ;;
    brew)                   printf '%s' "$f_brew" ;;
    dnf|yum)                printf '%s' "$f_dnf" ;;
    pacman)                 printf '%s' "$f_pac" ;;
    *)                      printf '%s' "$f_apt" ;;
  esac
}

box_line() { printf '%s%s│%s %-*s %s%s│%s\n' "$_B" "$_CY" "$_R" "$(( $2 - 3 ))" "$1" "$_B" "$_CY" "$_R"; }

preflight_check() {
  local -a missing=() missing_entries=()
  local entry bin
  for entry in "${REQUIRED_BINS[@]}"; do
    bin=${entry%%|*}
    command -v "$bin" &>/dev/null || { missing+=("$bin"); missing_entries+=("$entry"); }
  done
  (( ${#missing[@]} == 0 )) && return 0

  local mgr W=62 bar
  mgr=$(detect_pkgmgr)
  # Pure-bash horizontal rule via brace expansion — no `seq` dependency (BUG-21 fix)
  printf -v bar '%*s' "$W" ''; bar=${bar// /─}

  printf '\n%s%s┌%s┐%s\n' "$_B" "$_CY" "$bar" "$_R"
  box_line "Zenmap TUI  ──  Dependency Check" $W
  box_line "" $W
  box_line "The following required binaries were not found:" $W
  for bin in "${missing[@]}"; do
    printf '%s%s│%s    %s✗%s  %s%-*s%s%s%s│%s\n' "$_B" "$_CY" "$_R" "$_RD" "$_R" "$_WH" $(( W - 7 )) "$bin" "$_R" "$_B" "$_CY" "$_R"
  done
  box_line "" $W

  if [[ "$mgr" == unknown ]]; then
    box_line "No package manager detected." $W
    box_line "Install the binaries manually and re-run." $W
    printf '%s%s└%s┘%s\n\n' "$_B" "$_CY" "$bar" "$_R"
    printf '%sPress any key to exit.%s ' "$_YL" "$_R"; read -rsn1; printf '\n'
    exit 1
  fi

  local -A seen=(); local -a pkgs=()
  for entry in "${missing_entries[@]}"; do
    local p; p=$(field_for_mgr "$entry" "$mgr")
    [[ -n "$p" && -z "${seen[$p]+_}" ]] && { seen[$p]=1; pkgs+=("$p"); }
  done

  build_install_argv "$mgr" "${pkgs[@]}"
  local icmd_display="${INSTALL_ARGV[*]}"

  box_line "Package manager : ${mgr}" $W
  box_line "" $W
  box_line "Proposed install command:" $W
  printf '%s%s│%s    %s%-*s%s%s%s│%s\n' "$_B" "$_CY" "$_R" "$_YL" $(( W - 5 )) "${icmd_display:0:$(( W - 5 ))}" "$_R" "$_B" "$_CY" "$_R"
  box_line "" $W
  printf '%s%s└%s┘%s\n\n' "$_B" "$_CY" "$bar" "$_R"

  while true; do
    printf '%sInstall missing dependencies now?%s  [%sy%s]es  [%sn%s]o  [%ss%s]kip and launch anyway\n> ' \
      "$_B" "$_R" "$_GN" "$_R" "$_RD" "$_R" "$_CY" "$_R"
    local ans; read -r ans
    case "${ans,,}" in
      y|yes)
        printf '\n%sRunning:%s %s%s%s\n\n' "$_CY" "$_R" "$_YL" "${INSTALL_ARGV[*]}" "$_R"
        # Direct argv exec — no eval, no shell re-parsing of package names (BUG-17 fix)
        if "${INSTALL_ARGV[@]}"; then
          printf '\n%s%s✓  Installation complete.%s\n\n' "$_GN" "$_B" "$_R"
          local -a still=()
          for bin in "${missing[@]}"; do command -v "$bin" &>/dev/null || still+=("$bin"); done
          if (( ${#still[@]} > 0 )); then
            printf '%sStill missing: %s%s\nPlease install manually and re-run.\n\n' "$_RD" "${still[*]}" "$_R"
            exit 1
          fi
          printf '%sPress any key to launch the TUI…%s ' "$_D" "$_R"; read -rsn1; printf '\n'
          return 0
        else
          printf '\n%sInstallation failed.%s\n' "$_RD" "$_R"
          printf 'Try running manually:\n  %s%s%s\n\n' "$_YL" "${INSTALL_ARGV[*]}" "$_R"
          exit 1
        fi ;;
      n|no)
        printf '\n%sAborted. Install the missing binaries and re-run.%s\n\n' "$_YL" "$_R"
        exit 0 ;;
      s|skip)
        printf '\n%sSkipping install — some features may not work.%s\n\n' "$_YL" "$_R"
        sleep 1; return 0 ;;
      *)
        printf '%sPlease enter y, n, or s.%s\n' "$_RD" "$_R" ;;
    esac
  done
}

preflight_check
main
