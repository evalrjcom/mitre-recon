#!/bin/ash
# tui_fw_v3.sh — TinyWall-style TUI Firewall Manager
# POSIX ash / BusyBox compatible · Alpine Linux / LXC
# Requires: iptables (or ufw), ss or /proc/net/tcp, root
# Usage: sh tui_fw_v3.sh
#
# Changelog:
#   v1 — original
#   v2 — security/correctness/perf fixes (eval removed, probe leak fixed,
#         big-endian support, bulk PID cache, _validate_ip, _TAB fix)
#   v3 — endianness detection rewritten: ELF-header primary (always correct),
#         loopback full-scan fallback; reversed-LOCAL-IP bug fixed

# ─────────────────────── CONSTANTS ───────────────────────────────────────────
CHAIN="TUIFW"
RULEFILE="/var/lib/tuifw/rules"
UPDATE_INTERVAL=3   # seconds between connection-list refresh
INPUT_TIMEOUT=1     # VTIME units (tenths of second) per read attempt
MAX_ROWS=16         # visible connection rows

R='\033[1;31m'  G='\033[1;32m'  Y='\033[1;33m'
C='\033[1;36m'  W='\033[1;37m'
DIM='\033[2m'   BOLD='\033[1m'  RST='\033[0m'

# ─────────────────────── GLOBAL STATE ────────────────────────────────────────
UFW=0
CURSOR=1
CONN_COUNT=0
# Store last-rule components separately to avoid eval entirely.
# LAST_RULE_TYPE: "cmd" | "uid" | "ip" | ""
# LAST_RULE_VAL:  the comm/uid/ip value used
LAST_RULE_TYPE=""
LAST_RULE_VAL=""
TMPCONN="/tmp/tuifw_conn_$$"

_T_HOME=""   # tput cup 0 0
_T_ED=""     # tput ed

# stty saved state — captured ONCE before raw mode, never overwritten
_STTY_SAVE=""

# Tick counter: each iteration ≈ 0.1 s (VTIME=1 tenth-second).
# Refresh fires when _TICK reaches _TICK_MAX = UPDATE_INTERVAL * 10.
_TICK=0
_TICK_MAX=30  # overwritten in main() to UPDATE_INTERVAL*10

# Scratch globals used by _pid_name / _pid_user (avoid subshell cache loss)
_G_NAME=""
_G_USER=""

# Portable literal tab
_TAB=$(printf '\t')

# Per-PID name+user cache file: "PID\tNAME\tUSER" lines.
PIDCACHE="/tmp/tuifw_pidc_$$"
: > "$PIDCACHE"

# Bulk cache lookup scratch files, rebuilt each draw.
_PIDCACHE_MISS="/tmp/tuifw_miss_$$"
_PRECACHE_FILE="/tmp/tuifw_pre_$$"

# Cached iptables/ufw block output; refreshed only at UPDATE_INTERVAL.
_BLOCKS_OUT=""
_BLOCKS_DIRTY=1

# Per-session UID→name cache (globals, not subshell)
_uid_cache_uid=""
_uid_cache_name=""

# ─────────────────────── ENDIANNESS DETECTION ────────────────────────────────
# /proc/net/tcp stores addresses in HOST byte order (not network order):
#   little-endian (x86/x86_64/ARM-LE): 127.0.0.1 → 0100007F  (reversed)
#   big-endian    (MIPS/s390/ARM-BE):  127.0.0.1 → 7F000001  (natural)
#
# Method A (primary): read ELF header byte 6 (EI_DATA) from any binary.
#   01 = ELFDATA2LSB (little-endian), 02 = ELFDATA2MSB (big-endian).
#   Always present on Linux; independent of any sockets existing.
# Method B (fallback): scan ALL rows of /proc/net/tcp for loopback pattern.
#   0100007F = LE, 7F000001 = BE.  Scanning all rows (not just NR==2)
#   works even when loopback isn't the first entry or doesn't exist.
# Default: little-endian — correct for the vast majority of Alpine/LXC hosts.
_PROC_LE=1

_detect_endian() {
    # Method A: ELF EI_DATA field (byte index 5, 0-based)
    for _bin in /bin/busybox /bin/sh /usr/bin/awk /bin/ls; do
        [ -r "$_bin" ] || continue
        _eidata=$(dd if="$_bin" bs=1 skip=5 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
        case "$_eidata" in
            01) _PROC_LE=1; return ;;   # ELFDATA2LSB — little-endian
            02) _PROC_LE=0; return ;;   # ELFDATA2MSB — big-endian
        esac
    done

    # Method B: scan /proc/net/tcp for loopback byte pattern
    if [ -f /proc/net/tcp ]; then
        while IFS= read -r _row; do
            case "$_row" in *' 0100007F:'*) _PROC_LE=1; return ;; esac
            case "$_row" in *' 7F000001:'*) _PROC_LE=0; return ;; esac
        done < /proc/net/tcp
    fi
    # Default: _PROC_LE=1 (little-endian)
}

# ─────────────────────── TERMINAL SETUP ──────────────────────────────────────
init_term() {
    _T_HOME=$(tput cup 0 0 2>/dev/null) || _T_HOME=""
    _T_ED=$(tput ed     2>/dev/null)    || _T_ED=""
    tput civis 2>/dev/null || true
}

stty_init_raw() {
    _STTY_SAVE=$(stty -g 2>/dev/null) || _STTY_SAVE=""
    _stty_raw_rearm
}

_stty_raw_rearm() {
    stty -echo -icanon min 0 time "$INPUT_TIMEOUT" 2>/dev/null || true
}

stty_restore() {
    if [ -n "$_STTY_SAVE" ]; then
        stty "$_STTY_SAVE" 2>/dev/null || stty sane 2>/dev/null || true
    else
        stty sane 2>/dev/null || true
    fi
}

# ─────────────────────── ENVIRONMENT DETECTION ───────────────────────────────
detect_environment() {
    UFW=0
    if command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null | grep -qw "active" && UFW=1
    fi
    if [ "$UFW" -eq 0 ]; then
        iptables -N "$CHAIN" 2>/dev/null || true
        iptables -C OUTPUT -j "$CHAIN" 2>/dev/null || iptables -I OUTPUT 1 -j "$CHAIN"
        iptables -C INPUT  -j "$CHAIN" 2>/dev/null || iptables -I INPUT  1 -j "$CHAIN"
    fi
    mkdir -p "$(dirname "$RULEFILE")"
    touch "$RULEFILE"
}

# ─────────────────────── CONNECTION ENUMERATION ──────────────────────────────
_parse_ss() {
    ss -tupn 2>/dev/null | awk '
    NR == 1 { next }
    {
        proto = $1
        if (proto != "tcp" && proto != "tcp6" && proto != "udp" && proto != "udp6") next

        pid = ""
        pos = index($0, "pid=")
        if (pos > 0) {
            rest = substr($0, pos + 4)
            match(rest, /^[0-9]+/)
            pid = substr(rest, 1, RLENGTH)
        }

        line = $0
        pos2 = index(line, "users:((")
        if (pos2 > 0) line = substr(line, 1, pos2 - 1)

        # Collect addr:port tokens; delete a not needed (cnt resets each row)
        cnt = 0
        n = split(line, t, " ")
        for (i = 1; i <= n; i++) {
            if (match(t[i], /:[0-9]+$/)) {
                cnt++
                a[cnt] = t[i]
            }
        }
        if (cnt < 1) next
        local  = (cnt >= 2) ? a[cnt-1] : a[1]
        remote = a[cnt]

        print proto "\t" local "\t" remote "\t" pid
    }'
}

# /proc/net/tcp fallback — endianness-aware, no shell subshells.
_parse_proc() {
    for f in /proc/net/tcp /proc/net/tcp6; do
        [ -f "$f" ] || continue
        case "$f" in *6) _proto="tcp6" ;; *) _proto="tcp" ;; esac
        awk -v proto="$_proto" -v le="$_PROC_LE" '
        NR == 1 { next }
        {
            split($2, l, ":")
            split($3, r, ":")
            if (length(l[1]) != 8) next

            lp = hnum(l[1]); rp = hnum(r[1])
            lport = hnum(l[2]); rport = hnum(r[2])

            if (le) {
                # Little-endian: bytes stored reversed in /proc/net/tcp
                printf "%s\t%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t\n",
                    proto,
                    hbyte(lp,24), hbyte(lp,16), hbyte(lp,8), hbyte(lp,0), lport,
                    hbyte(rp,24), hbyte(rp,16), hbyte(rp,8), hbyte(rp,0), rport
            } else {
                # Big-endian: bytes already in network order
                printf "%s\t%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t\n",
                    proto,
                    hbyte(lp,0), hbyte(lp,8), hbyte(lp,16), hbyte(lp,24), lport,
                    hbyte(rp,0), hbyte(rp,8), hbyte(rp,16), hbyte(rp,24), rport
            }
        }
        function hdigit(c,  v) {
            v = index("0123456789abcdef", tolower(c))
            return (v > 0) ? v - 1 : 0
        }
        function hnum(s,  i, v) {
            v = 0
            for (i = 1; i <= length(s); i++) v = v * 16 + hdigit(substr(s,i,1))
            return v
        }
        function hbyte(n, shift,  div) {
            if      (shift ==  0) div = 1
            else if (shift ==  8) div = 256
            else if (shift == 16) div = 65536
            else                  div = 16777216
            return int(n / div) % 256
        }
        ' "$f"
    done
}

enumerate_connections() {
    : > "$TMPCONN"
    if command -v ss >/dev/null 2>&1; then
        _parse_ss >> "$TMPCONN"
    else
        _parse_proc >> "$TMPCONN"
    fi
    _wc=$(wc -l < "$TMPCONN" 2>/dev/null) || _wc=0
    CONN_COUNT=$(printf '%s' "$_wc" | tr -d ' \t')
    case "$CONN_COUNT" in ''|*[!0-9]*) CONN_COUNT=0 ;; esac
    [ "$CURSOR" -gt "$CONN_COUNT" ] && CURSOR=$CONN_COUNT
    [ "$CURSOR" -lt 1 ]             && CURSOR=1
}

# ─────────────────────── PID RESOLUTION ──────────────────────────────────────
_pid_name() {
    _G_NAME="?"
    [ -z "$1" ] && return
    if [ -r "/proc/$1/comm" ]; then
        IFS= read -r _G_NAME < "/proc/$1/comm" 2>/dev/null || _G_NAME="?"
    fi
    # Strip chars unsafe in iptables args; comm is kernel-limited to 15 chars
    # but prctl() can inject arbitrary bytes — sanitise before use in rules.
    _G_NAME=$(printf '%s' "$_G_NAME" | tr -cd 'A-Za-z0-9._-')
    [ -z "$_G_NAME" ] && _G_NAME="?"
}

_pid_user() {
    _G_USER="?"
    [ -z "$1" ] && return
    _uid=""
    {
        while IFS= read -r _sl; do
            case "$_sl" in
                Uid:*)
                    _uid="${_sl#Uid:}"
                    _uid="${_uid#"${_uid%%[! ]*}"}"
                    # Use _TAB variable — no fragile literal tab in char class
                    _uid="${_uid%%["$_TAB" ]*}"
                    break ;;
            esac
        done
    } < "/proc/$1/status" 2>/dev/null
    [ -z "$_uid" ] && return
    if [ "$_uid" = "$_uid_cache_uid" ]; then
        _G_USER="$_uid_cache_name"; return
    fi
    _uid_cache_uid="$_uid"
    _uid_cache_name=$(awk -F: -v u="$_uid" '$3==u{print $1;exit}' /etc/passwd 2>/dev/null)
    [ -z "$_uid_cache_name" ] && _uid_cache_name="uid:$_uid"
    _G_USER="$_uid_cache_name"
}

# Bulk preload: single awk pass over TMPCONN finds cache misses; resolves them
# in one batch before the draw loop — eliminates per-row grep forks.
_preload_pid_cache() {
    : > "$_PIDCACHE_MISS"
    awk -F"$_TAB" -v cachefile="$PIDCACHE" -v missfile="$_PIDCACHE_MISS" '
    BEGIN {
        while ((getline line < cachefile) > 0) {
            n = split(line, a, "\t")
            if (n >= 3) cached[a[1]] = 1
        }
    }
    {
        pid = $4
        if (pid != "" && !(pid in cached) && !(pid in seen)) {
            seen[pid] = 1
            print pid > missfile
        }
    }
    ' "$TMPCONN"

    if [ -s "$_PIDCACHE_MISS" ]; then
        while IFS= read -r _mp; do
            _pid_name "$_mp"
            _pid_user "$_mp"
            printf '%s\t%s\t%s\n' "$_mp" "$_G_NAME" "$_G_USER" >> "$PIDCACHE"
        done < "$_PIDCACHE_MISS"
    fi

    cp "$PIDCACHE" "$_PRECACHE_FILE" 2>/dev/null || : > "$_PRECACHE_FILE"
}

# Single awk lookup per PID against preloaded cache — no grep fork per row.
_pid_resolve() {
    _rp="$1"
    if [ -z "$_rp" ]; then
        _G_NAME="?"; _G_USER="?"; return
    fi
    _hit=$(awk -F"$_TAB" -v pid="$_rp" '$1==pid{print $2"\t"$3; exit}' \
               "$_PRECACHE_FILE" 2>/dev/null)
    if [ -n "$_hit" ]; then
        _G_NAME="${_hit%%"$_TAB"*}"
        _G_USER="${_hit##*"$_TAB"}"
    else
        _pid_name "$_rp"
        _pid_user "$_rp"
    fi
}

# ─────────────────────── BLOCKING ────────────────────────────────────────────

# Probe --cmd-owner support ONCE at startup; immediately clean up probe rule
# to prevent accumulation (the original per-block-call probe leaked one rule
# per invocation on kernels that support --cmd-owner).
_CMD_OWNER_SUPPORTED=""

_probe_cmd_owner() {
    [ -n "$_CMD_OWNER_SUPPORTED" ] && return
    if iptables -A "$CHAIN" -m owner --cmd-owner _tuifw_probe_ -j REJECT 2>/dev/null; then
        # Immediately remove — never leave probe rules in the chain
        iptables -D "$CHAIN" -m owner --cmd-owner _tuifw_probe_ -j REJECT 2>/dev/null || true
        _CMD_OWNER_SUPPORTED=1
    else
        _CMD_OWNER_SUPPORTED=0
    fi
}

block_exe() {
    _exe="$1"; _label="$2"; _uid="$3"
    [ -z "$_exe" ] && { printf "${R}No exe path.${RST}\n"; return 1; }

    _safe=$(printf '%s' "$_label" | tr -d "'\"\\" | cut -c1-30)
    _comm=$(basename "$_exe" | cut -c1-15)

    # Reject comms with unsafe chars — fall back to UID block
    case "$_comm" in
        *[!A-Za-z0-9._-]*)
            printf "${Y}Comm '%s' has unsafe chars — blocking by UID.${RST}\n" "$_comm"
            _block_by_uid "$_uid" "$_safe"; return $? ;;
    esac

    if [ "$_CMD_OWNER_SUPPORTED" != "1" ]; then
        _block_by_uid "$_uid" "$_safe"; return $?
    fi

    iptables -A "$CHAIN" -m owner --cmd-owner "$_comm" -j REJECT \
        --reject-with icmp-port-unreachable 2>/dev/null \
        || iptables -A "$CHAIN" -m owner --cmd-owner "$_comm" -j REJECT 2>/dev/null

    # Store rule components separately — no eval path anywhere
    LAST_RULE_TYPE="cmd"
    LAST_RULE_VAL="$_comm"
    printf '%s\t%s\n' "cmd:$_comm" "$_safe" >> "$RULEFILE"
    printf "${R}✖ Blocked:${RST} %s (comm=%s)\n" "$_safe" "$_comm"
    _BLOCKS_DIRTY=1
}

_block_by_uid() {
    _uid="$1"; _label="$2"
    [ -z "$_uid" ] && { printf "${R}Cannot determine UID.${RST}\n"; return 1; }
    iptables -A "$CHAIN" -m owner --uid-owner "$_uid" -j REJECT \
        --reject-with icmp-port-unreachable 2>/dev/null
    LAST_RULE_TYPE="uid"
    LAST_RULE_VAL="$_uid"
    printf '%s\t%s\n' "uid:$_uid" "$_label" >> "$RULEFILE"
    printf "${R}✖ Blocked uid=%s${RST} (%s)\n" "$_uid" "$_label"
    _BLOCKS_DIRTY=1
}

# Tightened IP validation: reject malformed addresses that the original
# [!0-9a-fA-F.:] pattern would have accepted (e.g. "...", "::::::").
_validate_ip() {
    _vip="$1"
    _vip="${_vip#[}"; _vip="${_vip%]}"   # strip IPv6 brackets
    _vip="${_vip%%\%*}"                   # strip zone ID (fe80::1%eth0)
    case "$_vip" in
        "") return 1 ;;
        # IPv4: digits and dots only, exactly 3 dots
        [0-9]*.*[0-9])
            case "$_vip" in *[!0-9.]*) return 1 ;; esac
            _dots=$(printf '%s' "$_vip" | tr -cd '.' | wc -c | tr -d ' ')
            [ "$_dots" -eq 3 ] || return 1 ;;
        # IPv6: colons present, only hex digits and colons
        *:*)
            case "$_vip" in *[!0-9a-fA-F:]*) return 1 ;; esac ;;
        *) return 1 ;;
    esac
    return 0
}

block_ip() {
    _ip="${1%%:*}"
    if ! _validate_ip "$_ip"; then
        printf "${Y}Invalid IP: '%s'${RST}\n" "$_ip"; return 1
    fi
    iptables -A "$CHAIN" -s "$_ip" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
    iptables -A "$CHAIN" -d "$_ip" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
    LAST_RULE_TYPE="ip"
    LAST_RULE_VAL="$_ip"
    printf 'ip:%s\t%s\n' "$_ip" "$_ip" >> "$RULEFILE"
    printf "${R}✖ IP blocked:${RST} %s\n" "$_ip"
    _BLOCKS_DIRTY=1
}

# Explicit iptables -D dispatch by rule type — eval eliminated entirely.
unblock_last() {
    [ -z "$LAST_RULE_TYPE" ] && { printf "${Y}Nothing to unblock.${RST}\n"; return; }

    _ok=0
    case "$LAST_RULE_TYPE" in
        cmd)
            iptables -D "$CHAIN" -m owner --cmd-owner "$LAST_RULE_VAL" -j REJECT \
                --reject-with icmp-port-unreachable 2>/dev/null \
                || iptables -D "$CHAIN" -m owner --cmd-owner "$LAST_RULE_VAL" -j REJECT \
                   2>/dev/null \
                && _ok=1
            ;;
        uid)
            iptables -D "$CHAIN" -m owner --uid-owner "$LAST_RULE_VAL" -j REJECT \
                --reject-with icmp-port-unreachable 2>/dev/null \
                && _ok=1
            ;;
        ip)
            iptables -D "$CHAIN" -s "$LAST_RULE_VAL" -j REJECT \
                --reject-with icmp-port-unreachable 2>/dev/null && _ok=1
            iptables -D "$CHAIN" -d "$LAST_RULE_VAL" -j REJECT \
                --reject-with icmp-port-unreachable 2>/dev/null || true
            ;;
    esac

    if [ "$_ok" -eq 1 ]; then
        printf "${G}✔ Unblocked.${RST}\n"
    else
        printf "${Y}Rule not found (already gone?).${RST}\n"
    fi

    LAST_RULE_TYPE=""; LAST_RULE_VAL=""
    _BLOCKS_DIRTY=1

    _rfl=$(wc -l < "$RULEFILE" | tr -d ' ')
    case "$_rfl" in
        ''|0|1) : > "$RULEFILE" ;;
        *) awk "NR<$_rfl" "$RULEFILE" > "/tmp/tuifw_rf_$$" \
               && mv "/tmp/tuifw_rf_$$" "$RULEFILE" ;;
    esac
}

flush_all() {
    iptables -F "$CHAIN" 2>/dev/null
    : > "$RULEFILE"
    LAST_RULE_TYPE=""; LAST_RULE_VAL=""
    _BLOCKS_DIRTY=1
}

ufw_block_ip() {
    _ip="$1"
    if ! _validate_ip "$_ip"; then
        printf "${Y}Invalid IP: '%s'${RST}\n" "$_ip"; return 1
    fi
    ufw insert 1 deny from "$_ip" >/dev/null 2>&1 \
        && printf "${R}✖ UFW blocked:${RST} %s\n" "$_ip" \
        || printf "${Y}UFW block failed.${RST}\n"
}

# ─────────────────────── DRAW ─────────────────────────────────────────────────
draw_ui() {
    if [ -n "$_T_HOME" ] && [ -n "$_T_ED" ]; then
        printf '%s%s' "$_T_HOME" "$_T_ED"
    else
        clear
    fi
    _draw_header
    _draw_keys
    _draw_connections
    _draw_blocks
    printf '\n'
}

_draw_header() {
    [ "$UFW" -eq 1 ] \
        && _be="${C}ufw${RST}" \
        || _be="${C}iptables/${CHAIN}${RST}"
    printf "${BOLD}╔══════════════════════════════════════════════════════════════╗${RST}\n"
    printf "${BOLD}║  TUIFW  ▸  TinyWall-style Firewall Manager  v3              ║${RST}\n"
    printf "${BOLD}╚══════════════════════════════════════════════════════════════╝${RST}\n"
    printf "  Backend: %b   Connections: ${W}%d${RST}\n\n" "$_be" "$CONN_COUNT"
}

_draw_keys() {
    printf "  ${DIM}↑/↓ j/k navigate  b:block-exe  i:block-ip  u:undo  f:flush  q:quit${RST}\n\n"
}

_draw_connections() {
    printf "  ${BOLD}${C}%-6s  %-22s  %-22s  %-13s  %s${RST}\n" \
        "PROTO" "LOCAL" "REMOTE" "PROCESS" "USER"
    printf "  ${DIM}──────  ──────────────────────  ──────────────────────  ─────────────  ────${RST}\n"

    _row=0
    while IFS="${_TAB}" read -r _proto _local _remote _pid; do
        _row=$((_row + 1))
        [ "$_row" -gt "$MAX_ROWS" ] && break

        _pid_resolve "$_pid"

        _locs=$(printf '%.22s' "$_local")
        _rems=$(printf '%.22s' "$_remote")
        _nams=$(printf '%.13s' "$_G_NAME")
        _usrs=$(printf '%.8s'  "$_G_USER")

        if [ "$_row" -eq "$CURSOR" ]; then
            printf "  ${BOLD}${G}▶ %-4s  %-22s  %-22s  %-13s  %s${RST}\n" \
                "$_proto" "$_locs" "$_rems" "$_nams" "$_usrs"
        else
            printf "    %-4s  %-22s  %-22s  %-13s  ${DIM}%s${RST}\n" \
                "$_proto" "$_locs" "$_rems" "$_nams" "$_usrs"
        fi
    done < "$TMPCONN"

    while [ "$_row" -lt "$MAX_ROWS" ]; do
        printf '\n'; _row=$((_row + 1))
    done
}

_draw_blocks() {
    printf "\n  ${BOLD}${R}Active Blocks${RST}  ${DIM}(${CHAIN} chain)${RST}\n"
    printf "  ${DIM}──────────────────────────────────────────────────────────────${RST}\n"
    if [ "$_BLOCKS_DIRTY" -eq 1 ]; then
        if [ "$UFW" -eq 1 ]; then
            _BLOCKS_OUT=$(ufw status 2>/dev/null | grep -E 'DENY|REJECT' | head -6)
        else
            _BLOCKS_OUT=$(iptables -L "$CHAIN" -n 2>/dev/null | grep -E 'REJECT|DROP' | head -6)
        fi
        _BLOCKS_DIRTY=0
    fi
    if [ -n "$_BLOCKS_OUT" ]; then
        printf '%s\n' "$_BLOCKS_OUT" | while IFS= read -r _l; do
            printf "  ${R}✖${RST}  %s\n" "$_l"
        done
    else
        printf "  ${DIM}No active blocks.${RST}\n"
    fi
}

# ─────────────────────── CURSOR HELPERS ──────────────────────────────────────
_get_field() {
    awk -v r="$1" -v f="$2" -F"$_TAB" 'NR==r{print (f<=NF)?$f:""; exit}' "$TMPCONN"
}
_sel_pid()    { _get_field "$CURSOR" 4; }
_sel_remote() {
    _addr=$(_get_field "$CURSOR" 3)
    printf '%s' "${_addr%:*}"
}

cursor_up()   { [ "$CURSOR" -gt 1 ]            && CURSOR=$((CURSOR - 1)); }
cursor_down() { [ "$CURSOR" -lt "$CONN_COUNT" ] && CURSOR=$((CURSOR + 1)); }

# ─────────────────────── INPUT ───────────────────────────────────────────────
_ESC=$(printf '\033')

read_key() {
    KEY=""; ARROW=""
    # shellcheck disable=SC3045
    IFS= read -r -n 1 KEY 2>/dev/null || KEY=""
    [ -z "$KEY" ] && return 1

    if [ "$KEY" = "$_ESC" ]; then
        _b2=""; _b3=""
        # shellcheck disable=SC3045
        IFS= read -r -n 1 _b2 2>/dev/null || true
        # shellcheck disable=SC3045
        IFS= read -r -n 1 _b3 2>/dev/null || true
        if [ "$_b2" = "[" ]; then
            case "$_b3" in
                A) ARROW="up"    ;;
                B) ARROW="down"  ;;
                C) ARROW="right" ;;
                D) ARROW="left"  ;;
            esac
        fi
        KEY="ESC"
    fi
    return 0
}

# ─────────────────────── PROMPT ──────────────────────────────────────────────
_prompt_read() {
    _PROMPT_VAL=""
    stty_restore
    tput cnorm 2>/dev/null || true
    printf "  ${Y}%s${RST} " "$1"
    IFS= read -r _PROMPT_VAL 2>/dev/null || true
    tput civis 2>/dev/null || true
    _stty_raw_rearm
}

# ─────────────────────── ACTION DISPATCH ─────────────────────────────────────
handle_key() {
    case "$KEY" in
        ESC)
            case "$ARROW" in
                up)   cursor_up   ;;
                down) cursor_down ;;
            esac ;;
        k|K) cursor_up   ;;
        j|J) cursor_down ;;

        b|B)
            _pid=$(_sel_pid)
            if [ -z "$_pid" ]; then
                draw_ui
                printf "  ${Y}No PID on this row — use 'i' to block by IP.${RST}\n"
                sleep 1; return 0
            fi
            _exe=$(readlink -f "/proc/$_pid/exe" 2>/dev/null || printf '')
            _pid_name "$_pid"; _bname="$_G_NAME"
            _uid=$(awk '/^Uid:/{print $2;exit}' "/proc/$_pid/status" 2>/dev/null)
            draw_ui
            printf "  ${Y}Block:${RST} ${BOLD}%s${RST}  pid=%s  exe=%s\n" \
                "$_bname" "$_pid" "${_exe:-unknown}"
            _prompt_read "Confirm? [y/N]:"
            case "$_PROMPT_VAL" in y|Y)
                [ "$UFW" -eq 1 ] \
                    && ufw_block_ip "$(_sel_remote)" \
                    || block_exe "$_exe" "$_bname" "$_uid"
                sleep 1
            esac ;;

        i|I)
            _ip=$(_sel_remote)
            draw_ui
            printf "  ${Y}Block IP:${RST} ${BOLD}%s${RST}\n" "${_ip:-<none>}"
            _prompt_read "Enter IP (blank = use above):"
            [ -n "$_PROMPT_VAL" ] && _ip="$_PROMPT_VAL"
            [ "$UFW" -eq 1 ] && ufw_block_ip "$_ip" || block_ip "$_ip"
            sleep 1 ;;

        u|U)
            draw_ui; unblock_last; sleep 1 ;;

        f|F)
            draw_ui
            _prompt_read "Flush ALL blocks in '$CHAIN'? [y/N]:"
            case "$_PROMPT_VAL" in y|Y)
                flush_all
                printf "  ${G}✔ Flushed.${RST}\n"; sleep 1
            esac ;;

        q|Q) return 1 ;;
    esac
    return 0
}

# ─────────────────────── CLEANUP ─────────────────────────────────────────────
cleanup() {
    stty_restore
    tput cnorm 2>/dev/null || true
    rm -f "$TMPCONN" "$PIDCACHE" "$_PIDCACHE_MISS" "$_PRECACHE_FILE" "/tmp/tuifw_rf_$$"
    printf "\n${DIM}TUIFW exited. Chain '%s' rules persist.${RST}\n" "$CHAIN"
    printf "${DIM}To flush: iptables -F %s${RST}\n" "$CHAIN"
}
trap 'cleanup' INT TERM EXIT

# ─────────────────────── MAIN ────────────────────────────────────────────────
main() {
    [ "$(id -u)" -ne 0 ] && printf "${R}Error: must run as root.${RST}\n" && exit 1

    init_term
    stty_init_raw
    _detect_endian        # ELF-header based; must run before first _parse_proc
    detect_environment
    _probe_cmd_owner      # probe once; cleans up its own test rule immediately

    _TICK_MAX=$((UPDATE_INTERVAL * 10))
    _TICK=0

    enumerate_connections
    _preload_pid_cache    # warm cache before first draw
    _BLOCKS_DIRTY=1
    draw_ui

    while true; do
        if read_key; then
            handle_key || break
            _preload_pid_cache
            draw_ui
        fi

        _TICK=$((_TICK + 1))
        if [ "$_TICK" -ge "$_TICK_MAX" ]; then
            _TICK=0
            : > "$PIDCACHE"
            _BLOCKS_DIRTY=1
            enumerate_connections
            _preload_pid_cache
            draw_ui
        fi
    done
}

main "$@"
