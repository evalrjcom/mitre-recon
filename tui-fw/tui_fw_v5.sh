#!/bin/ash
# tui_fw_v5.sh — TinyWall-style TUI Firewall Manager
# POSIX ash / BusyBox compatible · Alpine Linux / LXC
# Requires: root, iptables (or active ufw); optional: ip6tables, ss (iproute2-ss)
#
# Usage:  sh tui_fw_v5.sh            interactive TUI
#         sh tui_fw_v5.sh --restore  re-apply saved rules, then exit (boot hook)
#         sh tui_fw_v5.sh --check    report drift (rule file vs firewall); exit 1 if any
#         sh tui_fw_v5.sh --install-boot | --uninstall-boot   persist rules across reboot
#         sh tui_fw_v5.sh --help | --version
#
# Env:    TUIFW_PROTECT="1.2.3.4 ..."  extra IPs that can never be blocked
#         TUIFW_ALLOW_ROOT_UID=1       allow uid-0 blocks (DANGEROUS: severs SSH)
#         TUIFW_BACKEND=auto|iptables|nft|ufw   force a backend (default auto)
#         TUIFW_DEADMAN=30             seconds before an unconfirmed block auto-reverts (0=off)
#         TUIFW_KILL_FLOWS=1           drop established flows when an IP is blocked (0=off)
#
# Changelog (changes are tagged "# v4:" / "# v5:" inline):
#   v1 original · v2 eval/probe-leak/perf fixes · v3 ELF endian detection
#   v4 owner-match chain split (v3 owner rules could never load), predictable-/tmp
#      root file clobber fixed, trap/INT fix, IPv6, lockout guards, persistence,
#      multi-level undo, viewport scrolling, 1-fork rendering, no tput dependency
#   v5 dead-man's switch (auto-revert unless confirmed), native nftables backend
#      (uid + cgroupv2 matching), conntrack/ss -K flow kill on block, boot hook
#      (--install-boot), drift detection + repair (d key, --check)

VERSION="v5"                                   # single bump point for banner/usage
SCRIPT_NAME="tui_fw_${VERSION}.sh"

# ─────────────────────── HARDENING ───────────────────────────────────────────
# v4: root script must not trust inherited PATH/IFS/umask/startup files.
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
IFS=$(printf ' \t\nx'); IFS="${IFS%x}"
umask 077
unset ENV BASH_ENV CDPATH 2>/dev/null

# ─────────────────────── CONSTANTS ───────────────────────────────────────────
CHAIN="TUIFW"            # IP rules: hooked from INPUT + OUTPUT
# v4: xt_owner is only valid on OUTPUT/POSTROUTING. In v3 the single TUIFW chain was
# also jumped from INPUT, so the kernel rejected every --cmd-owner/--uid-owner rule
# (EINVAL) and process blocking silently never worked. Owner rules get their own
# OUTPUT-only chain.
CHAIN_OUT="TUIFW_OUT"
RULEDIR="/var/lib/tuifw"
RULEFILE="$RULEDIR/rules"            # lines: type:value<TAB>label  (type: cmd|uid|ip|ufw)
LOCKDIR="$RULEDIR/lock"
UPDATE_INTERVAL=3        # seconds between connection-list refreshes
READ_TIMEOUT_DS=10       # key-poll timeout in tenths of a second (1 s tick)
MAX_ROWS=16              # visible connection rows (viewport height)
# v5: dead-man's switch window; a typo'd block can no longer lock you out for good
DEADMAN_SECS="${TUIFW_DEADMAN:-30}"
case "$DEADMAN_SECS" in ''|*[!0-9]*) DEADMAN_SECS=30 ;; esac
_NFT_T="tuifw"           # v5: nftables table (inet family: v4+v6 in one table)

_ESC=$(printf '\033')    # v4: real ESC byte so colours work in printf AND awk -v
R="${_ESC}[1;31m"  G="${_ESC}[1;32m"  Y="${_ESC}[1;33m"
C="${_ESC}[1;36m"  W="${_ESC}[1;37m"
DIM="${_ESC}[2m"   BOLD="${_ESC}[1m"  RST="${_ESC}[0m"
_TAB=$(printf '\t')

# v4: raw escape sequences — tput/terminfo no longer required (often absent on Alpine)
_T_HOME="${_ESC}[H"  _T_ED="${_ESC}[J"  _EL="${_ESC}[K"
_HIDE="${_ESC}[?25l" _SHOW="${_ESC}[?25h"
_ALT_ON="${_ESC}[?1049h" _ALT_OFF="${_ESC}[?1049l"   # v4: alternate screen, restores user's terminal

# ─────────────────────── GLOBAL STATE ────────────────────────────────────────
UFW=0
CURSOR=1
_TOP=0                   # v4: viewport offset (v3 let the cursor leave the 16 drawn rows)
CONN_COUNT=0
_RULE_COUNT=0
_MSG=""                  # v4: status line replaces printf+sleep 1 (UI no longer blocks)
_PROC_LE=1               # /proc/net/* byte order: 1=little-endian, 0=big-endian
_CMD_OWNER_SUPPORTED=""
_HAVE_IP6=0
BACKEND=""; NFT=0        # v5: iptables | nft | ufw
_CG_SUPPORTED=""
_PEND_MSG=""; _REV_EXIT=0
_DRIFT_MISSING=0; _DRIFT_EXTRA=0; _DRIFT_TICK=0
_rest_ok=0; _rest_bad=0
_STTY_SAVE=""
_TUI_ACTIVE=0
_HAVE_LOCK=0
_CLEANED=0
_REDRAW=0
_TICK=0
TMPD=""; TMPCONN=""; _FRAME=""; _INOMAP=""
_PENDING=""; _DRIFT_MISS=""; _DRIFT_XTRA=""; _EXPECT=""
NORM_IP=""; KEY=""; ARROW=""; _PROMPT_VAL=""; _C=""

# ─────────────────────── TEMP FILES / LOCK ───────────────────────────────────
# v4: SECURITY — v3 used /tmp/tuifw_*_$$ (predictable names) as root: a local user
# could pre-plant a symlink and make `: > $TMPCONN` truncate any file. Use a private
# 0700 directory instead (mktemp -d, or mkdir which fails if the path already exists).
_mk_tmpdir() {
    for _base in /run /tmp; do
        [ -d "$_base" ] && [ -w "$_base" ] || continue
        TMPD=$(mktemp -d "$_base/tuifw.XXXXXX" 2>/dev/null)
        [ -n "$TMPD" ] && [ -d "$TMPD" ] && break
        TMPD="$_base/tuifw.$$.$(date +%s 2>/dev/null)"
        mkdir "$TMPD" 2>/dev/null && break
        TMPD=""
    done
    [ -n "$TMPD" ] || return 1
    TMPCONN="$TMPD/conn"; _FRAME="$TMPD/frame"; _INOMAP="$TMPD/inomap"
    _PENDING="$TMPD/pending"; _DRIFT_MISS="$TMPD/dmiss"; _DRIFT_XTRA="$TMPD/dxtra"; _EXPECT="$TMPD/expect"
    : > "$_PENDING"
    return 0
}

# v4: single-instance lock (two instances raced on RULEFILE and the undo stack)
_acquire_lock() {
    mkdir -p "$RULEDIR" || return 1
    if mkdir "$LOCKDIR" 2>/dev/null; then
        printf '%s\n' "$$" > "$LOCKDIR/pid"; _HAVE_LOCK=1; return 0
    fi
    _op=$(cat "$LOCKDIR/pid" 2>/dev/null)
    if [ -n "$_op" ] && kill -0 "$_op" 2>/dev/null; then return 1; fi
    rm -rf "$LOCKDIR"                                  # stale lock from a dead PID
    mkdir "$LOCKDIR" 2>/dev/null || return 1
    printf '%s\n' "$$" > "$LOCKDIR/pid"; _HAVE_LOCK=1
    return 0
}

# ─────────────────────── ENDIANNESS ──────────────────────────────────────────
# /proc/net/* prints addresses in HOST byte order. v4 order of trust:
#   1. loopback in the data itself (ground truth, cannot disagree with the data)
#   2. ELF EI_DATA byte of a system binary
#   3. uname -m heuristic, default little-endian
_detect_endian() {
    for _f in /proc/net/tcp /proc/net/udp; do
        [ -r "$_f" ] || continue
        grep -q ' 0100007F:' "$_f" 2>/dev/null && { _PROC_LE=1; return 0; }
        grep -q ' 7F000001:' "$_f" 2>/dev/null && { _PROC_LE=0; return 0; }
    done
    for _bin in /bin/busybox /bin/sh /usr/bin/awk /bin/ls; do
        [ -r "$_bin" ] || continue
        _eidata=$(dd if="$_bin" bs=1 skip=5 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
        case "$_eidata" in
            01) _PROC_LE=1; return 0 ;;
            02) _PROC_LE=0; return 0 ;;
        esac
    done
    case "$(uname -m 2>/dev/null)" in      # v4: last-resort heuristic before the default
        mips|mips64|ppc|ppc64|s390x|sparc*|armeb|aarch64_be) _PROC_LE=0 ;;
        *) _PROC_LE=1 ;;
    esac
    return 0
}

# ─────────────────────── IP VALIDATION / NORMALISATION ───────────────────────
# v4: v3 accepted "1..2.3", "256.1.1.1" and ":::::". iptables uses inet_aton, so
# "010.0.0.1" would silently mean 8.0.0.1 — leading zeros are rejected too.
_validate_ip() {
    _vip="$1"
    case "$_vip" in
        '') return 1 ;;
        *[!0-9a-fA-F:.]*) return 1 ;;
    esac
    case "$_vip" in
        *:*)                                            # ---- IPv6 ----
            case "$_vip" in *.*) return 1 ;; esac
            case "$_vip" in :[!:]*|*[!:]:|*:::*) return 1 ;; esac
            _hdc=0
            case "$_vip" in
                *::*) _hdc=1; _t="${_vip#*::}"; case "$_t" in *::*) return 1 ;; esac ;;
            esac
            _ne=0; _ee=0
            _oIFS=$IFS; IFS=:; set -- $_vip; IFS=$_oIFS
            for _g in "$@"; do
                if [ -z "$_g" ]; then _ee=$((_ee + 1)); continue; fi
                [ "${#_g}" -le 4 ] || return 1
                _ne=$((_ne + 1))
            done
            if [ "$_hdc" -eq 1 ]; then
                [ "$_ne" -le 7 ] || return 1
            else
                [ "$_ee" -eq 0 ] && [ "$_ne" -eq 8 ] || return 1
            fi ;;
        *)                                              # ---- IPv4 ----
            case "$_vip" in *[!0-9.]*|.*|*.|*..*) return 1 ;; esac
            _oIFS=$IFS; IFS=.; set -- $_vip; IFS=$_oIFS
            [ "$#" -eq 4 ] || return 1
            for _o in "$@"; do
                case "$_o" in ''|*[!0-9]*|0?*) return 1 ;; esac
                [ "${#_o}" -le 3 ] && [ "$_o" -le 255 ] || return 1
            done ;;
    esac
    return 0
}

# v4: v3's `${1%%:*}` turned every IPv6 address into "" or "[2001"; ss zone IDs
# (fe80::1%eth0) and v4-mapped ([::ffff:1.2.3.4]) were also passed to iptables raw.
# Result goes in $NORM_IP (no subshell).
_norm_addr() {
    _na="$1"
    case "$_na" in
        \[*\]*) _na="${_na#\[}"; _na="${_na%%\]*}" ;;   # [v6]:port  or [v6]
        *:*:*)  : ;;                                    # bare IPv6, no port
        *:*)    _na="${_na%%:*}" ;;                     # v4:port
    esac
    _na="${_na%%\%*}"                                   # strip zone id
    case "$_na" in ::[fF][fF][fF][fF]:*.*.*.*) _na="${_na#::[fF][fF][fF][fF]:}" ;; esac
    NORM_IP="$_na"
}

# v5: RFC 5952 canonical form (lowercase, no leading zeros, longest zero run -> ::).
# The kernel prints addresses this way, so records and drift comparison must match it.
_canon_ip() {
    case "$1" in
        *:*) NORM_IP=$(printf '%s' "$1" | awk '{
                s = tolower($0); i = index(s, "::")
                if (i) {
                    l = substr(s, 1, i - 1); r = substr(s, i + 2)
                    nl = (l == "") ? 0 : split(l, a, ":"); nr = (r == "") ? 0 : split(r, b, ":")
                    k = 0
                    for (j = 1; j <= nl; j++) g[++k] = a[j]
                    for (j = 1; j <= 8 - nl - nr; j++) g[++k] = "0"
                    for (j = 1; j <= nr; j++) g[++k] = b[j]
                } else split(s, g, ":")
                for (j = 1; j <= 8; j++) { sub(/^0+/, "", g[j]); if (g[j] == "") g[j] = "0" }
                best = 0; bs = 0; cur = 0; cs = 0
                for (j = 1; j <= 8; j++) {
                    if (g[j] == "0") { if (!cur) cs = j; cur++; if (cur > best) { best = cur; bs = cs } } else cur = 0
                }
                if (best < 2) bs = 0
                out = ""
                for (j = 1; j <= 8; j++) {
                    if (bs && j == bs) { out = out "::"; j += best - 1; continue }
                    if (out != "" && substr(out, length(out)) != ":") out = out ":"
                    out = out g[j]
                }
                print out }') ;;
        *) NORM_IP="$1" ;;
    esac
}

# v4: lockout guard — never block loopback, unspecified, the current SSH peer, or
# anything the admin lists in TUIFW_PROTECT.
_is_protected() {
    case "$1" in 127.*|::1|0.0.0.0|::|'') return 0 ;; esac
    _canon_ip "$1"; _pc="$NORM_IP"                  # v5: compare canonical forms (v6 spelling)
    _pl="${TUIFW_PROTECT:-}"
    [ -n "${SSH_CONNECTION:-}" ] && _pl="$_pl ${SSH_CONNECTION%% *}"
    [ -n "${SSH_CLIENT:-}" ]     && _pl="$_pl ${SSH_CLIENT%% *}"
    for _p in $_pl; do
        _canon_ip "$_p"
        [ "$NORM_IP" = "$_pc" ] && return 0
    done
    return 1
}

_valid_comm() {   # kernel comm: <=15 chars; reject anything unsafe in an iptables arg
    [ -n "$1" ] || return 1
    case "$1" in *[!A-Za-z0-9._-]*) return 1 ;; esac
    [ "${#1}" -le 15 ] || return 1
    return 0
}

# ─────────────────────── FIREWALL BACKEND ────────────────────────────────────
_hook_chain() {   # $1 = iptables|ip6tables
    "$1" -N "$CHAIN"     2>/dev/null || true
    "$1" -N "$CHAIN_OUT" 2>/dev/null || true
    "$1" -C OUTPUT -j "$CHAIN"     2>/dev/null || "$1" -I OUTPUT 1 -j "$CHAIN"     2>/dev/null || return 1
    "$1" -C INPUT  -j "$CHAIN"     2>/dev/null || "$1" -I INPUT  1 -j "$CHAIN"     2>/dev/null || return 1
    "$1" -C OUTPUT -j "$CHAIN_OUT" 2>/dev/null || "$1" -I OUTPUT 1 -j "$CHAIN_OUT" 2>/dev/null || return 1
    return 0
}

detect_environment() {
    UFW=0; NFT=0; BACKEND=""
    _want="${TUIFW_BACKEND:-auto}"
    case "$_want" in auto|iptables|nft|ufw) ;; *) printf '%s\n' "Error: TUIFW_BACKEND must be auto|iptables|nft|ufw." >&2; return 1 ;; esac
    if [ "$_want" = auto ] || [ "$_want" = ufw ]; then
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw active; then BACKEND=ufw; fi
    fi
    if [ -z "$BACKEND" ] && { [ "$_want" = auto ] || [ "$_want" = iptables ]; }; then
        if command -v iptables >/dev/null 2>&1 && _hook_chain iptables; then
            BACKEND=iptables; _HAVE_IP6=0                # v4: IPv6 chains (best effort)
            if command -v ip6tables >/dev/null 2>&1 && _hook_chain ip6tables; then _HAVE_IP6=1; fi
        fi
    fi
    # v5: native nftables when iptables is absent or cannot be programmed
    if [ -z "$BACKEND" ] && { [ "$_want" = auto ] || [ "$_want" = nft ]; }; then
        if command -v nft >/dev/null 2>&1 && _nft_init; then BACKEND=nft; fi
    fi
    if [ -z "$BACKEND" ]; then
        printf '%s\n' "Error: no usable backend (need iptables, nft or active ufw; root/CAP_NET_ADMIN required)." >&2
        return 1
    fi
    case "$BACKEND" in ufw) UFW=1 ;; nft) NFT=1 ;; esac
    mkdir -p "$RULEDIR" && touch "$RULEFILE" && chmod 600 "$RULEFILE" 2>/dev/null
    return 0
}

# v4: probe ONCE against the OUTPUT-only chain; the probe rule is always removed.
_probe_cmd_owner() {
    [ -n "$_CMD_OWNER_SUPPORTED" ] && return 0
    _CMD_OWNER_SUPPORTED=0; _CG_SUPPORTED=0
    case "$BACKEND" in
        iptables)
            if iptables -A "$CHAIN_OUT" -m owner --cmd-owner _tuifw_probe_ -j REJECT 2>/dev/null; then
                iptables -D "$CHAIN_OUT" -m owner --cmd-owner _tuifw_probe_ -j REJECT 2>/dev/null || true
                _CMD_OWNER_SUPPORTED=1
            fi ;;
        nft)
            # v5: dry-run (-c) with our OWN cgroup path: validates the syntax and that the
            # kernel has cgroupv2 socket matching, without ever installing a live rule.
            _ocg=$(awk -F: '$1=="0"{print $3; exit}' "/proc/$$/cgroup" 2>/dev/null)
            case "$_ocg" in
                /?*)
                    _rel="${_ocg#/}"
                    _cd=$(printf '%s' "$_rel" | tr -cd '/' | wc -c); _cd=$((_cd + 1))
                    if printf '%s\n' "add rule inet $_NFT_T out socket cgroupv2 level $_cd \"$_rel\" reject" \
                        | nft -c -f - >/dev/null 2>&1; then _CG_SUPPORTED=1; fi ;;
            esac ;;
    esac
    return 0
}

# v4: ONE function builds the rule for add (-A), delete (-D) and check (-C), so the
# three can never drift apart (v3 added without --reject-with in one path and deleted
# with it in another). Every value is re-validated here, so a tampered RULEFILE can
# not inject arguments when rules are restored as root.
_rule_apply() {   # $1=-A|-D|-C  $2=type  $3=value
    _ro="$1"; _rt="$2"; _rv="$3"; _rrc=0
    if [ "$NFT" -eq 1 ]; then _nft_apply "$_ro" "$_rt" "$_rv"; return $?; fi   # v5
    case "$_rt" in
        cmd|uid)
            if [ "$_rt" = cmd ]; then
                _valid_comm "$_rv" || return 1; _rm="--cmd-owner"
            else
                case "$_rv" in ''|*[!0-9]*) return 1 ;; esac; _rm="--uid-owner"
            fi
            for _x in iptables ip6tables; do
                [ "$_x" = ip6tables ] && [ "$_HAVE_IP6" -ne 1 ] && continue
                # shellcheck disable=SC2086
                if ! "$_x" "$_ro" "$CHAIN_OUT" -m owner $_rm "$_rv" -j REJECT 2>/dev/null; then
                    [ "$_x" = iptables ] && _rrc=1          # IPv6 side is best-effort
                fi
            done
            return "$_rrc" ;;
        ip)
            _validate_ip "$_rv" || return 1
            _canon_ip "$_rv"; _rv="$NORM_IP"                 # v5: one spelling everywhere (rule, record, drift)
            case "$_rv" in
                *:*) [ "$_HAVE_IP6" -eq 1 ] || return 1; _x=ip6tables ;;
                *)   _x=iptables ;;
            esac
            "$_x" "$_ro" "$CHAIN" -s "$_rv" -j REJECT 2>/dev/null || _rrc=1
            "$_x" "$_ro" "$CHAIN" -d "$_rv" -j REJECT 2>/dev/null || _rrc=$((_rrc + 2))
            if [ "$_ro" = "-A" ] && [ "$_rrc" -ne 0 ]; then       # v4: no half-installed rule
                "$_x" -D "$CHAIN" -s "$_rv" -j REJECT 2>/dev/null
                "$_x" -D "$CHAIN" -d "$_rv" -j REJECT 2>/dev/null
            fi
            [ "$_rrc" -eq 0 ] ;;
        ufw)
            _validate_ip "$_rv" || return 1
            case "$_ro" in
                -A) ufw insert 1 deny from "$_rv" >/dev/null 2>&1 || ufw deny from "$_rv" >/dev/null 2>&1 || return 1
                    ufw insert 1 deny out to "$_rv" >/dev/null 2>&1 || ufw deny out to "$_rv" >/dev/null 2>&1 ;;
                -D) ufw --force delete deny from "$_rv" >/dev/null 2>&1; _rrc=$?
                    ufw --force delete deny out to "$_rv" >/dev/null 2>&1
                    return "$_rrc" ;;
                -C) ufw status 2>/dev/null | grep DENY | grep -qF -- "$_rv" ;;
            esac ;;
        *) return 1 ;;
    esac
}

_count_rules() {
    set -- $(wc -l < "$RULEFILE" 2>/dev/null)
    _RULE_COUNT="${1:-0}"
    case "$_RULE_COUNT" in ''|*[!0-9]*) _RULE_COUNT=0 ;; esac
}

# v4: rules were never reloaded in v3 (RULEFILE was write-only). Idempotent via -C.
_restore_rules() {
    _rest_ok=0; _rest_bad=0
    [ -s "$RULEFILE" ] || return 0
    while IFS="$_TAB" read -r _key _lbl; do
        [ -n "$_key" ] || continue
        _rt="${_key%%:*}"; _rv="${_key#*:}"
        if _rule_apply -C "$_rt" "$_rv" || _rule_apply -A "$_rt" "$_rv"; then
            _rest_ok=$((_rest_ok + 1))
        else
            _rest_bad=$((_rest_bad + 1))
        fi
    done < "$RULEFILE"
    return 0
}

_block() {   # $1=type $2=value $3=label (label already sanitised)
    _bt="$1"; _bv="$2"; _bl="$3"
    if _rule_apply -C "$_bt" "$_bv"; then
        _MSG="${Y}Already blocked: ${_bv}${RST}"; return 0
    fi
    if _rule_apply -A "$_bt" "$_bv"; then
        printf '%s:%s\t%s\n' "$_bt" "$_bv" "$_bl" >> "$RULEFILE"
        _count_rules
        _MSG="${R}✖ Blocked${RST} ${_bt}:${_bv} (${_bl})"
        _kill_flows "$_bt" "$_bv"                       # v5
        _pending_add "${_bt}:${_bv}"                    # v5: dead-man's switch
    else
        _MSG="${Y}Failed to add ${_bt}:${_bv} — check kernel/iptables support.${RST}"
    fi
    return 0
}

# v4: undo is now a real stack backed by RULEFILE (v3 remembered only ONE rule and
# desynced RULEFILE from iptables on the second undo).
unblock_last() {
    if [ ! -s "$RULEFILE" ]; then _MSG="${Y}Nothing to unblock.${RST}"; return 0; fi
    _line=$(tail -n 1 "$RULEFILE")
    _key="${_line%%"$_TAB"*}"
    _rt="${_key%%:*}"; _rv="${_key#*:}"
    if _rule_apply -D "$_rt" "$_rv"; then
        _MSG="${G}✔ Unblocked ${_rt}:${_rv}${RST}"
    else
        _MSG="${Y}Rule ${_rt}:${_rv} not present in firewall (record removed).${RST}"
    fi
    sed '$d' "$RULEFILE" > "$RULEDIR/rules.new" && mv -f "$RULEDIR/rules.new" "$RULEFILE"
    _pending_drop "$_key"                               # v5: undo also cancels its countdown
    _count_rules
    return 0
}

flush_all() {
    while IFS="$_TAB" read -r _key _lbl; do                 # v4: also removes ufw rules we added
        [ -n "$_key" ] || continue
        _rule_apply -D "${_key%%:*}" "${_key#*:}" 2>/dev/null
    done < "$RULEFILE"
    case "$BACKEND" in
        iptables)
            iptables -F "$CHAIN" 2>/dev/null; iptables -F "$CHAIN_OUT" 2>/dev/null
            if [ "$_HAVE_IP6" -eq 1 ]; then
                ip6tables -F "$CHAIN" 2>/dev/null; ip6tables -F "$CHAIN_OUT" 2>/dev/null
            fi ;;
        nft)    # v5
            nft flush chain inet "$_NFT_T" in 2>/dev/null; nft flush chain inet "$_NFT_T" out 2>/dev/null ;;
    esac
    : > "$RULEFILE"; : > "$_PENDING"; _PEND_MSG=""
    _count_rules
    _MSG="${G}✔ Flushed all TUIFW rules.${RST}"
    return 0
}

# ─────────────────────── v5: NFTABLES BACKEND ────────────────────────────────
# One `inet` table covers IPv4+IPv6. Every rule carries comment "tuifw:<type>:<value>",
# which is how -C (check), -D (delete by handle) and drift listing find it again.
# nft has no per-process-name match: process blocks use cgroupv2 (precise, whole service)
# when available, else uid.
_nft_init() {
    printf '%s\n' \
        "add table inet $_NFT_T" \
        "add chain inet $_NFT_T in { type filter hook input priority -10 ; policy accept ; }" \
        "add chain inet $_NFT_T out { type filter hook output priority -10 ; policy accept ; }" \
        | nft -f - >/dev/null 2>&1
}

_nft_handles() {   # $1=chain $2=type:value  -> rule handles, one per line
    nft -a list chain inet "$_NFT_T" "$1" 2>/dev/null | awk -v c="\"tuifw:$2\"" '
        index($0, c) { for (i = 1; i < NF; i++) if ($i == "handle") print $(i + 1) }'
}

_nft_apply() {   # $1=-A|-D|-C  $2=type  $3=value   (validates like _rule_apply)
    _no="$1"; _nt="$2"; _nv="$3"
    case "$_nt" in
        ip)  _validate_ip "$_nv" || return 1
             _canon_ip "$_nv"; _nv="$NORM_IP"                # v5: comment text must equal the canonical form
             _nch="in out" ;;
        uid) case "$_nv" in ''|*[!0-9]*) return 1 ;; esac; _nch="out" ;;
        cg)  case "$_nv" in /?*) ;; *) return 1 ;; esac
             case "$_nv" in *[!A-Za-z0-9._/-]*|*//*|*/..|*/../*) return 1 ;; esac
             _nch="out" ;;
        *)   return 1 ;;
    esac
    _nk="$_nt:$_nv"
    case "$_no" in
        -C) for _c in $_nch; do [ -n "$(_nft_handles "$_c" "$_nk")" ] || return 1; done
            return 0 ;;
        -D) _nd=1
            for _c in $_nch; do
                for _h in $(_nft_handles "$_c" "$_nk"); do
                    nft delete rule inet "$_NFT_T" "$_c" handle "$_h" 2>/dev/null && _nd=0
                done
            done
            return "$_nd" ;;
        -A) case "$_nt" in
                ip)
                    case "$_nv" in *:*) _nf=ip6 ;; *) _nf=ip ;; esac
                    # one nft transaction: both directions or neither (no half-installed rule)
                    printf '%s\n' \
                        "add rule inet $_NFT_T in $_nf saddr $_nv reject comment \"tuifw:$_nk\"" \
                        "add rule inet $_NFT_T out $_nf daddr $_nv reject comment \"tuifw:$_nk\"" \
                        | nft -f - >/dev/null 2>&1 ;;
                uid)
                    printf '%s\n' "add rule inet $_NFT_T out meta skuid $_nv reject comment \"tuifw:$_nk\"" \
                        | nft -f - >/dev/null 2>&1 ;;
                cg)
                    _rel="${_nv#/}"
                    _cd=$(printf '%s' "$_rel" | tr -cd '/' | wc -c); _cd=$((_cd + 1))
                    printf '%s\n' "add rule inet $_NFT_T out socket cgroupv2 level $_cd \"$_rel\" reject comment \"tuifw:$_nk\"" \
                        | nft -f - >/dev/null 2>&1 ;;
            esac
            return $? ;;
    esac
    return 1
}

# v5: never block a cgroup that contains this very session (would cut our own SSH)
_cg_safe() {
    case "$1" in /?*) ;; *) return 1 ;; esac
    case "$1" in *[!A-Za-z0-9._/-]*|*//*|*/..|*/../*) return 1 ;; esac
    _own=$(awk -F: '$1=="0"{print $3; exit}' "/proc/$$/cgroup" 2>/dev/null)
    [ "$_own" = "$1" ] && return 1
    case "$_own" in "$1"/*) return 1 ;; esac
    return 0
}

# ─────────────────────── v5: DEAD-MAN'S SWITCH ───────────────────────────────
# A new block auto-reverts after DEADMAN_SECS unless confirmed with 'c'. If you block
# something that kills your own connectivity you simply wait; nothing to repair.
_rf_remove() {   # remove the newest RULEFILE record whose key == $1
    awk -F"$_TAB" -v k="$1" '{ l[NR] = $0; f[NR] = $1 }
        END { d = 0; for (i = NR; i >= 1; i--) if (f[i] == k) { d = i; break }
              for (i = 1; i <= NR; i++) if (i != d) print l[i] }' "$RULEFILE" > "$RULEDIR/rules.new" \
        && mv -f "$RULEDIR/rules.new" "$RULEFILE"
    _count_rules
}

_pending_add() {   # $1 = type:value
    [ "$_TUI_ACTIVE" -eq 1 ] && [ "$DEADMAN_SECS" -gt 0 ] || return 0
    printf '%s\t%s\n' "$1" $(( $(date +%s) + DEADMAN_SECS )) >> "$_PENDING"
    _MSG="${_MSG} ${Y}— auto-reverts in ${DEADMAN_SECS}s, press c to keep${RST}"
}

_pending_drop() {
    [ -s "$_PENDING" ] || return 0
    awk -F"$_TAB" -v k="$1" '$1 != k' "$_PENDING" > "$_PENDING.new" && mv -f "$_PENDING.new" "$_PENDING"
}

_pending_revert() {
    _rrt="${1%%:*}"; _rrv="${1#*:}"
    _rule_apply -D "$_rrt" "$_rrv"
    _rf_remove "$1"
    _pending_drop "$1"
}

# returns 0 when the screen should be redrawn (countdown visible or something reverted)
_pending_tick() {
    _PEND_MSG=""
    [ -s "$_PENDING" ] || return 1
    _now=$(date +%s)
    _exp=$(awk -F"$_TAB" -v n="$_now" '$2 <= n { print $1 }' "$_PENDING")
    for _k in $_exp; do
        _pending_revert "$_k"
        _MSG="${Y}⏪ Auto-reverted ${_k} (not confirmed in time).${RST}"
    done
    if [ -s "$_PENDING" ]; then
        set -- $(awk -F"$_TAB" -v n="$_now" 'NR == 1 || $2 < m { m = $2 } END { print NR, m - n }' "$_PENDING")
        _PEND_MSG="⏳ $1 unconfirmed block(s); oldest reverts in ${2}s — press c to keep"
    fi
    return 0
}

# ─────────────────────── v5: FLOW KILL ───────────────────────────────────────
# REJECT stops NEW packets, but conntrack keeps ESTABLISHED flows alive (and they resume
# if the block is later reverted). Drop them explicitly; both tools are optional.
_kill_flows() {   # $1=type $2=value
    [ "${TUIFW_KILL_FLOWS:-1}" = "1" ] || return 0
    case "$1" in ip|ufw) ;; *) return 0 ;; esac
    case "$2" in *:*) _fam=ipv6 ;; *) _fam=ipv4 ;; esac
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -D -f "$_fam" -s "$2" >/dev/null 2>&1
        conntrack -D -f "$_fam" -d "$2" >/dev/null 2>&1
    fi
    if command -v ss >/dev/null 2>&1; then          # needs CONFIG_INET_DIAG_DESTROY; silent if absent
        ss -K dst "$2" >/dev/null 2>&1
        ss -K src "$2" >/dev/null 2>&1
    fi
    return 0
}

# ─────────────────────── v5: DRIFT DETECTION ─────────────────────────────────
# Compares RULEFILE (what we think is installed) with the live firewall:
#   missing  = recorded but not present (flushed/reloaded by something else)
#   extra    = present in TUIFW chains/table but not recorded (manual edits)
_kernel_set() {   # canonical "type:value", one per line, for every TUIFW rule in the firewall
    case "$BACKEND" in
        nft)
            for _kc in in out; do nft list chain inet "$_NFT_T" "$_kc" 2>/dev/null; done |
                awk 'match($0, /comment "tuifw:[^"]+"/) { print substr($0, RSTART + 15, RLENGTH - 16) }' ;;
        iptables)
            { for _kc in "$CHAIN" "$CHAIN_OUT"; do
                  iptables -S "$_kc" 2>/dev/null
                  if [ "$_HAVE_IP6" -eq 1 ]; then ip6tables -S "$_kc" 2>/dev/null; fi
              done; } |
                awk '/^-A/ && !/_tuifw_probe_/ {
                    for (i = 1; i < NF; i++) {
                        if ($i == "-s" || $i == "-d") { v = $(i + 1); sub(/\/(32|128)$/, "", v); print "ip:" v }
                        else if ($i == "--uid-owner") print "uid:" $(i + 1)
                        else if ($i == "--cmd-owner") { v = $(i + 1); gsub(/"/, "", v); print "cmd:" v }
                    } }' ;;
    esac | sort -u
}

_drift_check() {
    : > "$_DRIFT_MISS"; : > "$_DRIFT_XTRA"; : > "$_EXPECT"
    if [ -s "$RULEFILE" ]; then
        while IFS="$_TAB" read -r _key _lbl; do
            [ -n "$_key" ] || continue
            _dt="${_key%%:*}"; _dv="${_key#*:}"
            _rule_apply -C "$_dt" "$_dv" || printf '%s\n' "$_key" >> "$_DRIFT_MISS"
            if [ "$_dt" = ip ]; then _canon_ip "$_dv"; _dv="$NORM_IP"; fi
            printf '%s:%s\n' "$_dt" "$_dv" >> "$_EXPECT"
        done < "$RULEFILE"
    fi
    if [ "$UFW" -eq 0 ]; then                       # ufw has no private chain to enumerate
        if [ -s "$_EXPECT" ]; then
            _kernel_set | grep -vxF -f "$_EXPECT" > "$_DRIFT_XTRA" 2>/dev/null
        else
            _kernel_set > "$_DRIFT_XTRA"
        fi
    fi
    set -- $(wc -l < "$_DRIFT_MISS"); _DRIFT_MISSING="${1:-0}"
    set -- $(wc -l < "$_DRIFT_XTRA"); _DRIFT_EXTRA="${1:-0}"
    return 0
}

action_drift() {
    _drift_check
    if [ "$_DRIFT_MISSING" -eq 0 ] && [ "$_DRIFT_EXTRA" -eq 0 ]; then
        _MSG="${G}✔ No drift: firewall matches the rule file.${RST}"; return 0
    fi
    draw_ui
    printf "  ${Y}Drift:${RST} %s missing from firewall, %s unrecorded in firewall\n" "$_DRIFT_MISSING" "$_DRIFT_EXTRA"
    sed -n '1,3s/^/    missing   /p' "$_DRIFT_MISS"
    sed -n '1,3s/^/    unrecorded /p' "$_DRIFT_XTRA"
    _prompt_read "[r] re-apply missing  [a] adopt unrecorded  [x] delete unrecorded  [Enter] cancel:"
    case "$_PROMPT_VAL" in
        r|R) _n=0
             for _k in $(cat "$_DRIFT_MISS"); do _rule_apply -A "${_k%%:*}" "${_k#*:}" && _n=$((_n + 1)); done
             _MSG="${G}Re-applied ${_n} rule(s).${RST}" ;;
        a|A) _n=0
             for _k in $(cat "$_DRIFT_XTRA"); do printf '%s\tadopted\n' "$_k" >> "$RULEFILE"; _n=$((_n + 1)); done
             _count_rules; _MSG="${G}Adopted ${_n} rule(s) into the rule file.${RST}" ;;
        x|X) _n=0
             for _k in $(cat "$_DRIFT_XTRA"); do _rule_apply -D "${_k%%:*}" "${_k#*:}" && _n=$((_n + 1)); done
             _MSG="${G}Deleted ${_n} unrecorded rule(s).${RST}" ;;
        *)   _MSG="${DIM}Cancelled.${RST}" ;;
    esac
    _drift_check
    return 0
}

# ─────────────────────── v5: BOOT PERSISTENCE ───────────────────────────────
# The hook runs a root-owned COPY under /usr/local/sbin, never the file you launched:
# a boot-time root job must not point at a user-writable path (privilege escalation).
install_boot() {
    _sp=$(readlink -f "$0" 2>/dev/null)
    if [ -z "$_sp" ] || [ ! -f "$_sp" ]; then printf '%s\n' "Error: cannot resolve script path." >&2; return 1; fi
    _dst="/usr/local/sbin/$SCRIPT_NAME"
    mkdir -p /usr/local/sbin || return 1
    if [ "$_sp" != "$_dst" ]; then
        cp "$_sp" "$_dst.new" && chmod 755 "$_dst.new" && mv -f "$_dst.new" "$_dst" || return 1
    fi
    chown root:root "$_dst" 2>/dev/null
    for _o in /usr/local/sbin/tui_fw_v[0-9]*.sh; do          # drop copies of older versions
        [ -e "$_o" ] && [ "$_o" != "$_dst" ] && rm -f "$_o"
    done
    if [ -d /run/systemd/system ]; then
        printf '%s\n' "[Unit]" "Description=Re-apply TUIFW firewall rules" "After=network-pre.target" "Before=network.target" \
            "" "[Service]" "Type=oneshot" "RemainAfterExit=yes" "ExecStart=$_dst --restore" \
            "" "[Install]" "WantedBy=multi-user.target" > /etc/systemd/system/tuifw-restore.service
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable tuifw-restore.service >/dev/null 2>&1
        printf '%s\n' "Installed systemd unit tuifw-restore.service -> $_dst --restore"
    elif [ -d /etc/local.d ] || command -v rc-update >/dev/null 2>&1; then
        mkdir -p /etc/local.d
        printf '%s\n' '#!/bin/sh' "# managed by $SCRIPT_NAME: re-apply saved TUIFW rules at boot" "exec $_dst --restore" \
            > /etc/local.d/tuifw.start
        chmod 755 /etc/local.d/tuifw.start
        command -v rc-update >/dev/null 2>&1 && rc-update add local default >/dev/null 2>&1
        printf '%s\n' "Installed OpenRC hook /etc/local.d/tuifw.start -> $_dst --restore"
    else
        printf '%s\n' "Copied to $_dst, but no OpenRC local.d or systemd found: call '$_dst --restore' from your init." >&2
        return 1
    fi
    return 0
}

uninstall_boot() {
    rm -f /etc/local.d/tuifw.start
    if [ -f /etc/systemd/system/tuifw-restore.service ]; then
        systemctl disable tuifw-restore.service >/dev/null 2>&1
        rm -f /etc/systemd/system/tuifw-restore.service
        systemctl daemon-reload >/dev/null 2>&1
    fi
    rm -f /usr/local/sbin/tui_fw_v[0-9]*.sh
    printf '%s\n' "Boot hook removed (saved rules in $RULEFILE are kept)."
    return 0
}

# ─────────────────────── CONNECTION ENUMERATION ──────────────────────────────
# Output (tab-separated): proto  local  remote  pid
# v4: v3 collected every "addr:port" token, so unconnected UDP rows (peer "0.0.0.0:*"
# has no numeric port) showed remote == local. Use fixed ss columns 5/6 instead.
_parse_ss() {
    ss -tunp 2>/dev/null | awk '
    NR == 1 { next }
    NF < 6  { next }
    {
        proto = $1
        if (proto != "tcp" && proto != "udp") next
        loc = $5; rem = $6
        if (substr(loc, 1, 1) == "[") proto = proto "6"
        pid = ""
        p = index($0, "pid=")
        if (p > 0) { rest = substr($0, p + 4); if (match(rest, /^[0-9]+/)) pid = substr(rest, 1, RLENGTH) }
        printf "%s\t%s\t%s\t%s\n", proto, loc, rem, pid
    }'
}

# v4: /proc fallback now covers tcp6/udp/udp6 (v3 silently skipped every IPv6 row),
# skips LISTEN sockets (matches ss), and maps socket inode -> PID with ONE ls call.
_parse_proc() {
    ls -l /proc/[0-9]*/fd/ 2>/dev/null | awk '
        /^\/proc\/[0-9]+\/fd\/?:$/ { split($0, h, "/"); pid = h[3]; next }
        { if (match($0, /socket:\[[0-9]+\]/)) m[substr($0, RSTART + 8, RLENGTH - 9)] = pid }
        END { for (i in m) printf "%s\t%s\n", i, m[i] }' > "$_INOMAP"
    for _pf in tcp tcp6 udp udp6; do
        [ -r "/proc/net/$_pf" ] || continue
        awk -v proto="$_pf" -v le="$_PROC_LE" -v mapf="$_INOMAP" '
        BEGIN {
            while ((getline l < mapf) > 0) { split(l, a, "\t"); ino[a[1]] = a[2] }
            close(mapf)
        }
        function hv(s,   i, v) {
            v = 0
            for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", tolower(substr(s, i, 1))) - 1
            return v
        }
        function sw(w) {                      # one host-order 32-bit word -> network order
            return (le == 1) ? substr(w,7,2) substr(w,5,2) substr(w,3,2) substr(w,1,2) : w
        }
        function dq(n) { return hv(substr(n,1,2)) "." hv(substr(n,3,2)) "." hv(substr(n,5,2)) "." hv(substr(n,7,2)) }
        function addr(f,   p, h, port, net, i, g, out) {
            split(f, p, ":"); h = p[1]; port = hv(p[2])
            if (length(h) == 8) {
                if (h == "00000000" && port == 0) return "*:*"
                return dq(sw(h)) ":" port
            }
            if (length(h) == 32) {
                net = tolower(sw(substr(h,1,8)) sw(substr(h,9,8)) sw(substr(h,17,8)) sw(substr(h,25,8)))
                if (net ~ /^0+$/ && port == 0) return "*:*"
                if (substr(net, 1, 24) == "00000000000000000000ffff") return dq(substr(net, 25, 8)) ":" port
                out = ""
                for (i = 0; i < 8; i++) {
                    g = substr(net, i * 4 + 1, 4); sub(/^0+/, "", g); if (g == "") g = "0"
                    out = out (i ? ":" : "") g
                }
                return "[" out "]:" port
            }
            return "?:0"
        }
        NR == 1 || NF < 10 { next }
        proto ~ /^tcp/ && $4 == "0A" { next }
        { printf "%s\t%s\t%s\t%s\n", proto, addr($2), addr($3), (($10) in ino) ? ino[$10] : "" }
        ' "/proc/net/$_pf"
    done
}

enumerate_connections() {
    # v4: keep the selected connection selected across refreshes (rows are sorted so
    # their order is stable; v3 let the cursor drift onto a different socket).
    _selkey=$(awk -F"$_TAB" -v r="$CURSOR" 'NR==r{print $1 FS $2 FS $3; exit}' "$TMPCONN" 2>/dev/null)
    : > "$TMPCONN.new"
    if command -v ss >/dev/null 2>&1; then
        _parse_ss | sort -t "$_TAB" -k1,1 -k2,2 -k3,3 > "$TMPCONN.new"
    fi
    if [ ! -s "$TMPCONN.new" ]; then
        _parse_proc | sort -t "$_TAB" -k1,1 -k2,2 -k3,3 > "$TMPCONN.new"
    fi
    mv -f "$TMPCONN.new" "$TMPCONN"
    set -- $(wc -l < "$TMPCONN")
    CONN_COUNT="${1:-0}"
    case "$CONN_COUNT" in ''|*[!0-9]*) CONN_COUNT=0 ;; esac
    if [ -n "$_selkey" ]; then
        _found=$(awk -F"$_TAB" -v k="$_selkey" '($1 FS $2 FS $3)==k{print NR; exit}' "$TMPCONN")
        [ -n "$_found" ] && CURSOR="$_found"
    fi
    _fix_view
}

_fix_view() {     # keep CURSOR in range and inside the viewport
    [ "$CURSOR" -gt "$CONN_COUNT" ] && CURSOR="$CONN_COUNT"
    [ "$CURSOR" -lt 1 ] && CURSOR=1
    [ "$CURSOR" -le "$_TOP" ] && _TOP=$((CURSOR - 1))
    [ "$CURSOR" -gt $((_TOP + MAX_ROWS)) ] && _TOP=$((CURSOR - MAX_ROWS))
    [ "$_TOP" -lt 0 ] && _TOP=0
    return 0
}

# ─────────────────────── PROCESS HELPERS (action path only) ──────────────────
_pid_name() {
    _G_NAME="?"
    [ -n "$1" ] && [ -r "/proc/$1/comm" ] || return 0
    IFS= read -r _G_NAME 2>/dev/null < "/proc/$1/comm" || _G_NAME="?"   # v4: stderr redirect now precedes the failing <
    _G_NAME=$(printf '%s' "$_G_NAME" | tr -cd 'A-Za-z0-9._-')
    [ -n "$_G_NAME" ] || _G_NAME="?"
    return 0
}

# ─────────────────────── DRAW ────────────────────────────────────────────────
# v4: the whole frame is built in a file and written once (+ one sed to add
# clear-to-EOL). v3 did `tput ed` first, then drew line by line => visible flicker.
draw_ui() {
    { _draw_header; _draw_keys; _draw_connections; _draw_blocks; _draw_status; } > "$_FRAME"
    printf '%s' "$_T_HOME"
    sed "s/\$/${_EL}/" "$_FRAME"
    printf '%s' "$_T_ED"
}

_draw_header() {
    case "$BACKEND" in
        iptables) _be="iptables/${CHAIN}+${CHAIN_OUT}" ;;
        nft)      _be="nft/inet ${_NFT_T}" ;;
        *)        _be="$BACKEND" ;;
    esac
    if [ "$_DRIFT_MISSING" -eq 0 ] && [ "$_DRIFT_EXTRA" -eq 0 ]; then _dr="${G}ok${RST}"
    else _dr="${Y}⚠ ${_DRIFT_MISSING} missing/${_DRIFT_EXTRA} extra (d)${RST}"; fi
    printf "${BOLD}╔%s╗${RST}\n" "$_HR"
    printf "${BOLD}║  %-60s║${RST}\n" "TUIFW - TinyWall-style Firewall Manager ${VERSION}"
    printf "${BOLD}╚%s╝${RST}\n" "$_HR"
    printf "  Backend: ${C}%s${RST}  Conns: ${W}%s${RST}  Rules: ${W}%s${RST}  Drift: %s\n\n" \
        "$_be" "$CONN_COUNT" "$_RULE_COUNT" "$_dr"
}

_draw_keys() {
    printf "  ${DIM}j/k ↑/↓ move  PgUp/Dn  g/G  b proc  i IP  u undo  c keep  d drift  f flush  r refresh  q quit${RST}\n\n"
}

# v4: ONE awk process renders every visible row, resolving process name and user from
# /proc and /etc/passwd itself. v3 forked an awk plus four $(...) subshells per row
# (~80 forks per redraw) and kept a stale PID cache file.
_draw_connections() {
    printf "${BOLD}${C}    %-5s  %-21s  %-21s  %-13s  %s${RST}\n" PROTO LOCAL REMOTE PROCESS USER
    printf "  ${DIM}  %s${RST}\n" "-----  ---------------------  ---------------------  -------------  --------"
    awk -F"$_TAB" -v top="$_TOP" -v max="$MAX_ROWS" -v cur="$CURSOR" \
        -v cG="$G" -v cB="$BOLD" -v cD="$DIM" -v cX="$RST" '
    BEGIN {
        while ((getline l < "/etc/passwd") > 0) {
            n = split(l, p, ":"); if (n >= 3 && !(p[3] in un)) un[p[3]] = p[1]
        }
        close("/etc/passwd")
    }
    function trunc(s, w) { return (length(s) > w) ? substr(s, 1, w - 1) "~" : s }
    function pname(pid,   f, nm, r) {
        if (pid == "") return "?"
        if (!(pid in nc)) {
            f = "/proc/" pid "/comm"; nm = ""
            r = (getline nm < f); close(f)
            if (r <= 0) nm = ""
            gsub(/[^A-Za-z0-9._-]/, "", nm)
            nc[pid] = (nm == "") ? "?" : nm
        }
        return nc[pid]
    }
    function puser(pid,   f, ln, u, r) {
        if (pid == "") return "?"
        if (!(pid in uc)) {
            f = "/proc/" pid "/status"; uc[pid] = "?"
            while ((r = (getline ln < f)) > 0) {
                if (ln ~ /^Uid:/) { split(ln, u, /[ \t]+/); uc[pid] = (u[2] in un) ? un[u[2]] : "uid:" u[2]; break }
            }
            close(f)
        }
        return uc[pid]
    }
    NR > top && NR <= top + max {
        shown++
        nm = trunc(pname($4), 13); us = trunc(puser($4), 8)
        if (NR == cur)
            printf "  %s%s▶ %-5s  %-21s  %-21s  %-13s  %s%s\n", cB, cG, $1, trunc($2, 21), trunc($3, 21), nm, us, cX
        else
            printf "    %-5s  %-21s  %-21s  %-13s  %s%s%s\n", $1, trunc($2, 21), trunc($3, 21), nm, cD, us, cX
    }
    END {
        if (NR == 0) { print "    (no active connections)"; shown = 1 }
        for (i = shown; i < max; i++) print ""
    }' "$TMPCONN"
}

_draw_blocks() {
    printf "\n  ${BOLD}${R}Active Blocks${RST}  ${DIM}(last 6 of %s, newest last; u undoes the newest)${RST}\n" "$_RULE_COUNT"
    printf "  ${DIM}%s${RST}\n" "--------------------------------------------------------------"
    if [ "$_RULE_COUNT" -gt 0 ]; then
        tail -n 6 "$RULEFILE" | awk -F"$_TAB" -v cR="$R" -v cD="$DIM" -v cX="$RST" '
            { i = index($1, ":"); printf "  %s✖%s  %-4s %-40s %s%s%s\n", cR, cX, substr($1, 1, i - 1), substr($1, i + 1), cD, $2, cX }'
    else
        printf "  ${DIM}No active blocks.${RST}\n"
    fi
}

_draw_status() {
    printf '\n  %s\n' "$_MSG"
    if [ -n "$_PEND_MSG" ]; then printf '  %s%s%s\n' "$Y" "$_PEND_MSG" "$RST"; fi
    return 0
}

# ─────────────────────── CURSOR HELPERS ──────────────────────────────────────
_get_field() { awk -v r="$1" -v f="$2" -F"$_TAB" 'NR==r{print (f<=NF)?$f:""; exit}' "$TMPCONN"; }

cursor_up()   { [ "$CURSOR" -gt 1 ] && CURSOR=$((CURSOR - 1)); _fix_view; return 0; }
cursor_down() { [ "$CURSOR" -lt "$CONN_COUNT" ] && CURSOR=$((CURSOR + 1)); _fix_view; return 0; }
cursor_page() { CURSOR=$((CURSOR + $1)); _fix_view; return 0; }

# ─────────────────────── TERMINAL / INPUT ────────────────────────────────────
stty_init_raw() { _STTY_SAVE=$(stty -g 2>/dev/null) || _STTY_SAVE=""; _stty_raw; }
_stty_raw()     { stty -echo -icanon min 0 time "$READ_TIMEOUT_DS" 2>/dev/null || true; }
stty_restore() {
    if [ -n "$_STTY_SAVE" ]; then stty "$_STTY_SAVE" 2>/dev/null || stty sane 2>/dev/null || true
    else stty sane 2>/dev/null || true; fi
}

# v4: v3 used `read -n 1`. BusyBox ash's read -n re-programs VMIN=1, which makes the
# first read BLOCK until a key arrives — the periodic refresh then never fires. dd on
# a min=0/time=N tty returns after the timeout with 0 bytes, which is exactly a tick.
_rd1() { _C=$(dd bs=1 count=1 2>/dev/null); }

read_key() {
    KEY=""; ARROW=""
    _rd1
    [ -n "$_C" ] || return 1
    KEY="$_C"
    [ "$KEY" = "$_ESC" ] || return 0
    KEY="ESC"
    _rd1
    case "$_C" in
        '['|O)
            _seq="$_C"; _n=0
            while [ "$_n" -lt 4 ]; do                 # read until the CSI final byte
                _rd1; [ -n "$_C" ] || break
                _seq="$_seq$_C"
                case "$_C" in [0-9]|\;) _n=$((_n + 1)) ;; *) break ;; esac
            done
            case "$_seq" in
                '[A'|OA) ARROW=up ;;     '[B'|OB) ARROW=down ;;
                '[5~')   ARROW=pgup ;;   '[6~')   ARROW=pgdn ;;
                '[H'|OH|'[1~') ARROW=home ;;
                '[F'|OF|'[4~') ARROW=end ;;
            esac ;;
    esac
    return 0
}

_prompt_read() {
    _PROMPT_VAL=""
    stty_restore
    printf '%s' "$_SHOW"
    printf "  ${Y}%s${RST} " "$1"
    IFS= read -r _PROMPT_VAL 2>/dev/null || _PROMPT_VAL=""
    printf '%s' "$_HIDE"
    _stty_raw
}

# ─────────────────────── ACTIONS ─────────────────────────────────────────────
action_block_process() {
    if [ "$UFW" -eq 1 ]; then                       # v4: v3 silently blocked the remote IP instead
        _MSG="${Y}ufw backend cannot match processes — use 'i' to block the remote IP.${RST}"; return 0
    fi
    _pid=$(_get_field "$CURSOR" 4)
    if [ -z "$_pid" ]; then _MSG="${Y}No PID on this row — use 'i' to block by IP.${RST}"; return 0; fi
    if [ ! -d "/proc/$_pid" ]; then _MSG="${Y}Process $_pid has exited.${RST}"; return 0; fi
    _pid_name "$_pid"; _bname="$_G_NAME"
    _raw=""; IFS= read -r _raw 2>/dev/null < "/proc/$_pid/comm" || _raw=""
    _uid=$(awk '/^Uid:/{print $2; exit}' "/proc/$_pid/status" 2>/dev/null)
    _cg=""                                          # v5: cgroupv2 match (nft) — whole service, precise
    if [ "$NFT" -eq 1 ] && [ "$_CG_SUPPORTED" = "1" ]; then
        _cg=$(awk -F: '$1=="0"{print $3; exit}' "/proc/$_pid/cgroup" 2>/dev/null)
        _cg_safe "$_cg" || _cg=""
    fi
    # v4: match the kernel comm EXACTLY (v3 used basename(exe): wrong for renamed threads
    # and "foo (deleted)"; its sanitised copy could differ from the real comm).
    if [ "$_CMD_OWNER_SUPPORTED" = "1" ] && _valid_comm "$_raw"; then
        _bt=cmd; _bv="$_raw"
        _what="process '$_raw' (cmd-owner)"
    elif [ -n "$_cg" ]; then
        _bt=cg; _bv="$_cg"
        _what="every process in cgroup $_cg"
    else
        case "$_uid" in ''|*[!0-9]*) _MSG="${Y}Cannot determine UID for pid $_pid.${RST}"; return 0 ;; esac
        # v4: uid 0 would sever every root service incl. sshd — refuse unless forced.
        if [ "$_uid" = "0" ] && [ "${TUIFW_ALLOW_ROOT_UID:-0}" != "1" ]; then
            _MSG="${R}Refused:${RST} no per-process match here and uid 0 would cut ALL root traffic (SSH). Use 'i'."
            return 0
        fi
        _bt=uid; _bv="$_uid"
        _what="ALL processes of uid $_uid (no per-process match available)"
    fi
    draw_ui
    printf "  ${Y}Block:${RST} ${BOLD}%s${RST}  pid=%s\n" "$_what" "$_pid"
    _prompt_read "Confirm? [y/N]:"
    case "$_PROMPT_VAL" in y|Y) _block "$_bt" "$_bv" "$_bname" ;; *) _MSG="${DIM}Cancelled.${RST}" ;; esac
    return 0
}

action_block_ip() {
    _norm_addr "$(_get_field "$CURSOR" 3)"; _ip="$NORM_IP"
    draw_ui
    printf "  ${Y}Block IP:${RST} ${BOLD}%s${RST}\n" "${_ip:-<none>}"
    _prompt_read "Enter IP (blank = use above):"
    if [ -n "$_PROMPT_VAL" ]; then _norm_addr "$_PROMPT_VAL"; _ip="$NORM_IP"; fi
    if ! _validate_ip "$_ip"; then
        _MSG="${Y}Invalid or non-routable address: '${_ip}'${RST}"; return 0
    fi
    _canon_ip "$_ip"; _ip="$NORM_IP"                # v5: store the kernel's canonical spelling
    if _is_protected "$_ip"; then
        _MSG="${R}Refused:${RST} ${_ip} is protected (loopback / your SSH peer / TUIFW_PROTECT)."; return 0
    fi
    if [ "$UFW" -eq 1 ]; then _block ufw "$_ip" "$_ip"; else _block ip "$_ip" "$_ip"; fi
    return 0
}

handle_key() {
    _MSG=""
    case "$KEY" in
        ESC)
            case "$ARROW" in
                up) cursor_up ;; down) cursor_down ;;
                pgup) cursor_page -"$MAX_ROWS" ;; pgdn) cursor_page "$MAX_ROWS" ;;
                home) CURSOR=1; _fix_view ;; end) CURSOR="$CONN_COUNT"; _fix_view ;;
            esac ;;
        k|K) cursor_up ;;
        j|J) cursor_down ;;
        g)   CURSOR=1; _fix_view ;;
        G)   CURSOR="$CONN_COUNT"; _fix_view ;;
        r|R) enumerate_connections ;;
        c|C) if [ -s "$_PENDING" ]; then : > "$_PENDING"; _PEND_MSG=""; _MSG="${G}✔ Blocks confirmed and kept.${RST}"
             else _MSG="${DIM}Nothing pending.${RST}"; fi ;;
        d|D) action_drift ;;
        b|B) action_block_process ;;
        i|I) action_block_ip ;;
        u|U) unblock_last ;;
        f|F)
            draw_ui
            _prompt_read "Flush ALL TUIFW blocks? [y/N]:"
            case "$_PROMPT_VAL" in y|Y) flush_all ;; *) _MSG="${DIM}Cancelled.${RST}" ;; esac ;;
        q|Q) return 1 ;;
    esac
    return 0
}

# ─────────────────────── CLEANUP ─────────────────────────────────────────────
cleanup() {
    [ "$_CLEANED" -eq 1 ] && return 0     # v4: v3 ran this twice (INT trap + EXIT trap)
    _CLEANED=1
    _REV_EXIT=0
    if [ -n "$_PENDING" ] && [ -s "$_PENDING" ]; then      # v5: leaving = unconfirmed blocks revert
        for _k in $(awk -F"$_TAB" '{ print $1 }' "$_PENDING"); do
            _pending_revert "$_k"; _REV_EXIT=$((_REV_EXIT + 1))
        done
    fi
    if [ "$_TUI_ACTIVE" -eq 1 ]; then
        stty_restore
        printf '%s%s' "$_SHOW" "$_ALT_OFF"
    fi
    [ "$_HAVE_LOCK" -eq 1 ] && rm -rf "$LOCKDIR"
    case "$TMPD" in /run/tuifw.*|/tmp/tuifw.*) rm -rf "$TMPD" ;; esac
    if [ "$_TUI_ACTIVE" -eq 1 ]; then
        [ "$_REV_EXIT" -gt 0 ] && printf "${Y}Reverted %s unconfirmed block(s) on exit.${RST}\n" "$_REV_EXIT"
        case "$BACKEND" in
            nft) printf "${DIM}TUIFW exited. Rules persist in nft table 'inet %s'. Flush: nft flush table inet %s${RST}\n" "$_NFT_T" "$_NFT_T" ;;
            *)   printf "${DIM}TUIFW exited. Rules persist (chains '%s' / '%s').${RST}\n" "$CHAIN" "$CHAIN_OUT" ;;
        esac
    fi
    return 0
}

usage() {
    printf '%s\n' "Usage: sh $SCRIPT_NAME [--restore | --check | --install-boot | --uninstall-boot | --help | --version]" \
        "  (no args)        interactive firewall manager (root, terminal required)" \
        "  --restore        re-apply saved rules from $RULEFILE and exit" \
        "  --check          report drift between rule file and firewall (exit 1 if any)" \
        "  --install-boot   install a boot hook (OpenRC local.d or systemd) running --restore" \
        "  --uninstall-boot remove that hook" \
        "Env: TUIFW_BACKEND TUIFW_DEADMAN TUIFW_KILL_FLOWS TUIFW_PROTECT TUIFW_ALLOW_ROOT_UID"
}

# ─────────────────────── MAIN ────────────────────────────────────────────────
main() {
    case "${1:-}" in
        '') _mode=tui ;;
        --restore) _mode=restore ;;
        --check) _mode=check ;;
        --install-boot) _mode=install ;;
        --uninstall-boot) _mode=uninstall ;;
        -h|--help) usage; return 0 ;;
        -V|--version) printf '%s\n' "$SCRIPT_NAME"; return 0 ;;
        *) usage >&2; return 2 ;;
    esac

    # v4: root check happens BEFORE traps are armed (v3 printed the "exited" banner
    # and ran terminal cleanup even for a non-root refusal).
    if [ "$(id -u)" -ne 0 ]; then printf "${R}Error: must run as root.${RST}\n" >&2; return 1; fi
    case "$_mode" in
        install)   install_boot;   return $? ;;
        uninstall) uninstall_boot; return $? ;;
    esac
    if [ "$_mode" = tui ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
        printf '%s\n' "Error: interactive mode needs a terminal (use --restore/--check for scripts)." >&2; return 1
    fi

    _mk_tmpdir || { printf '%s\n' "Error: cannot create private temp dir." >&2; return 1; }
    # v4: signals now exit; cleanup runs exactly once via the EXIT trap.
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    trap cleanup EXIT
    trap '_REDRAW=1' WINCH

    _acquire_lock || { printf '%s\n' "Error: another tui_fw instance is running (lock: $LOCKDIR)." >&2; return 1; }
    detect_environment || return 1
    _detect_endian
    _probe_cmd_owner
    [ "$_mode" = check ] || _restore_rules          # v5: --check must see the drift, not repair it
    _count_rules

    case "$_mode" in
        restore)
            printf 'tui_fw: restored %s rule(s), %s failed (backend: %s).\n' "$_rest_ok" "$_rest_bad" "$BACKEND"
            [ "$_rest_bad" -eq 0 ]; return $? ;;
        check)
            _drift_check
            printf 'tui_fw: backend=%s rules=%s missing=%s unrecorded=%s\n' \
                "$BACKEND" "$_RULE_COUNT" "$_DRIFT_MISSING" "$_DRIFT_EXTRA"
            sed 's/^/  missing:    /' "$_DRIFT_MISS"; sed 's/^/  unrecorded: /' "$_DRIFT_XTRA"
            [ "$_DRIFT_MISSING" -eq 0 ] && [ "$_DRIFT_EXTRA" -eq 0 ]; return $? ;;
    esac

    _HR=""; _i=0; while [ "$_i" -lt 62 ]; do _HR="$_HR═"; _i=$((_i + 1)); done
    [ "$_rest_ok" -gt 0 ] && _MSG="${G}Restored ${_rest_ok} saved rule(s).${RST}"
    [ "$_rest_bad" -gt 0 ] && _MSG="${Y}${_rest_bad} saved rule(s) could not be restored.${RST}"
    [ "$BACKEND" = iptables ] && [ "$_CMD_OWNER_SUPPORTED" != "1" ] && \
        _MSG="${_MSG} ${DIM}(no --cmd-owner: 'b' blocks by uid)${RST}"
    [ "$NFT" -eq 1 ] && [ "$_CG_SUPPORTED" != "1" ] && \
        _MSG="${_MSG} ${DIM}(no cgroupv2 match: 'b' blocks by uid)${RST}"

    _TUI_ACTIVE=1
    printf '%s%s' "$_ALT_ON" "$_HIDE"
    stty_init_raw
    : > "$TMPCONN"
    _drift_check
    enumerate_connections
    draw_ui

    while true; do
        if read_key; then
            handle_key || break
            _pending_tick
            _fix_view
            draw_ui
        else
            _TICK=$((_TICK + 1)); _need=0
            _pending_tick && _need=1                 # v5: countdown redraw / auto-revert
            if [ "$_TICK" -ge "$UPDATE_INTERVAL" ] || [ "$_REDRAW" -eq 1 ]; then
                _TICK=0; _REDRAW=0; _need=1
                enumerate_connections
                _DRIFT_TICK=$((_DRIFT_TICK + 1))     # v5: drift re-check every ~10 refreshes
                if [ "$_DRIFT_TICK" -ge 10 ]; then _DRIFT_TICK=0; _drift_check; fi
            fi
            [ "$_need" -eq 1 ] && draw_ui
        fi
    done
    return 0
}

# v4: TUIFW_SOURCE_ONLY=1 lets tests source the functions without starting the UI.
[ -n "${TUIFW_SOURCE_ONLY:-}" ] || { main "$@"; exit $?; }
