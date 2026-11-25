#!/bin/sh
# obfuscate.sh - Obfuscate inline <script> JavaScript inside an HTML file.
# Target shell : ash (busybox) on Alpine Linux. POSIX sh only, no bashisms.
# Obfuscator   : javascript-obfuscator (AST-based, npm) - installed on demand.
#
# Usage:
#   ./obfuscate.sh input.html output.html
#
# Notes:
#   - Only inline <script>...</script> blocks WITHOUT a src= attribute are
#     touched. External scripts (<script src="...">) are left untouched.
#   - This is code obfuscation for minification/IP-protection purposes, not
#     encryption - a determined reader can still deobfuscate the output.
#   - Requires root (or passwordless doas/sudo) the first time, to `apk add`
#     nodejs/npm if they are not already installed.
#
# Version: 1.0.0
# Changelog:
#   1.0.0 - Initial release: apk bootstrap, awk-based extraction/reinjection,
#           javascript-obfuscator with a conservative-but-strong preset.

set -eu

IN="${1:?Usage: $0 input.html output.html}"
OUT="${2:?Usage: $0 input.html output.html}"

if [ ! -f "$IN" ]; then
    echo "error: input file '$IN' not found" >&2
    exit 1
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

# --- 1. Ensure dependencies -------------------------------------------------

if ! command -v node >/dev/null 2>&1; then
    echo "[*] node not found - installing via apk..." >&2
    apk add --no-cache nodejs npm >&2
fi

if ! command -v javascript-obfuscator >/dev/null 2>&1; then
    echo "[*] javascript-obfuscator not found - installing globally via npm..." >&2
    npm install -g javascript-obfuscator >&2
fi

# --- 2. Extract inline <script> blocks (no src=) into numbered .js files ---
# Produces a skeleton HTML with each inline block replaced by a
# __JSOBF_BLOCK_n__ marker, and writes block n's raw JS to $WORKDIR/n.js.
# External <script src="...">, and blocks with no closing tag found before
# EOF (malformed input), are left in place untouched.

awk -v workdir="$WORKDIR" '
BEGIN { n = 0; in_script = 0 }
{
    line = $0
    if (!in_script) {
        if (match(line, /<script[^>]*>/)) {
            tag = substr(line, RSTART, RLENGTH)
            if (tag ~ /src=/) {
                print line
                next
            }
            pre  = substr(line, 1, RSTART - 1)
            rest = substr(line, RSTART + RLENGTH)
            jsfile = workdir "/" n ".js"
            print pre tag "__JSOBF_BLOCK_" n "__"
            if (match(rest, /<\/script>/)) {
                body = substr(rest, 1, RSTART - 1)
                tail = substr(rest, RSTART)
                print body > jsfile
                close(jsfile)
                print tail
            } else {
                print rest > jsfile
                in_script = 1
                cur = jsfile
            }
            n++
            next
        }
        print line
    } else {
        if (match(line, /<\/script>/)) {
            body = substr(line, 1, RSTART - 1)
            tail = substr(line, RSTART)
            print body >> cur
            close(cur)
            print tail
            in_script = 0
        } else {
            print line >> cur
        }
    }
}
' "$IN" > "$WORKDIR/skeleton.html"

BLOCK_COUNT=$(find "$WORKDIR" -maxdepth 1 -name '[0-9]*.js' 2>/dev/null | wc -l)
echo "[*] Found $BLOCK_COUNT inline script block(s)" >&2

# --- 3. Obfuscate each extracted block --------------------------------------

i=0
while [ "$i" -lt "$BLOCK_COUNT" ]; do
    src="$WORKDIR/$i.js"
    dst="$WORKDIR/$i.obf.js"
    if [ -s "$src" ]; then
        javascript-obfuscator "$src" \
            --output "$dst" \
            --compact true \
            --control-flow-flattening true \
            --control-flow-flattening-threshold 0.75 \
            --dead-code-injection true \
            --dead-code-injection-threshold 0.4 \
            --string-array true \
            --string-array-encoding base64 \
            --string-array-threshold 0.75 \
            --rename-globals false \
            --self-defending true \
            --disable-console-output false >&2
    else
        : > "$dst"
    fi
    i=$((i + 1))
done

# --- 4. Reassemble HTML, substituting obfuscated JS back in -----------------

cp "$WORKDIR/skeleton.html" "$OUT.tmp"

i=0
while [ "$i" -lt "$BLOCK_COUNT" ]; do
    marker="__JSOBF_BLOCK_${i}__"
    obf="$WORKDIR/$i.obf.js"
    awk -v marker="$marker" -v jsfile="$obf" '
        BEGIN {
            while ((getline line < jsfile) > 0) {
                js = js line "\n"
            }
            close(jsfile)
        }
        {
            idx = index($0, marker)
            if (idx > 0) {
                pre  = substr($0, 1, idx - 1)
                post = substr($0, idx + length(marker))
                printf "%s", pre
                printf "%s", js
                print post
            } else {
                print
            }
        }
    ' "$OUT.tmp" > "$OUT.tmp2"
    mv "$OUT.tmp2" "$OUT.tmp"
    i=$((i + 1))
done

mv "$OUT.tmp" "$OUT"
echo "[*] Obfuscated HTML written to $OUT" >&2
