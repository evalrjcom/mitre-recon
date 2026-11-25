#!/bin/sh
# build_links_static_v1.sh
#
# Builds the Links text-mode web browser (links.twibright.com) with OpenSSL TLS and
# zlib as a fully STATIC binary linked against musl libc, so it runs on any x86_64
# Linux with an old glibc (for example 2.8): it needs nothing from the host's libc,
# libssl or zlib.
#
# Usage:
#   sh build_links_static_v1.sh                 # build + package into ./links-out
#   OUT=/some/dir sh build_links_static_v1.sh   # output directory
#   SRC_DIR=/path sh build_links_static_v1.sh   # use pre-downloaded tarballs found there:
#                                               #   links-X.tar.bz2 (or links2_X.orig.tar.bz2)
#                                               #   openssl-X.tar.gz  zlib-X.tar.gz  cacert.pem
#   RUN_NET_TEST=1 sh build_links_static_v1.sh  # also fetch https://example.com with the
#                                               # bundled CA (must pass) and with no CA (must fail)
#   LINKS_VER=2.30 LINKS_SHA256=<hash> sh ...   # other versions need their own pinned hash
#
# Output: $OUT/links-<ver>-static-<arch>-musl_pkg1.tar.gz  (+ unpacked directory)
#
# Toolchain (one of):
#   * Debian/Ubuntu:  apt-get install build-essential perl musl-tools curl
#   * Alpine:         apk add build-base perl linux-headers curl
# Tested on Ubuntu 24.04 x86_64 with musl-tools 1.2.4. The Alpine path is untested.

set -eu
umask 022

# ---- Pinned versions and checksums (override via env) ----------------------------
LINKS_VER="${LINKS_VER:-2.29}"
OPENSSL_VER="${OPENSSL_VER:-3.5.4}"
ZLIB_VER="${ZLIB_VER:-1.3.1}"
PKG_REV="${PKG_REV:-1}"

[ "$LINKS_VER" = "2.29" ] && LINKS_SHA256="${LINKS_SHA256:-22aa96c0b38e1a6f8f7ed9d7a4167a47fc37246097759ef6059ecf8f9ead7998}"
[ "$OPENSSL_VER" = "3.5.4" ] && OPENSSL_SHA256="${OPENSSL_SHA256:-967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99}"
[ "$ZLIB_VER" = "1.3.1" ] && ZLIB_SHA256="${ZLIB_SHA256:-9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23}"
LINKS_SHA256="${LINKS_SHA256:-}"
OPENSSL_SHA256="${OPENSSL_SHA256:-}"
ZLIB_SHA256="${ZLIB_SHA256:-}"
CACERT_SHA256="${CACERT_SHA256:-}"      # optional; the CA bundle changes over time

# Mirror lists, tried in order. The Ubuntu archive is plain http: its content is only
# accepted when it matches the pinned SHA-256 above.
LINKS_URLS="https://links.twibright.com/download/links-${LINKS_VER}.tar.bz2 http://archive.ubuntu.com/ubuntu/pool/universe/l/links2/links2_${LINKS_VER}.orig.tar.bz2"
OPENSSL_URLS="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz"
ZLIB_URLS="https://github.com/madler/zlib/releases/download/v${ZLIB_VER}/zlib-${ZLIB_VER}.tar.gz https://zlib.net/fossils/zlib-${ZLIB_VER}.tar.gz"
CACERT_URLS="https://curl.se/ca/cacert.pem"

die() { echo "ERROR: $*" >&2; exit 1; }
say() { echo ">> $*"; }

# ---- Host checks -----------------------------------------------------------------
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH=x86_64;  OSSL_TARGET=linux-x86_64 ;;
  aarch64|arm64) ARCH=aarch64; OSSL_TARGET=linux-aarch64 ;;
  *) die "unsupported architecture: $ARCH (x86_64 is the tested target)" ;;
esac
for t in tar bzip2 gzip make perl sha256sum; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die "need curl or wget"

KINC=""
if command -v musl-gcc >/dev/null 2>&1; then
  CC="musl-gcc"
elif [ -f /etc/alpine-release ] && command -v gcc >/dev/null 2>&1; then
  CC="gcc"            # native musl toolchain; linux-headers supplies <linux/*.h>
else
  die "no musl toolchain: install musl-tools (Debian/Ubuntu) or build-base (Alpine)"
fi

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$PWD/links-out}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
SRC_DIR="${SRC_DIR:-}"
[ -z "$SRC_DIR" ] || [ -d "$SRC_DIR" ] || die "SRC_DIR is not a directory: $SRC_DIR"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/links_static.XXXXXX")"
cleanup() { [ "${KEEP_WORK:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT INT TERM
DL="$WORK/dl"; PFX="$WORK/prefix"; BLD="$WORK/build"
mkdir -p "$DL" "$PFX" "$BLD"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"

# ---- Downloads -------------------------------------------------------------------
# fetch DEST URL...   -> uses SRC_DIR copy if present, else tries each URL in turn
fetch() {
  dest="$1"; shift
  if [ -n "$SRC_DIR" ]; then
    for cand in "$SRC_DIR/$(basename "$dest")" "$SRC_DIR/$(basename "$1")"; do
      if [ -s "$cand" ]; then cp "$cand" "$dest"; say "using $cand"; return 0; fi
    done
  fi
  for u in "$@"; do
    say "downloading $u"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --connect-timeout 20 --max-time 600 --retry 2 -o "$dest.part" "$u" || { rm -f "$dest.part"; continue; }
    else
      wget -q -T 30 -t 2 -O "$dest.part" "$u" || { rm -f "$dest.part"; continue; }
    fi
    [ -s "$dest.part" ] && { mv "$dest.part" "$dest"; return 0; }
  done
  return 1
}

# check FILE EXPECTED   -> always prints the hash; aborts on mismatch when EXPECTED is set
check() {
  h="$(sha256sum "$1" | cut -d' ' -f1)"
  say "sha256 $(basename "$1") = $h"
  if [ -n "$2" ] && [ "$h" != "$2" ]; then die "checksum mismatch for $(basename "$1") (expected $2)"; fi
  [ -n "$2" ] || echo "   (no pinned checksum for this version: compare with the publisher's value)"
}

fetch "$DL/links.tar.bz2"   $LINKS_URLS   || die "could not download Links $LINKS_VER (set SRC_DIR to supply it)"
fetch "$DL/openssl.tar.gz"  $OPENSSL_URLS || die "could not download OpenSSL $OPENSSL_VER"
fetch "$DL/zlib.tar.gz"     $ZLIB_URLS    || die "could not download zlib $ZLIB_VER"
if ! fetch "$DL/cacert.pem" $CACERT_URLS; then
  # Fallback: the certifi wheel carries the same Mozilla roots.
  say "curl.se unreachable; trying the certifi Python package"
  command -v python3 >/dev/null 2>&1 || die "no CA bundle: supply SRC_DIR/cacert.pem"
  mkdir -p "$WORK/certifi"
  python3 -m pip download certifi --no-deps -d "$WORK/certifi" -q || die "could not fetch certifi"
  python3 -I - "$WORK/certifi" "$DL/cacert.pem" <<'PYEOF' || die "could not extract cacert.pem from certifi"
import glob, sys, zipfile
whl = glob.glob(sys.argv[1] + "/certifi-*.whl")[0]
with zipfile.ZipFile(whl) as z:
    open(sys.argv[2], "wb").write(z.read("certifi/cacert.pem"))
PYEOF
fi
check "$DL/links.tar.bz2"  "$LINKS_SHA256"
check "$DL/openssl.tar.gz" "$OPENSSL_SHA256"
check "$DL/zlib.tar.gz"    "$ZLIB_SHA256"
check "$DL/cacert.pem"     "$CACERT_SHA256"
NCERTS="$(grep -c 'BEGIN CERTIFICATE' "$DL/cacert.pem" || true)"
[ "$NCERTS" -ge 50 ] || die "cacert.pem looks wrong ($NCERTS certificates)"

# ---- Kernel-header shim for musl-gcc on Debian/Ubuntu ------------------------------
if [ "$CC" = "musl-gcc" ]; then
  mkdir -p "$WORK/kinc"
  for d in linux asm-generic; do [ -e "/usr/include/$d" ] && ln -s "/usr/include/$d" "$WORK/kinc/$d"; done
  for d in "/usr/include/$ARCH-linux-gnu/asm" /usr/include/asm; do
    [ -e "$d" ] && { ln -s "$d" "$WORK/kinc/asm"; break; }
  done
  [ -e "$WORK/kinc/linux" ] || die "kernel headers not found: apt-get install linux-libc-dev"
  KINC="-I$WORK/kinc"
fi

# ---- 1) zlib ---------------------------------------------------------------------
say "building zlib $ZLIB_VER"
cd "$BLD"
tar xzf "$DL/zlib.tar.gz"
cd "zlib-$ZLIB_VER"
CC="$CC" CFLAGS="-O2 -fPIC $KINC" ./configure --static --prefix="$PFX" >"$BLD/zlib.log" 2>&1 || { tail -20 "$BLD/zlib.log"; die "zlib configure failed"; }
make -j"$JOBS" >>"$BLD/zlib.log" 2>&1 && make install >>"$BLD/zlib.log" 2>&1 || { tail -20 "$BLD/zlib.log"; die "zlib build failed"; }

# ---- 2) OpenSSL (static) -----------------------------------------------------------
say "building OpenSSL $OPENSSL_VER (a few minutes)"
cd "$BLD"
tar xzf "$DL/openssl.tar.gz"
cd "openssl-$OPENSSL_VER"
# --openssldir=/etc/ssl makes the compiled-in trust path a real, common location.
CC="$CC -static" ./Configure "$OSSL_TARGET" --prefix="$PFX" --openssldir=/etc/ssl --libdir=lib \
  no-shared no-tests no-async no-afalgeng no-engine no-dso no-ssl3 no-comp no-module no-docs \
  -fPIC $KINC >"$BLD/openssl.log" 2>&1 || { tail -20 "$BLD/openssl.log"; die "OpenSSL configure failed"; }
make -j"$JOBS" >>"$BLD/openssl.log" 2>&1 || { grep -m5 -E 'error|Error' "$BLD/openssl.log"; die "OpenSSL build failed"; }
make install_sw >>"$BLD/openssl.log" 2>&1 || { tail -20 "$BLD/openssl.log"; die "OpenSSL install failed"; }
[ -f "$PFX/lib/libssl.a" ] && [ -f "$PFX/lib/libcrypto.a" ] || die "static OpenSSL libraries missing"

# ---- 3) Links ----------------------------------------------------------------------
say "building Links $LINKS_VER"
cd "$BLD"
tar xjf "$DL/links.tar.bz2"
LDIR="$(find "$BLD" -mindepth 1 -maxdepth 1 -type d -name 'links-*' | head -n 1)"
[ -n "$LDIR" ] || die "Links source directory not found after unpacking"
cd "$LDIR"
CC="$CC" CPPFLAGS="-I$PFX/include $KINC" CFLAGS="-O2" LDFLAGS="-static -L$PFX/lib" LIBS="-lssl -lcrypto -lz" \
./configure --prefix=/usr/local --with-ssl="$PFX" --with-zlib \
  --without-x --without-svgalib --without-directfb --without-libjpeg --without-libtiff \
  --without-librsvg --without-fb --disable-graphics \
  --without-bzip2 --without-lzma --without-brotli --without-zstd >"$BLD/links.log" 2>&1 \
  || { tail -30 "$BLD/links.log"; die "Links configure failed"; }
grep -q 'SSL support:.*OPENSSL' "$BLD/links.log" || die "Links was configured without OpenSSL"
make -j"$JOBS" >>"$BLD/links.log" 2>&1 || { grep -m5 -E 'error|undefined' "$BLD/links.log"; die "Links build failed"; }
[ -x links ] || die "links binary missing"
strip -o "$BLD/links.stripped" links

# ---- 4) Verify the binary -----------------------------------------------------------
say "verifying the binary"
if command -v readelf >/dev/null 2>&1 && readelf -d "$BLD/links.stripped" 2>/dev/null | grep -q NEEDED; then
  die "binary has dynamic dependencies"
fi
if strings "$BLD/links.stripped" 2>/dev/null | grep -q 'GLIBC_'; then die "binary references glibc symbols"; fi
"$BLD/links.stripped" -version | grep -q "Links $LINKS_VER" || die "binary does not report Links $LINKS_VER"

# ---- 5) Package ---------------------------------------------------------------------
PKGNAME="links-${LINKS_VER}-static-${ARCH}-musl_pkg${PKG_REV}"
PKG="$OUT/$PKGNAME"
rm -rf "$PKG"; mkdir -p "$PKG/docs"
install -m 755 "$BLD/links.stripped" "$PKG/links"
install -m 644 "$DL/cacert.pem" "$PKG/cacert.pem"
cat >"$PKG/links-color" <<'EOF'
#!/bin/sh
# Run Links with the bundled CA roots and a 256-color default terminal.
# Resolves symlinks, so it also works when linked into /usr/local/bin.
SELF=$0
if command -v readlink >/dev/null 2>&1; then SELF=$(readlink -f "$0" 2>/dev/null || echo "$0"); fi
D=$(cd "$(dirname "$SELF")" && pwd)
# Trust ONLY the bundled roots: pointing SSL_CERT_DIR at a directory that does not exist
# stops OpenSSL also reading the host's (possibly stale) /etc/ssl/certs.
SSL_CERT_FILE="$D/cacert.pem"; export SSL_CERT_FILE
SSL_CERT_DIR="$D/.no-host-certs"; export SSL_CERT_DIR
case "${TERM:-}" in xterm|linux|"") TERM=xterm-256color; export TERM;; esac
exec "$D/links" "$@"
EOF
chmod 755 "$PKG/links-color"
for g in program_description admin_guide user_guide; do
  [ -f "$SELF_DIR/links_static_v1_$g.md" ] && cp "$SELF_DIR/links_static_v1_$g.md" "$PKG/docs/"
done
cat >"$PKG/README.txt" <<EOF
Links $LINKS_VER + OpenSSL $OPENSSL_VER + zlib $ZLIB_VER, static musl build ($ARCH), package pkg$PKG_REV.
Run ./links-color https://example.org     (use the wrapper: it supplies the CA file)
Guides are in docs/. Built by build_links_static_v1.sh.
Source sha256:
  links $LINKS_VER     $(sha256sum "$DL/links.tar.bz2" | cut -d' ' -f1)
  openssl $OPENSSL_VER  $(sha256sum "$DL/openssl.tar.gz" | cut -d' ' -f1)
  zlib $ZLIB_VER        $(sha256sum "$DL/zlib.tar.gz" | cut -d' ' -f1)
  cacert.pem ($NCERTS roots) $(sha256sum "$DL/cacert.pem" | cut -d' ' -f1)
EOF
( cd "$PKG" && sha256sum links cacert.pem links-color >SHA256SUMS )
( cd "$OUT" && tar czf "$PKGNAME.tar.gz" "$PKGNAME" )

# ---- 6) Optional network test ---------------------------------------------------------
if [ "${RUN_NET_TEST:-0}" = 1 ]; then
  say "network test: bundled CA must succeed, empty CA must fail"
  page="$(SSL_CERT_FILE="$PKG/cacert.pem" SSL_CERT_DIR=/nonexistent timeout 90 "$PKG/links" -ssl.certificates 2 -dump https://example.com 2>&1 || true)"
  echo "$page" | grep -qi 'example domain' || die "HTTPS fetch with the bundled CA failed"
  bad="$(SSL_CERT_FILE=/dev/null SSL_CERT_DIR=/nonexistent timeout 90 "$PKG/links" -ssl.certificates 2 -dump https://example.com 2>&1 || true)"
  if echo "$bad" | grep -qi 'example domain'; then die "certificate verification is not enforced"; fi
  say "network test passed"
fi

say "done: $OUT/$PKGNAME.tar.gz"
sha256sum "$OUT/$PKGNAME.tar.gz"
