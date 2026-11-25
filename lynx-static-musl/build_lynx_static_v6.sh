#!/bin/sh
# build_lynx_static_v6.sh
#
# Builds official Lynx (invisible-island.net) with OpenSSL TLS as a fully STATIC
# binary linked against musl libc, so it runs on any Linux with glibc 2.8
# (or older/newer): no dependency on the target's libc, libssl, libncurses or zlib.
#
# Usage:
#   sh build_lynx_static_v1.sh                 # builds for host arch (via Docker/Podman unless already on Alpine)
#   ARCH=i686 sh build_lynx_static_v1.sh       # 32-bit x86 target (common for glibc 2.8-era boxes)
#   ARCH=x86_64 | i686 | aarch64
#   OUT=/some/dir sh build_lynx_static_v6.sh   # output dir (default ./lynx-out)
#   SRC_DIR=/path sh build_lynx_static_v6.sh   # use pre-downloaded tarballs found there
#                                              # (zlib-X.tar.gz openssl-X.tar.gz ncurses-X.tar.gz lynxX.tar.gz cacert.pem)
#
# Output: $OUT/lynx-<ver>-static-<arch>.tar.gz  (+ unpacked dir)
#
# Requirements: docker or podman (or run directly on Alpine as root) + network.

set -eu
umask 022

# ---- Pinned versions (override via env). Verify "latest" before release builds. ----
LYNX_VER="${LYNX_VER:-2.9.3}"
OPENSSL_VER="${OPENSSL_VER:-3.5.4}"      # 3.5.x = LTS line
ZLIB_VER="${ZLIB_VER:-1.3.1}"
NCURSES_VER="${NCURSES_VER:-6.5}"
ALPINE_TAG="${ALPINE_TAG:-3.20}"

# Each *_URLS is a space-separated mirror list, tried in order.
LYNX_URLS="${LYNX_URLS:-https://invisible-island.net/archives/lynx/tarballs/lynx${LYNX_VER}.tar.gz https://invisible-mirror.net/archives/lynx/tarballs/lynx${LYNX_VER}.tar.gz}"
OPENSSL_URLS="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz https://ftp.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz"
ZLIB_URLS="https://github.com/madler/zlib/releases/download/v${ZLIB_VER}/zlib-${ZLIB_VER}.tar.gz https://zlib.net/fossils/zlib-${ZLIB_VER}.tar.gz https://downloads.sourceforge.net/project/libpng/zlib/${ZLIB_VER}/zlib-${ZLIB_VER}.tar.gz"
NCURSES_URLS="https://mirrors.kernel.org/gnu/ncurses/ncurses-${NCURSES_VER}.tar.gz https://invisible-mirror.net/archives/ncurses/ncurses-${NCURSES_VER}.tar.gz https://ftpmirror.gnu.org/ncurses/ncurses-${NCURSES_VER}.tar.gz https://ftp.gnu.org/gnu/ncurses/ncurses-${NCURSES_VER}.tar.gz"
CACERT_URLS="https://curl.se/ca/cacert.pem"

ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in
  x86_64|amd64)  ARCH=x86_64;  OSSL_TARGET=linux-x86_64;  PLATFORM=linux/amd64 ;;
  i386|i486|i586|i686|x86) ARCH=i686; OSSL_TARGET=linux-x86; PLATFORM=linux/386 ;;
  aarch64|arm64) ARCH=aarch64; OSSL_TARGET=linux-aarch64; PLATFORM=linux/arm64 ;;
  *) echo "Unsupported ARCH: $ARCH" >&2; exit 2 ;;
esac

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
OUT="${OUT:-$PWD/lynx-out}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# ======================= Stage 1: host side =======================
# Re-run ourselves inside an Alpine (musl) container unless already inside one.
if [ -z "${IN_BUILD_CONTAINER:-}" ] && [ ! -f /etc/alpine-release ]; then
  RT=""
  for c in docker podman; do command -v "$c" >/dev/null 2>&1 && { RT="$c"; break; }; done
  [ -n "$RT" ] || { echo "Need docker or podman (or run this on Alpine)." >&2; exit 1; }
  echo ">> Building in $RT alpine:$ALPINE_TAG ($PLATFORM)"
  SRCMNT=""
  if [ -n "${SRC_DIR:-}" ]; then
    [ -d "$SRC_DIR" ] || { echo "SRC_DIR not a directory: $SRC_DIR" >&2; exit 1; }
    SRCMNT="-v $(cd "$SRC_DIR" && pwd):/src:ro"
  fi
  # shellcheck disable=SC2086
  exec "$RT" run --rm $SRCMNT --platform "$PLATFORM" \
    -e IN_BUILD_CONTAINER=1 -e ARCH="$ARCH" -e OSSL_TARGET="$OSSL_TARGET" \
    -e LYNX_VER="$LYNX_VER" -e OPENSSL_VER="$OPENSSL_VER" -e ZLIB_VER="$ZLIB_VER" \
    -e NCURSES_VER="$NCURSES_VER" -e LYNX_URLS="$LYNX_URLS" \
    -e HTTP_PROXY -e HTTPS_PROXY -e NO_PROXY -e http_proxy -e https_proxy -e no_proxy \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$SELF:/build.sh:ro" -v "$OUT:/out" \
    "alpine:$ALPINE_TAG" sh /build.sh
fi

# ======================= Stage 2: inside musl =======================
OUT=/out
[ -d "$OUT" ] || OUT="${OUT_DIR:-$PWD/lynx-out}"
mkdir -p "$OUT"

if [ -f /etc/alpine-release ]; then
  apk add --no-cache build-base perl linux-headers curl tar gzip xz bzip2 file \
    pkgconf coreutils >/dev/null
fi

JOBS="$(nproc 2>/dev/null || echo 2)"
W="$(mktemp -d /tmp/lynxbuild.XXXXXX)"
trap 'rm -rf "$W"' EXIT INT TERM
DEPS="$W/deps"; mkdir -p "$DEPS"

# Download trying each mirror in turn. Per-mirror: IPv4-forced retry on failure
# (many containers have broken IPv6 -> "Connection timed out"). Sets LAST_URL.
LAST_URL=""
fetch() { # dest url [url...]
  _dest="$1"; shift
  LAST_URL=""
  for _u in "$@"; do
    for _d in /src "$OUT/.dl"; do
      if [ -s "$_d/${_u##*/}" ]; then
        echo "   LOCAL $_d/${_u##*/}"; cp "$_d/${_u##*/}" "$_dest"; return 0
      fi
    done
  done
  for _u in "$@"; do
    for _ipf in "" "-4"; do
      echo "   GET $_u ${_ipf:+(IPv4)}"
      # shellcheck disable=SC2086
      if curl -fSL $_ipf --proto '=https' --tlsv1.2 --retry 1 --retry-delay 2 \
           --connect-timeout 15 --speed-limit 1024 --speed-time 60 --max-time 1200 \
           -sS -o "$_dest" "$_u"; then
        LAST_URL="$_u"
        # cache for re-runs (best effort)
        mkdir -p "$OUT/.dl" 2>/dev/null && cp "$_dest" "$OUT/.dl/${_u##*/}" 2>/dev/null || true
        return 0
      fi
      echo "   -> failed, trying next" >&2
    done
  done
  echo "ERROR: all mirrors failed for $_dest" >&2
  return 1
}
unpack() { # tarball destdir  (strips the top-level dir)
  mkdir -p "$2"; tar -xzf "$1" -C "$2" --strip-components=1
}

echo ">> Fetching sources"
cd "$W"
# shellcheck disable=SC2086
fetch zlib.tgz    $ZLIB_URLS    || exit 1
# shellcheck disable=SC2086
fetch openssl.tgz $OPENSSL_URLS || exit 1; OSSL_SRC="$LAST_URL"
# shellcheck disable=SC2086
fetch ncurses.tgz $NCURSES_URLS || exit 1
# shellcheck disable=SC2086
fetch lynx.tgz    $LYNX_URLS    || exit 1
# CA bundle: curl.se preferred; fall back to Alpine's ca-certificates bundle.
CA_SRC=""
# shellcheck disable=SC2086
if fetch cacert.pem $CACERT_URLS; then CA_SRC="$LAST_URL"
elif [ -s /etc/ssl/certs/ca-certificates.crt ]; then
  echo "   WARN: using container CA bundle as fallback"
  cp /etc/ssl/certs/ca-certificates.crt cacert.pem
else exit 1; fi

# Integrity: OpenSSL publishes a .sha256 next to each release; CA bundle too.
if [ -n "$OSSL_SRC" ] && fetch openssl.sha256 "${OSSL_SRC}.sha256" 2>/dev/null; then
  want="$(cut -d' ' -f1 openssl.sha256)"
  have="$(sha256sum openssl.tgz | cut -d' ' -f1)"
  [ "$want" = "$have" ] || { echo "OpenSSL checksum MISMATCH" >&2; exit 1; }
  echo "   openssl sha256 OK"
else
  echo "   WARN: no openssl .sha256 available; sha256=$(sha256sum openssl.tgz | cut -d' ' -f1)"
fi
if [ -n "$CA_SRC" ] && fetch cacert.sha256 "${CA_SRC}.sha256" 2>/dev/null; then
  want="$(cut -d' ' -f1 cacert.sha256)"
  have="$(sha256sum cacert.pem | cut -d' ' -f1)"
  [ "$want" = "$have" ] || { echo "cacert.pem checksum MISMATCH" >&2; exit 1; }
  echo "   cacert sha256 OK"
fi
for f in zlib.tgz ncurses.tgz lynx.tgz; do echo "   $f sha256=$(sha256sum $f | cut -d' ' -f1)"; done
grep -q 'BEGIN CERTIFICATE' cacert.pem || { echo "cacert.pem invalid" >&2; exit 1; }

# -D_FORTIFY_SOURCE dropped: musl ignores it, and -D flags inside CFLAGS make ncurses warn.
# -std=gnu17: gcc 15 defaults to C23, which breaks older C code (K&R-style prototypes,
# 'bool' as a keyword) in ncurses and Lynx. Pin the language level for every package.
export CC="${CC:-gcc} -std=gnu17"
export CFLAGS="-O2 -fPIC -fstack-protector-strong"
export PKG_CONFIG_PATH="$DEPS/lib/pkgconfig"

echo ">> zlib $ZLIB_VER"
unpack zlib.tgz zlib && cd zlib
./configure --prefix="$DEPS" --static >/dev/null
make -j"$JOBS" >/dev/null && make install >/dev/null
cd "$W"

echo ">> OpenSSL $OPENSSL_VER ($OSSL_TARGET)"
unpack openssl.tgz openssl && cd openssl
# no-ktls/no-afalgeng: avoid kernel-feature assumptions (old kernels); no-shared/no-dso: pure static.
./Configure "$OSSL_TARGET" --prefix="$DEPS" --openssldir="$DEPS/ssl" --libdir=lib \
  no-shared no-dso no-tests no-docs no-ktls no-afalgeng no-comp no-ssl3 no-weak-ssl-ciphers \
  -static -fPIC >/dev/null
make -j"$JOBS" build_libs >/dev/null
make install_dev >/dev/null
cd "$W"

echo ">> ncurses $NCURSES_VER (wide-char)"
unpack ncurses.tgz ncurses && cd ncurses
./configure --prefix="$DEPS" --without-shared --with-normal --without-debug \
  --without-cxx --without-cxx-binding --without-ada --without-tests --without-manpages \
  --enable-widec --enable-pc-files --with-pkg-config-libdir="$DEPS/lib/pkgconfig" \
  --with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo:/usr/lib/terminfo \
  --with-default-terminfo-dir=/usr/share/terminfo --disable-stripping >/dev/null
make -j"$JOBS" >/dev/null
# Install into a staging root: --with-default-terminfo-dir is an ABSOLUTE path
# (/usr/share/terminfo), so a plain 'make install' would write the database into the
# build machine's real /usr/share/terminfo instead of $DEPS. DESTDIR keeps it contained.
make install DESTDIR="$W/ncstage" >/dev/null
cp -a "$W/ncstage$DEPS/." "$DEPS/"                      # libs, headers, pkg-config files
TERMINFO_SRC="$(find "$W/ncstage" -type d -name terminfo 2>/dev/null | head -n1)"
[ -n "$TERMINFO_SRC" ] && [ -d "$TERMINFO_SRC" ] || { echo "ERROR: terminfo db not found in ncurses stage" >&2; exit 1; }
cd "$W"

echo ">> Lynx $LYNX_VER"
unpack lynx.tgz lynx && cd lynx
CPPFLAGS="-I$DEPS/include -I$DEPS/include/ncursesw" \
LDFLAGS="-static -L$DEPS/lib" \
./configure --prefix=/opt/lynx \
  --with-ssl="$DEPS" --with-zlib --with-screen=ncursesw \
  --disable-nls --enable-ipv6 --enable-default-colors --enable-color-style \
  --disable-echo >/dev/null
make -j"$JOBS" >/dev/null
make install DESTDIR="$W/stage" >/dev/null
cd "$W"

# ---- Package ----
NAME="lynx-${LYNX_VER}-static-${ARCH}"
PKG="$W/$NAME"
mkdir -p "$PKG/bin" "$PKG/share"
cp "$W/stage/opt/lynx/bin/lynx" "$PKG/bin/lynx.bin"
strip "$PKG/bin/lynx.bin"
cp "$W/stage/opt/lynx/etc/lynx.cfg" "$PKG/lynx.cfg"
# Color-style file (the binary hardcodes /opt/lynx/etc/lynx.lss; the launcher overrides via LYNX_LSS)
cp "$W/stage/opt/lynx/etc/lynx.lss" "$PKG/lynx.lss"
# Offline help pages (Lynx's lynx.cfg points HELPFILE at the web by default)
cp -R "$W/lynx/lynx_help" "$PKG/share/lynx_help"
cp "$W/cacert.pem" "$PKG/cacert.pem"
cp -R "$TERMINFO_SRC" "$PKG/share/terminfo"

# Launcher: resolves its own dir, points OpenSSL at the bundled CA file,
# lets ncurses find bundled terminfo plus system ones.
cat > "$PKG/lynx" <<'EOF'
#!/bin/sh
# Resolve symlinks to find the install dir
p="$0"
while [ -h "$p" ]; do
  l="$(readlink "$p")"; case "$l" in /*) p="$l";; *) p="$(dirname "$p")/$l";; esac
done
D="$(cd "$(dirname "$p")" && pwd)"
SSL_CERT_FILE="${SSL_CERT_FILE:-$D/cacert.pem}"; export SSL_CERT_FILE
LYNX_CFG="${LYNX_CFG:-$D/lynx.cfg}"; export LYNX_CFG
LYNX_LSS="${LYNX_LSS:-$D/lynx.lss}"; export LYNX_LSS
TERMINFO_DIRS="$D/share/terminfo:/etc/terminfo:/lib/terminfo:/usr/share/terminfo"; export TERMINFO_DIRS
exec "$D/bin/lynx.bin" "$@"
EOF
chmod 0755 "$PKG/lynx" "$PKG/bin/lynx.bin"

# ---- Verify: must be static, no glibc/dynamic deps ----
echo ">> Verifying"
file "$PKG/bin/lynx.bin"
if readelf -d "$PKG/bin/lynx.bin" 2>/dev/null | grep -q NEEDED; then
  echo "FAIL: binary has dynamic dependencies" >&2; exit 1
fi
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "i686" ] || [ "$(uname -m)" = "$ARCH" ]; then
  "$PKG/lynx" -version | head -n 3 || true
  # Live TLS smoke test (non-fatal if no network)
  if "$PKG/lynx" -dump -nolist -connect_timeout=15 https://example.com 2>/dev/null | grep -qi 'example domain'; then
    echo "   TLS smoke test: OK (certificate verified)"
  else
    echo "   TLS smoke test: skipped/failed (check network)"
  fi
fi

cd "$W"
tar -czf "$OUT/$NAME.tar.gz" "$NAME"
rm -rf "$OUT/$NAME"; cp -R "$PKG" "$OUT/$NAME"
if [ -n "${HOST_UID:-}" ]; then chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$OUT" 2>/dev/null || true; fi
echo ">> Done: $OUT/$NAME.tar.gz"
echo "   Install:  tar xzf $NAME.tar.gz && ./$NAME/lynx https://example.com"
