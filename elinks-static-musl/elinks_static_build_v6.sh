#!/usr/bin/env bash
# elinks_static_build_v6.sh
#
# Builds official ELinks (github.com/rkd77/elinks) as a FULLY STATIC musl binary
# with modern OpenSSL (TLS 1.2/1.3), so it runs on a distro with glibc 2.8
# (or anything else) because it does not use the target's libc at all.
#
# --arch 64    x86_64 build
# --arch 32    i686 build from an x86_64 host (needs: apt install gcc-multilib)
# --arch both  builds both packages into ./dist
# A private musl libc is built from a hash-pinned source tarball on first use, so no
# musl-tools package is needed (MUSL_MODE=system uses a host/TARGET_CC musl-gcc instead).
# Host needs: gcc make perl curl tar xz git sha256sum binutils autoconf automake
#             pkg-config m4 and the kernel headers.
#   Debian/Ubuntu: apt install gcc make perl curl xz-utils git binutils autoconf \
#                  automake pkg-config linux-libc-dev [gcc-multilib for --arch 32]
#
# Usage:   ./elinks_static_build_v6.sh [--arch 32|64|both] [--version] [--help]
#          (default arch: this host's native size)
# Tunables (env):
#   Versions/pins  ELINKS_VER OPENSSL_SERIES OPENSSL_VER(auto) OPENSSL_FALLBACK ZLIB_VER MUSL_VER
#                  ELINKS_SHA256 OPENSSL_SHA256 ZLIB_SHA256 MUSL_SHA256  STRICT_PINS=1 (unpinned = fatal)
#   Toolchain      MUSL_MODE=build|system  TARGET_CC (musl-capable compiler; implies system)
#                  STRIP TARGET_ARCH OPENSSL_TARGET JOBS
#   Locations      WORK_BASE WORK OUT DLDIR MUSL_DIR   CA_SRC (local PEM) CA_MIN_CERTS
#   Behaviour      CLEAN=1 VERBOSE=1 SELFTEST_URL SELFTEST_STRICT=1 ELINKS_ALLOW_PATCH=1
set -Eeuo pipefail
umask 022

SCRIPT_VERSION="v6"
SCRIPT_NAME="elinks_static_build_${SCRIPT_VERSION}.sh"

log()  { printf '\n==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
trap 'printf "ERROR: failed at line %s (exit %s)\n" "$LINENO" "$?" >&2' ERR

usage() { sed -n '2,/^set -E/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }

# Ambient compiler/linker search variables must never leak into a musl build.
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH LD_LIBRARY_PATH LD_PRELOAD \
      CPPFLAGS CXXFLAGS CFLAGS LDFLAGS LIBS CROSS_COMPILE PKG_CONFIG_PATH 2>/dev/null || true

# ---- architecture option -------------------------------------------------------
ARCH_OPT="${ARCH_OPT:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--arch)    [ $# -ge 2 ] || die "--arch needs a value"; ARCH_OPT="$2"; shift 2 ;;
    --arch=*)     ARCH_OPT="${1#*=}"; shift ;;
    -V|--version) echo "$SCRIPT_NAME"; exit 0 ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "unknown option: $1 (try --help)" ;;
  esac
done
HOST_M="$(uname -m)"
if [ -z "$ARCH_OPT" ]; then case "$HOST_M" in i?86) ARCH_OPT=32 ;; *) ARCH_OPT=64 ;; esac; fi
case "$ARCH_OPT" in
  32|i386|i686|x86)   BITS=32 ;;
  64|x86_64|amd64)    BITS=64 ;;
  both|all)           BITS=both ;;
  *) die "invalid --arch '$ARCH_OPT' (use 32, 64 or both)" ;;
esac

# Shared (arch-independent) locations, made absolute so child runs and subshells agree.
absdir() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
DLDIR="$(absdir "${DLDIR:-dl-cache}")";     export DLDIR
MUSL_DIR="$(absdir "${MUSL_DIR:-musl}")";   export MUSL_DIR
OUT="$(absdir "${OUT:-dist}")";             export OUT
WORK_BASE="$(absdir "${WORK_BASE:-build-elinks}")"; export WORK_BASE

if [ "$BITS" = both ]; then
  # These are architecture-specific; a shared value would make the two builds collide.
  for v in WORK TARGET_CC TARGET_ARCH OPENSSL_TARGET; do
    [ -z "${!v:-}" ] || die "$v is architecture-specific: unset it for --arch both (use WORK_BASE to move the build trees)"
  done
  bash "${BASH_SOURCE[0]}" --arch 64
  bash "${BASH_SOURCE[0]}" --arch 32
  exit 0
fi
if [ "$BITS" = 32 ]; then
  case "$HOST_M" in
    x86_64|i?86) TARGET_ARCH=i686; OPENSSL_TARGET=linux-x86 ;;
    *) die "32-bit x86 builds need an x86/x86_64 host (host is $HOST_M)" ;;
  esac
else
  TARGET_ARCH="${TARGET_ARCH:-$HOST_M}"
  case "$TARGET_ARCH" in i?86) die "--arch 64 on a 32-bit host is impossible" ;; esac
fi

# ---- versions, pins, settings --------------------------------------------------
ELINKS_VER="${ELINKS_VER:-0.19.1}"
OPENSSL_SERIES="${OPENSSL_SERIES:-3.5}"       # 3.5 is an LTS series (3.0 is EOL)
OPENSSL_VER="${OPENSSL_VER:-auto}"            # auto = newest release tag of the series
OPENSSL_FALLBACK="${OPENSSL_FALLBACK:-3.5.9}" # used (with a warning) if the tag lookup fails
ZLIB_VER="${ZLIB_VER:-1.3.1}"
MUSL_VER="${MUSL_VER:-1.2.6}"
MUSL_MODE="${MUSL_MODE:-build}"
WORK="${WORK:-$WORK_BASE-$TARGET_ARCH}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
STRIP="${STRIP:-strip}"
ARCH="$TARGET_ARCH"
case "$JOBS" in ''|*[!0-9]*|0) die "JOBS must be a positive integer (got '$JOBS')" ;; esac
case "$MUSL_MODE" in build|system) ;; *) die "MUSL_MODE must be 'build' or 'system'" ;; esac
[ -z "${TARGET_CC:-}" ] || MUSL_MODE=system

# Known-good SHA-256 values for the default versions. Other versions need an explicit
# *_SHA256 (or they are recorded unpinned; STRICT_PINS=1 makes that fatal).
pin_for() { # pin_for NAME VERSION
  case "$1:$2" in
    zlib:1.3.1)    echo 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 ;;
    elinks:0.19.1) echo 31960cd471246692b84008bffec89182f25818472f86ee1a41a09bf0dad09eeb ;;
    musl:1.2.4)    echo 7a35eae33d5372a7c0da1188de798726f68825513b7ae3ebe97aaaa52114f039 ;;
    musl:1.2.5)    echo a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 ;;
    musl:1.2.6)    echo d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a ;;
    *)             echo "" ;;
  esac
}
# sha256 of ELinks 0.19.1's original src/protocol/map.cpp, which this script replaces with C.
MAPCPP_SHA256="811760996daaf9e839e8ee5193036b81765bb4d9001da5fd8d2db3948934e26b"

# Generic baseline CPU (NO -march=native) so old CPUs can run the result.
CFLAGS_BASE="-O2 -pipe -fstack-protector-strong"
LDFLAGS_BASE="-static -Wl,-z,relro -Wl,-z,now"

# ---- preflight -------------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
for t in gcc make perl curl tar xz git sha256sum awk sed grep install readelf ld ar ranlib \
         aclocal autoheader autoconf pkg-config "$STRIP"; do need "$t"; done
[ "$(id -u)" != 0 ] || warn "building as root; an unprivileged user is safer"

# Paths with whitespace break autotools/OpenSSL; fail early.
case "$WORK$OUT$DLDIR$MUSL_DIR" in *[[:space:]]*) die "WORK/OUT/DLDIR/MUSL_DIR paths must not contain spaces" ;; esac

mkdir -p "$DLDIR" "$WORK" "$OUT" "$MUSL_DIR"
WORK="$(cd "$WORK" && pwd)"; OUT="$(cd "$OUT" && pwd)"
if command -v flock >/dev/null 2>&1; then          # two builds in one tree would corrupt it
  exec 9>"$WORK/.lock"
  flock -n 9 || die "another build is already using $WORK"
fi
avail_kb="$(df -Pk "$WORK" | awk 'NR==2{print $4}')"
[ "${avail_kb:-0}" -ge 1048576 ] || die "need at least 1 GiB free in $WORK (have ${avail_kb:-0} KiB)"
if [ "${CLEAN:-0}" = 1 ]; then rm -rf "$WORK/src" "$WORK/stamp" "$WORK/prefix"; fi
mkdir -p "$WORK/src" "$WORK/stamp" "$WORK/prefix"
PREFIX="$WORK/prefix"
: > "$WORK/SOURCES.sha256"

# ---- helpers ----------------------------------------------------------------
fetch() { # fetch URL DEST  (HTTPS only - also across redirects; retries; atomic move)
  local url="$1" dest="$2"
  if [ -s "$dest" ]; then return 0; fi
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --retry-delay 2 \
       --connect-timeout 20 --max-time 900 -o "$dest.part" "$url" \
    || { rm -f "$dest.part"; die "download failed: $url"; }
  mv "$dest.part" "$dest"
}
sha_of() { sha256sum "$1" | awk '{print $1}'; }
verify() { # verify FILE EXPECTED_HASH|"" LABEL  -> enforce the pin, or record the hash
  local f="$1" want="$2" label="$3" got
  got="$(sha_of "$f")"
  if [ -n "$want" ]; then
    [ "$got" = "$want" ] || die "$label SHA-256 mismatch: expected $want, got $got (delete $f and retry; do not bypass)"
  else
    [ "${STRICT_PINS:-0}" != 1 ] || die "$label has no pinned SHA-256 and STRICT_PINS=1 (computed $got)"
    warn "$label unpinned; computed sha256=$got"
  fi
  echo "$got  $(basename "$f")" >> "$WORK/SOURCES.sha256"
}
untar() { # untar TARBALL DIR  (fresh directory, no foreign ownership when run as root)
  rm -rf "$2"; mkdir -p "$2"
  tar --no-same-owner -xf "$1" -C "$2" --strip-components=1
}
run_logged() { # run_logged LOG cmd... : quiet unless VERBOSE=1; shows the log tail on failure
  local logf="$1"; shift
  if [ "${VERBOSE:-0}" = 1 ]; then "$@" 2>&1 | tee "$logf"; return "${PIPESTATUS[0]}"; fi
  if ! "$@" >"$logf" 2>&1; then
    tail -n 30 "$logf" >&2; printf 'ERROR: step failed; full log: %s\n' "$logf" >&2; return 1
  fi
}

# ---- C library: private musl (default) or the host's musl-gcc ------------------
MUSL_ID="$MUSL_VER"; MUSL_SRC=""
build_musl() {
  local dir="$MUSL_DIR/$MUSL_VER-$TARGET_ARCH" inst tgz u ok=0 wrapper cfgopt=""
  inst="$dir/inst"; tgz="$MUSL_DIR/musl-$MUSL_VER.tar.gz"; MUSL_SRC="$dir/src"
  if [ ! -s "$tgz" ]; then
    for u in "https://musl.libc.org/releases/musl-$MUSL_VER.tar.gz" \
             "https://archive.ubuntu.com/ubuntu/pool/universe/m/musl/musl_$MUSL_VER.orig.tar.gz"; do
      if curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 2 \
              --connect-timeout 20 --max-time 300 -o "$tgz.part" "$u"; then
        mv "$tgz.part" "$tgz"; ok=1; break
      fi
      rm -f "$tgz.part"; warn "could not fetch $u"
    done
    [ "$ok" = 1 ] || die "cannot download musl $MUSL_VER (place musl-$MUSL_VER.tar.gz in $MUSL_DIR)"
  fi
  verify "$tgz" "${MUSL_SHA256:-$(pin_for musl "$MUSL_VER")}" "musl-$MUSL_VER"
  if [ -x "$inst/bin/musl-gcc" ]; then CC="$inst/bin/musl-gcc"; return 0; fi

  log "Building musl $MUSL_VER for $TARGET_ARCH (one-time)"
  mkdir -p "$dir"
  wrapper="$dir/gcc-wrapper"
  case "$BITS:$HOST_M" in
    32:x86_64)  # gcc -m32 needs the multilib runtime; i386 linker emulation (musl specs drop -m)
      printf 'int main(void){return 0;}\n' > "$dir/t.c"
      gcc -m32 -o "$dir/t32" "$dir/t.c" 2>/dev/null \
        || die "gcc cannot build 32-bit programs (Debian/Ubuntu: apt install gcc-multilib)"
      rm -f "$dir/t.c" "$dir/t32"
      printf '#!/bin/sh\nexec gcc -m32 -march=i686 -mtune=generic -Wl,-m,elf_i386 "$@"\n' > "$wrapper"
      cfgopt="--target=i386" ;;
    32:i?86)
      printf '#!/bin/sh\nexec gcc -march=i686 -mtune=generic "$@"\n' > "$wrapper" ;;
    *)
      printf '#!/bin/sh\nexec gcc "$@"\n' > "$wrapper" ;;
  esac
  chmod +x "$wrapper"
  untar "$tgz" "$MUSL_SRC"
  rm -rf "$inst"
  run_logged "$dir/build.log" bash -c '
    cd "$1" && ./configure --prefix="$2" --disable-shared $3 CC="$4" &&
    make -j"$5" AR=ar RANLIB=ranlib && make install AR=ar RANLIB=ranlib' _ \
    "$MUSL_SRC" "$inst" "$cfgopt" "$wrapper" "$JOBS" || die "musl build failed"
  CC="$inst/bin/musl-gcc"
}
if [ "$MUSL_MODE" = build ]; then
  build_musl
else
  CC="${TARGET_CC:-musl-gcc}"; MUSL_ID="system"
  need "$CC"
  if [ "$BITS" = 32 ] && [ "$HOST_M" = x86_64 ] && [ -z "${TARGET_CC:-}" ]; then
    die "--arch 32 with MUSL_MODE=system on a 64-bit host needs TARGET_CC=<32-bit musl-gcc>"
  fi
fi

log "Checking $CC can build and run a static binary"
printf 'int main(void){return 0;}\n' > "$WORK/t.c"
"$CC" -static -o "$WORK/t" "$WORK/t.c" || die "$CC cannot link statically"
"$WORK/t" || die "test binary does not run on this host (32-bit programs need IA32 emulation in the kernel)"
rm -f "$WORK/t" "$WORK/t.c"

# ---- kernel headers: musl-gcc ships none, OpenSSL needs <linux/*.h> --------
KHDR="$WORK/khdr"; mkdir -p "$KHDR"
MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
for d in linux asm-generic; do
  [ -d "/usr/include/$d" ] || die "kernel headers missing (apt install linux-libc-dev)"
  ln -sfn "/usr/include/$d" "$KHDR/$d"
done
if   [ -n "$MULTIARCH" ] && [ -d "/usr/include/$MULTIARCH/asm" ]; then ln -sfn "/usr/include/$MULTIARCH/asm" "$KHDR/asm"
elif [ -d /usr/include/asm ]; then ln -sfn /usr/include/asm "$KHDR/asm"
else die "asm/ kernel headers not found"; fi
CFLAGS_BASE="$CFLAGS_BASE -idirafter $KHDR"

# ---- resolve + download sources ---------------------------------------------
if [ "$OPENSSL_VER" = auto ]; then
  OPENSSL_VER="$(git ls-remote --tags --refs https://github.com/openssl/openssl "openssl-${OPENSSL_SERIES}.*" 2>/dev/null \
    | sed 's#.*refs/tags/openssl-##' | grep -E "^${OPENSSL_SERIES//./\\.}\.[0-9]+$" | sort -V | tail -1 || true)"
  if [ -z "$OPENSSL_VER" ]; then
    OPENSSL_VER="$OPENSSL_FALLBACK"
    warn "OpenSSL tag lookup failed; falling back to $OPENSSL_VER - check it is still the latest ${OPENSSL_SERIES}.x"
  fi
fi
log "Versions: elinks $ELINKS_VER, openssl $OPENSSL_VER, zlib $ZLIB_VER, musl $MUSL_ID"

SSL_TGZ="$DLDIR/openssl-$OPENSSL_VER.tar.gz"
ZLIB_TGZ="$DLDIR/zlib-$ZLIB_VER.tar.gz"
EL_TXZ="$DLDIR/elinks-$ELINKS_VER.tar.xz"
CA_PEM="$DLDIR/cacert.pem"

SSL_URL="https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz"
fetch "$SSL_URL" "$SSL_TGZ"
if [ -z "${OPENSSL_SHA256:-}" ]; then   # published next to the tarball (same origin: pin OPENSSL_SHA256 for independence)
  fetch "$SSL_URL.sha256" "$SSL_TGZ.sha256"
  OPENSSL_SHA256="$(awk '{print $1; exit}' "$SSL_TGZ.sha256")"
fi
verify "$SSL_TGZ" "$OPENSSL_SHA256" "openssl-$OPENSSL_VER"
fetch "https://github.com/madler/zlib/releases/download/v$ZLIB_VER/zlib-$ZLIB_VER.tar.gz" "$ZLIB_TGZ"
verify "$ZLIB_TGZ" "${ZLIB_SHA256:-$(pin_for zlib "$ZLIB_VER")}" "zlib-$ZLIB_VER"
fetch "https://github.com/rkd77/elinks/releases/download/v$ELINKS_VER/elinks-$ELINKS_VER.tar.xz" "$EL_TXZ"
verify "$EL_TXZ" "${ELINKS_SHA256:-$(pin_for elinks "$ELINKS_VER")}" "elinks-$ELINKS_VER"

# CA bundle (Mozilla roots via curl.se) - its hash is published next to the file.
rm -f "$CA_PEM" "$CA_PEM.sha256"
if [ -n "${CA_SRC:-}" ]; then
  [ -r "$CA_SRC" ] || die "CA_SRC not readable: $CA_SRC"
  warn "using local CA bundle $CA_SRC (not curl.se)"; cp "$CA_SRC" "$CA_PEM"
else
  fetch "https://curl.se/ca/cacert.pem" "$CA_PEM"
  fetch "https://curl.se/ca/cacert.pem.sha256" "$CA_PEM.sha256"
  [ "$(sha_of "$CA_PEM")" = "$(awk '{print $1; exit}' "$CA_PEM.sha256")" ] || die "cacert.pem checksum mismatch"
fi
ca_count="$(grep -c 'BEGIN CERTIFICATE' "$CA_PEM" || true)"
[ "${ca_count:-0}" -ge "${CA_MIN_CERTS:-50}" ] || die "CA bundle has only ${ca_count:-0} certificates (minimum ${CA_MIN_CERTS:-50})"
if grep -q 'PRIVATE KEY' "$CA_PEM"; then die "CA bundle contains a private key; refusing to package it"; fi
CA_ASOF="$(grep -m1 -i 'Certificate data from Mozilla as of' "$CA_PEM" | sed 's/^#* *//' || true)"
[ -n "$CA_ASOF" ] || CA_ASOF="date not stated in bundle (packaged $(date -u +%F))"
CA_SHA="$(sha_of "$CA_PEM")"

# ---- common build environment (no host libs may leak into the link) ---------
export CC CFLAGS="$CFLAGS_BASE" LDFLAGS="-static"   # static: configure test programs must run without a musl loader
export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"

# Stamps are keyed by version AND toolchain, so changing either rebuilds the component.
FP="$(printf '%s|%s|%s|%s' "$CC" "$CFLAGS_BASE" "$TARGET_ARCH" "$MUSL_ID" | sha256sum | cut -c1-12)"
stamp_done() { [ -e "$WORK/stamp/$1-$FP" ]; }
stamp_set()  { : > "$WORK/stamp/$1-$FP"; }

# ---- zlib ---------------------------------------------------------------------
build_zlib() {
  untar "$ZLIB_TGZ" "$WORK/src/zlib" &&
  ( cd "$WORK/src/zlib" && ./configure --static --prefix="$PREFIX" &&
    make -j"$JOBS" && make install )
}
if ! stamp_done "zlib-$ZLIB_VER"; then
  log "Building zlib $ZLIB_VER"
  run_logged "$WORK/zlib.log" build_zlib || die "zlib build failed"
  stamp_set "zlib-$ZLIB_VER"
fi

# ---- OpenSSL (static; no dlopen/async/engines -> musl and old-kernel safe) ----
# openssldir points at a path that does not exist on purpose: the binary then never reads the
# target's /etc/ssl/openssl.cnf or CA directory by default, and fails closed without a CA file.
build_openssl() {
  local T extra=""
  case "${OPENSSL_TARGET:-$ARCH}" in
    x86_64|linux-x86_64)   T=linux-x86_64 ;;
    i?86|linux-x86)        T=linux-x86 ;;
    aarch64|linux-aarch64) T=linux-aarch64 ;;
    armv7*|linux-armv4)    T=linux-armv4 ;;
    *) echo "unsupported arch '$ARCH'; set OPENSSL_TARGET (e.g. linux-x86_64)" >&2; return 1 ;;
  esac
  case "$T" in linux-x86_64|linux-aarch64) extra="enable-ec_nistp_64_gcc_128" ;; esac
  untar "$SSL_TGZ" "$WORK/src/openssl" &&
  ( cd "$WORK/src/openssl" && ./Configure "$T" \
      no-shared no-dso no-async no-engine no-afalgeng no-tests no-comp no-weak-ssl-ciphers no-legacy $extra \
      --prefix="$PREFIX" --openssldir=/opt/elinks/ssl --libdir=lib \
      "CC=$CC" "CFLAGS=$CFLAGS_BASE" &&
    make -j"$JOBS" build_libs && make install_sw )   # install_sw: never touches the host's /etc/ssl
}
if ! stamp_done "openssl-$OPENSSL_VER"; then
  log "Building OpenSSL $OPENSSL_VER"
  run_logged "$WORK/openssl.log" build_openssl || die "OpenSSL build failed"
  stamp_set "openssl-$OPENSSL_VER"
fi

# ---- ELinks -------------------------------------------------------------------
# musl has no matching C++ runtime, and ELinks 0.19.1 compiles exactly one C++ file in this
# configuration (protocol/map.cpp, a std::map<string,list<string>> URI-position cache). It is
# replaced with an equivalent plain-C version so the whole binary is C. The original file's
# hash is checked first so an upstream change is never silently overwritten.
write_map_c() {
  cat > src/protocol/map.c <<'CMAP'
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include "protocol/map.h"
#include "util/string.h"
#include "elinks.h"

struct pos_node { char *pos; struct pos_node *next; };
struct uri_entry { char *url; struct pos_node *head, *tail; struct uri_entry *next; };
static struct uri_entry *uri_pos_map;

static struct uri_entry *find_entry(const char *url, struct uri_entry ***link)
{
	struct uri_entry **pp = &uri_pos_map;
	for (; *pp; pp = &(*pp)->next)
		if (!strcmp((*pp)->url, url)) { if (link) *link = pp; return *pp; }
	return NULL;
}

void save_in_uri_map(char *url, char *pos)
{
	struct uri_entry *e = find_entry(url, NULL);
	struct pos_node *n = malloc(sizeof(*n));
	if (!n) return;
	n->next = NULL;
	n->pos = strdup(pos);
	if (!n->pos) { free(n); return; }
	if (!e) {
		e = calloc(1, sizeof(*e));
		if (!e) { free(n->pos); free(n); return; }
		e->url = strdup(url);
		if (!e->url) { free(e); free(n->pos); free(n); return; }
		e->next = uri_pos_map; uri_pos_map = e;
	}
	if (e->tail) e->tail->next = n; else e->head = n;
	e->tail = n;
}

char *get_url_pos(char *url)
{
	struct uri_entry **link = NULL, *e = find_entry(url, &link);
	struct pos_node *n;
	char *value;
	if (!e) return NULL;
	if (!e->head) {                       /* empty queue: drop the entry (as the C++ code did) */
		*link = e->next; free(e->url); free(e);
		return NULL;
	}
	n = e->head; e->head = n->next; if (!e->head) e->tail = NULL;
	value = stracpy(n->pos);
	free(n->pos); free(n);
	return value;
}
CMAP
}

build_elinks() {
  local got ldovr=""
  untar "$EL_TXZ" "$WORK/src/elinks" && cd "$WORK/src/elinks" || return 1
  export CPPFLAGS="-I$PREFIX/include" LDFLAGS="$LDFLAGS_BASE -L$PREFIX/lib" LIBS="-lssl -lcrypto -lz"

  if [ -f src/protocol/map.cpp ]; then
    got="$(sha_of src/protocol/map.cpp)"
    if [ "$got" != "$MAPCPP_SHA256" ] && [ "${ELINKS_ALLOW_PATCH:-0}" != 1 ]; then
      echo "src/protocol/map.cpp differs from the reviewed 0.19.1 file ($got); review the C replacement in write_map_c, then set ELINKS_ALLOW_PATCH=1" >&2
      return 1
    fi
    write_map_c || return 1
    rm -f src/protocol/map.cpp
    sed -i 's/ map\.obj / map.o /' src/protocol/Makefile || return 1
    grep -q 'map\.o ' src/protocol/Makefile || { echo "failed to patch protocol/Makefile" >&2; return 1; }
  fi

  # The release tarball ships no configure script: generate it (autoconf/automake/pkg-config).
  if [ ! -x ./configure ]; then
    sh ./autogen.sh >"$WORK/autogen.log" 2>&1 || { tail -n 20 "$WORK/autogen.log" >&2; return 1; }
  fi
  if grep -qE 'PKG_(PROG_PKG_CONFIG|CHECK_MODULES)\(' configure; then
    echo "configure still contains unexpanded PKG_ macros: install pkg-config (pkg.m4)" >&2; return 1
  fi

  ./configure --prefix=/opt/elinks --disable-nls --without-x --without-gpm \
    --with-openssl="$PREFIX" --without-gnutls --with-zlib \
    --without-bzlib --without-lzma --without-brotli --without-zstd \
    --without-lua --without-guile --without-perl --without-python --without-ruby \
    --enable-256-colors --enable-true-color || return 1
  grep -q '^#define CONFIG_OPENSSL 1' config.h || { echo "OpenSSL not enabled in config.h" >&2; return 1; }
  # ELinks partial-links objects with plain `ld -r`; a 32-bit target built on a 64-bit host needs i386 emulation.
  case "$ARCH" in i?86) ldovr="ld -m elf_i386" ;; esac
  # -j1: parallel make is reported broken upstream; CXX=$CC: nothing C++ remains, but never fall back to the host g++.
  make -j1 CXX="$CC" ${ldovr:+"LD=$ldovr"}
}
BIN_SRC="$WORK/src/elinks/src/elinks"
# Reuse the previous ELinks build only if the toolchain, every dependency version and this
# script's own ELinks build steps are unchanged (the function bodies are part of the key).
EL_KEY="elinks-$ELINKS_VER-o$OPENSSL_VER-z$ZLIB_VER-$(declare -f build_elinks write_map_c | sha256sum | cut -c1-12)"
if stamp_done "$EL_KEY" && [ -x "$BIN_SRC" ]; then
  log "ELinks $ELINKS_VER already built with these inputs (CLEAN=1 forces a rebuild)"
else
  log "Building ELinks $ELINKS_VER"
  run_logged "$WORK/elinks.log" build_elinks || die "ELinks build failed"
  [ -x "$BIN_SRC" ] || die "elinks binary was not produced"
  stamp_set "$EL_KEY"
fi

# ---- verify the artifact -------------------------------------------------------
log "Verifying binary"
elf_hdr="$(readelf -h "$BIN_SRC")"
elf_class="$(printf '%s\n' "$elf_hdr" | awk '/Class:/{print $2}')"
case "$BITS:$elf_class" in 32:ELF32|64:ELF64) ;; *) die "binary is $elf_class but a $BITS-bit build was requested" ;; esac
elf_seg="$(readelf -lW "$BIN_SRC")"
case "$elf_seg" in *INTERP*) die "binary has a program interpreter (it is dynamically linked)" ;; esac
elf_dyn="$(readelf -dW "$BIN_SRC" 2>/dev/null || true)"
case "$elf_dyn" in *NEEDED*) die "binary has shared-library dependencies" ;; esac
if grep -aq 'GLIBC_2' "$BIN_SRC"; then die "binary references glibc symbols"; fi
"$STRIP" "$BIN_SRC"
if ver_out="$("$BIN_SRC" -version 2>&1)"; then
  printf '%s\n' "$ver_out" | sed -n '1,5p'
  case "$ver_out" in *"OpenSSL $OPENSSL_VER "*) ;; *) die "binary does not report OpenSSL $OPENSSL_VER" ;; esac
else
  warn "could not run the new binary on this host; skipped the version check"
fi

# ---- package (relocatable; the launcher enforces certificate verification) ----
PKG="elinks-$ELINKS_VER-static-$ARCH"
D="$OUT/$PKG"; rm -rf "$D"; mkdir -p "$D/bin" "$D/libexec" "$D/etc" "$D/share/licenses"
install -m 0755 "$BIN_SRC" "$D/libexec/elinks.bin"
install -m 0644 "$CA_PEM"  "$D/etc/cacert.pem"

cat > "$D/bin/elinks" <<'WRAP'
#!/bin/sh
# elinks launcher (built by elinks_static_build_v6.sh). Always start ELinks through this file.
# It pins the trust store to the bundled CA file, ignores the host's OpenSSL configuration and
# CA directory, and forces certificate verification on.
#   ELINKS_CA_FILE=/path/ca.pem   use another CA bundle (e.g. bundled CAs + your company CA)
#   ELINKS_SYSTEM_CA=1            additionally trust the host's CA directory
#   ELINKS_INSECURE_TLS=1         turn certificate verification OFF for this run (unsafe; prints a warning)

# Locate this install without `readlink -f` (missing on old systems): follow symlinks by hand.
self=$0
while [ -h "$self" ]; do
  dir=$(dirname "$self")
  link=$(readlink "$self") || break
  case $link in /*) self=$link ;; *) self=$dir/$link ;; esac
done
root=$(CDPATH= cd -- "$(dirname "$self")/.." 2>/dev/null && pwd -P) || {
  echo "elinks: cannot locate the install directory" >&2; exit 1; }

ca_file=${ELINKS_CA_FILE:-$root/etc/cacert.pem}
[ -r "$ca_file" ] || { echo "elinks: CA file not readable: $ca_file" >&2; exit 1; }
SSL_CERT_FILE=$ca_file
SSL_CERT_DIR=$root/etc/no-ca-dir      # deliberately absent: ignore any CA directory from the environment
if [ "${ELINKS_SYSTEM_CA:-0}" = 1 ]; then
  for d in /etc/ssl/certs /etc/pki/tls/certs; do
    if [ -d "$d" ]; then SSL_CERT_DIR=$d; break; fi
  done
fi
export SSL_CERT_FILE SSL_CERT_DIR
unset OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES

if [ "${ELINKS_INSECURE_TLS:-0}" = 1 ]; then
  echo "elinks: WARNING: TLS certificate verification is disabled (ELINKS_INSECURE_TLS=1)" >&2
  exec "$root/libexec/elinks.bin" "$@" -eval 'set connection.ssl.cert_verify = 0'
fi
# The enforcing option comes after "$@", so a command-line -eval cannot switch it off again.
exec "$root/libexec/elinks.bin" "$@" -eval 'set connection.ssl.cert_verify = 1'
WRAP
chmod 0755 "$D/bin/elinks"

copy_lic() { # copy_lic NAME SOURCE
  if [ -f "$2" ]; then cp "$2" "$D/share/licenses/$1"; else warn "license file not found: $2"; fi
}
copy_lic elinks-COPYING       "$WORK/src/elinks/COPYING"
copy_lic openssl-LICENSE.txt  "$WORK/src/openssl/LICENSE.txt"
copy_lic zlib-LICENSE         "$WORK/src/zlib/LICENSE"
if [ -n "$MUSL_SRC" ]; then copy_lic musl-COPYRIGHT "$MUSL_SRC/COPYRIGHT"; fi

cat > "$D/README.txt" <<EOF
ELinks $ELINKS_VER static ($ARCH), OpenSSL $OPENSSL_VER, musl libc $MUSL_ID.
Runs without any glibc dependency. Copy this directory anywhere; run bin/elinks.
Trust store: etc/cacert.pem only (Mozilla roots, $CA_ASOF). Refresh it periodically.
ELINKS_CA_FILE, ELINKS_SYSTEM_CA=1 and ELINKS_INSECURE_TLS=1 are described at the top of bin/elinks.
Built by $SCRIPT_NAME. See BUILD-INFO.txt and SOURCES.sha256.
EOF
cat > "$D/BUILD-INFO.txt" <<EOF
script:      $SCRIPT_NAME
built (UTC): $(date -u +%FT%TZ)
package:     $PKG
elinks:      $ELINKS_VER (protocol/map.cpp replaced by C, see script)
openssl:     $OPENSSL_VER
zlib:        $ZLIB_VER
libc:        musl $MUSL_ID
ca bundle:   $CA_ASOF; $ca_count certificates; sha256 $CA_SHA
build host:  $(uname -srm)
compiler:    $(gcc --version | sed -n 1p)
cflags:      $CFLAGS_BASE
EOF
cp "$WORK/SOURCES.sha256" "$D/SOURCES.sha256"

# optional online smoke test through the launcher
if [ -n "${SELFTEST_URL:-}" ]; then
  log "Self-test: $SELFTEST_URL"
  mkdir -p "$WORK/home"
  st_out=""
  if command -v timeout >/dev/null 2>&1; then
    st_out="$(HOME="$WORK/home" timeout 45 "$D/bin/elinks" -no-home -dump "$SELFTEST_URL" 2>&1 || true)"
  fi
  case "$st_out" in
    ""|*"SSL error"*|*"ELinks: "*)
      warn "self-test failed: $(printf '%s' "$st_out" | sed -n 1p)"
      [ "${SELFTEST_STRICT:-0}" != 1 ] || die "self-test failed" ;;
    *) printf '%s\n' "$st_out" | sed -n '1,8p' ;;
  esac
fi

tar_opts="--owner=0 --group=0 --numeric-owner"
tar_help="$(tar --help 2>&1 || true)"
case "$tar_help" in *--sort*) tar_opts="$tar_opts --sort=name" ;; esac
# shellcheck disable=SC2086  # tar_opts is a deliberate word list
( cd "$OUT" && tar $tar_opts -czf "$PKG.tar.gz" "$PKG" && sha256sum "$PKG.tar.gz" > "$PKG.tar.gz.sha256" )
log "Done: $OUT/$PKG.tar.gz  (sha256 $(awk '{print $1}' "$OUT/$PKG.tar.gz.sha256"))"
