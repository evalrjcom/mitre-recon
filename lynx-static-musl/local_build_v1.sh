#!/bin/sh
# Local sandbox build: static musl Lynx 2.9.0 (upstream) + OpenSSL 3.5.4 + ncurses 6.4 + zlib 1.3.1
set -eu
S=/home/claude/src
W=/home/claude/build
DEPS=$W/deps
rm -rf "$W"; mkdir -p "$W" "$DEPS"
JOBS=$(nproc)
export CC="musl-gcc"
export CFLAGS="-O2 -fPIC -fstack-protector-strong"
export PKG_CONFIG_PATH="$DEPS/lib/pkgconfig"
cd "$W"

un() { mkdir -p "$2"; tar -xf "$1" -C "$2" --strip-components=1; }

echo ">> zlib"
un "$S/zlib-1.3.1.tar.gz" zlib; cd zlib
./configure --prefix="$DEPS" --static >/dev/null
make -j"$JOBS" >/dev/null && make install >/dev/null
cd "$W"

echo ">> openssl"
un "$S/openssl-3.5.4.tar.gz" openssl; cd openssl
./Configure linux-x86_64 --prefix="$DEPS" --openssldir="$DEPS/ssl" --libdir=lib \
  no-shared no-dso no-tests no-docs no-ktls no-afalgeng no-comp no-ssl3 no-weak-ssl-ciphers \
  -static -fPIC >/dev/null
make -j"$JOBS" build_libs >/dev/null
make install_dev >/dev/null
cd "$W"

echo ">> ncurses"
un "$S/ncurses_6.4+20240113.orig.tar.gz" ncurses; cd ncurses
./configure --prefix="$DEPS" --without-shared --with-normal --without-debug \
  --without-cxx --without-cxx-binding --without-ada --without-tests --without-manpages \
  --enable-widec --enable-pc-files --with-pkg-config-libdir="$DEPS/lib/pkgconfig" \
  --with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo:/usr/lib/terminfo \
  --with-default-terminfo-dir=/usr/share/terminfo --disable-stripping \
  --with-build-cc=gcc >/dev/null
make -j"$JOBS" >/dev/null
make install DESTDIR="$W/ncstage" >/dev/null
cp -a "$W/ncstage$DEPS/." "$DEPS/"
TERMINFO_SRC="$(find "$W/ncstage" -type d -name terminfo | head -n1)"
[ -d "$TERMINFO_SRC" ] || { echo "no terminfo"; exit 1; }
cd "$W"

echo ">> lynx"
un "$S/lynx_2.9.0rel.0.orig.tar.bz2" lynx; cd lynx
CPPFLAGS="-I$DEPS/include -I$DEPS/include/ncursesw" LDFLAGS="-static -L$DEPS/lib" \
./configure --prefix=/opt/lynx --with-ssl="$DEPS" --with-zlib --with-screen=ncursesw \
  --disable-nls --enable-ipv6 --enable-default-colors --enable-color-style --disable-echo >/dev/null
make -j"$JOBS" >/dev/null
make install DESTDIR="$W/stage" >/dev/null
echo ">> build ok"
echo "$TERMINFO_SRC" > "$W/terminfo_src"
