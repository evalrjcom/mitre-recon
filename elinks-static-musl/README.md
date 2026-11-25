# elinks-static-musl

Builds the official [ELinks](https://github.com/rkd77/elinks) (rkd77 fork,
0.19.1) as a fully static musl binary with current OpenSSL (3.5 LTS, TLS 1.2
and 1.3), so it runs on Linux machines whose glibc is too old for a normal
build (for example glibc 2.8). The binary uses nothing from the host: no libc,
libssl or zlib.

## File

| File | Purpose |
| --- | --- |
| `elinks_static_build_v6.sh` | Single-file bash build script for x86_64 and i686. Builds a private musl libc, zlib, OpenSSL and ELinks from hash-pinned sources and writes a package plus its `.sha256` to `./dist`. |

No prebuilt packages are committed. The GitHub Actions workflow
(`.github/workflows/elinks-static.yml`) builds both and attaches them as
workflow artifacts; a `v*` tag publishes them as a release.

## Build

Host needs: gcc, make, perl, curl, tar, xz, git, sha256sum, binutils,
autoconf, automake, pkg-config, m4 and the kernel headers (plus
`gcc-multilib` for `--arch 32`).

```sh
sudo apt install gcc make perl curl xz-utils git binutils autoconf automake \
                 pkg-config m4 linux-libc-dev gcc-multilib
chmod +x elinks_static_build_v6.sh
./elinks_static_build_v6.sh --arch 64      # x86_64 package
./elinks_static_build_v6.sh --arch 32      # i686 package
./elinks_static_build_v6.sh --arch both    # both, one download cache
./elinks_static_build_v6.sh --help         # all tunables
```

Output: `dist/elinks-0.19.1-static-<arch>.tar.gz` and a matching `.sha256`.
Run it as an ordinary user. For a reproducible build set `OPENSSL_VER` and
`OPENSSL_SHA256`, and `STRICT_PINS=1`.

## Install the package

```sh
sha256sum -c elinks-0.19.1-static-x86_64.tar.gz.sha256
tar xzf elinks-0.19.1-static-x86_64.tar.gz -C /opt
ln -sfn /opt/elinks-0.19.1-static-x86_64/bin/elinks /usr/local/bin/elinks
elinks https://example.com
```

Use `uname -m`: x86_64 takes the 64-bit package, i686 or i386 the 32-bit one.

## Security model

Always start `bin/elinks`, not `libexec/elinks.bin`. The launcher:

- turns certificate and host-name verification on, after the command line, so
  a user `-eval` cannot switch it off;
- trusts only the bundled `etc/cacert.pem` and ignores the host's OpenSSL
  config and CA directories;
- accepts `ELINKS_CA_FILE=/path/ca.pem` (another bundle),
  `ELINKS_SYSTEM_CA=1` (also trust the host's CA directory) and
  `ELINKS_INSECURE_TLS=1` (verification off for that run, with a warning).

The bundled CA file is a snapshot. Rebuild or replace it on a schedule.

## Known limits

- x86 and x86_64 only. The 32-bit build targets i686 (Pentium Pro or newer).
- Not tested on a real glibc 2.8 machine; the minimum kernel is unverified.
- musl reads only `/etc/hosts` and `/etc/resolv.conf` (no NIS or LDAP).
- No JavaScript, images, X11 or translations.
- Licences: ELinks is GPL-2.0-only and OpenSSL 3 is Apache-2.0; review before
  redistributing binaries. Texts ship in each package's `share/licenses/`.
