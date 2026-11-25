# Static Links for Legacy Linux (v2): Program description

This package is a text-mode web browser (Links) with modern TLS that runs on an old Linux machine, including one with glibc 2.8, because it is one static file that needs nothing from the host's libraries. A companion build script, `build_links_static_v2.sh`, rebuilds it from source. Both live in the `links-static-musl` folder of the `evalrjcom/mitre-recon` repository on GitHub.

Related guides: [Administrator guide](links_static_v2_admin_guide.md), [User guide](links_static_v2_user_guide.md).

## Why it exists

A Links built on a current distribution needs a newer glibc than 2.8 provides, so it will not start. The distribution's own OpenSSL on such a machine is also too old for current websites. This package avoids both problems by linking everything statically against musl libc, so it does not use the host's libc, OpenSSL or zlib.

## Files in the repository folder

| File | Purpose |
| --- | --- |
| `links-2.29-static-x86_64-musl_pkg2.tar.gz` | Prebuilt x86_64 package. |
| `build_links_static_v2.sh` | Build script (POSIX sh). Builds zlib, OpenSSL and Links against musl, packages the result and checks it. |
| `links_static_v2_*.md` | These guides. |
| `README.md` | Short overview of the folder. |

## What is in the tarball

| File | Purpose |
| --- | --- |
| `links` | The static Links executable (7.5 MB, stripped). |
| `links-color` | Launcher script. Points OpenSSL at the bundled roots only, defaults the terminal to 256 colours, then starts `links`. Always start Links through this. |
| `cacert.pem` | Mozilla root certificates (113), used to verify HTTPS sites. |
| `SHA256SUMS` | Checksums of `links`, `cacert.pem` and `links-color`. |
| `README.txt` | Versions and source checksums of this build. |
| `docs/` | These three guides. |

## Versions in the prebuilt package

| Component | Version | Notes |
| --- | --- | --- |
| Links | 2.29 | From the Ubuntu `universe` orig tarball, checked against a pinned SHA-256. |
| OpenSSL | 3.5.4 | Long-term-support line. TLS 1.2 and 1.3. SHA-256 matches the value published on the OpenSSL release page. |
| zlib | 1.3.1 | Lets Links accept gzip and deflate responses. |
| musl libc | 1.2.4 | From Ubuntu 24.04's `musl-tools`. |
| Compiler | GCC 14.2 | Package revision 2 was built with GCC 14.2 through `musl-gcc`. |
| CA bundle | certifi 2026.11.20 | Mozilla roots, 113 certificates. |

## What it can and cannot do

**Can:** HTTP and HTTPS with certificate checking, HTML tables and frames, forms, cookies, bookmarks, history, downloads, HTTP/SOCKS proxies, FTP, IPv4 and IPv6, gzip/deflate compression, colour in a 16- or 256-colour terminal, `-dump` to print a page as text, `-source` to fetch raw data.

**Cannot:** run JavaScript, show images (text mode only), decompress bzip2, xz, brotli or zstd responses (those libraries are not built in, so Links does not ask for them), or run on anything but x86_64 (the prebuilt package).

## How certificate trust works

1. `links-color` sets `SSL_CERT_FILE` to the bundled `cacert.pem` and sets `SSL_CERT_DIR` to a directory that does not exist. Links then trusts **only** the bundled roots, never the host's own certificate store, which on an old machine may be stale.
2. The binary's built-in trust path is `/etc/ssl`. If you start `links` directly without the launcher, OpenSSL falls back to `/etc/ssl/cert.pem` and `/etc/ssl/certs`; if the host has current roots there, it works, otherwise every HTTPS site reports an invalid certificate. Use the launcher.
3. Links' default policy is to **warn** on an invalid certificate. Set `ssl.certificates 2` to reject instead (administrator guide).

## Checks that were run on the prebuilt package

- Statically linked ELF with no dynamic section and no `GLIBC_` symbols; `links -version` reports 2.29.
- A TLS connection through the build machine's HTTPS proxy, verified against that proxy's CA, with `ssl.certificates 2`: succeeded.
- The same connection with the bundled roots only, and with an empty trust store: both rejected with "Invalid certificate".
- The launcher works when called through a symlink.
- GitHub Actions (`ubuntu-latest`, v2): the build, a direct HTTPS fetch of example.com with only the bundled roots (succeeded) and with no roots (rejected).

**Not tested:** running on a glibc 2.8 machine or an old kernel (musl expects roughly Linux 2.6.32 or newer); gzip decoding against a live server (zlib is linked in, but no check requests a compressed page); IPv6 connections; the build script on Alpine or with `RUN_NET_TEST=1`.

## Provenance

| Source | SHA-256 |
| --- | --- |
| `links2_2.29.orig.tar.bz2` | `22aa96c0b38e1a6f8f7ed9d7a4167a47fc37246097759ef6059ecf8f9ead7998` |
| `openssl-3.5.4.tar.gz` | `967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99` |
| `zlib-1.3.1.tar.gz` | `9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23` |
| `cacert.pem` (certifi 2026.11.20) | `bb92c6ac31c92f4f553bffd6bf093db02c858c23e111b0b4df9bafa3fdbe00d1` |

The Links tarball came from the Ubuntu archive because `links.twibright.com` was unreachable from the build machine; its hash could not be compared with a value from the Links authors, so check it against a trusted copy if provenance matters.

## Licence

Links is GPL v2 or later. OpenSSL 3.x is Apache 2.0. zlib is the zlib licence. musl is MIT. The source tarballs listed above are the corresponding source.

## Version history

| Version | Notes |
| --- | --- |
| v1 | First release in this repository. Links 2.29, OpenSSL 3.5.4, zlib 1.3.1, IPv6 on, bundle-only trust in the launcher. The build script failed on GitHub's runners (GCC 14). |
| v2 | Build script fix: Links' `configure` no longer fails on GCC 14 and later (old implicit-int C is an error there; the script now pins `-std=gnu99` and downgrades those errors). Package revision 2, built with GCC 14.2. The binary's features are unchanged. |
