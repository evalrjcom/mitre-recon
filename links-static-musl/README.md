# links-static-musl

Static, musl-linked [Links](http://links.twibright.com/) (text-mode web browser) with
TLS (OpenSSL) and zlib, for Linux machines whose glibc is too old to run a normal
build (for example glibc 2.8). The binary needs nothing from the host: no libc,
libssl or zlib.

## Files

| File | Purpose |
| --- | --- |
| `links-2.29-static-x86_64-musl_pkg1.tar.gz` | Prebuilt x86_64 package (Links 2.29, OpenSSL 3.5.4, zlib 1.3.1, 113 Mozilla roots). |
| `build_links_static_v1.sh` | POSIX-sh build script. Builds zlib, OpenSSL and Links against musl on Debian/Ubuntu (`musl-tools`) or Alpine, packages the result and checks it. |
| `links_static_v1_program_description.md` | Guide 1: what the package is, contents, versions, limits. |
| `links_static_v1_admin_guide.md` | Guide 2: install, certificates, configuration, rebuild, troubleshooting. |
| `links_static_v1_user_guide.md` | Guide 3: keys, menus, colour, bookmarks, forms, options. |

SHA-256 of the tarball:
`34053d089358f5db111d208a8a8b0e4be4fac4dfab5204f9f0652cedb59c9914`

## Install the prebuilt package

```sh
uname -m                      # must print x86_64
sha256sum links-2.29-static-x86_64-musl_pkg1.tar.gz
tar xzf links-2.29-static-x86_64-musl_pkg1.tar.gz -C /opt
ln -s /opt/links-2.29-static-x86_64-musl_pkg1/links-color /usr/local/bin/links
links -version
```

Always start `links-color` (or a symlink to it), not the bare `links` file: the
launcher makes Links trust only the bundled CA file and defaults the terminal to
256 colours.

## Rebuild from source

```sh
apt-get install build-essential perl musl-tools curl linux-libc-dev   # Debian/Ubuntu
sh build_links_static_v1.sh                     # output: ./links-out/
OUT=$HOME/out sh build_links_static_v1.sh
SRC_DIR=$HOME/src sh build_links_static_v1.sh   # use pre-downloaded tarballs
RUN_NET_TEST=1 sh build_links_static_v1.sh      # also run the HTTPS pass/fail check
```

Output: `./links-out/links-2.29-static-x86_64-musl_pkg1.tar.gz`. The script stops if a
pinned SHA-256 for Links, OpenSSL or zlib does not match.

## Status and limits

- Tested on Ubuntu 24.04 x86_64: the script ran end to end; the binary is static
  (no dynamic section, no glibc symbols); TLS verification through the build
  machine's proxy succeeds with that proxy's CA and is rejected with the bundled
  roots only and with an empty trust store; the launcher works through a symlink.
- Not tested: running on glibc 2.8 or an old kernel (musl expects roughly Linux
  2.6.32 or newer); a plain un-proxied HTTPS page; gzip decoding against a live
  server; IPv6 connections; the Alpine build path; `RUN_NET_TEST=1`.
- The Links 2.29 tarball came from the Ubuntu archive (the Links site was
  unreachable from the build machine); its SHA-256 is pinned in the script but
  could not be compared with a value from the Links authors.
- Text mode only: no JavaScript, no images. x86_64 only for the prebuilt package.
- The CA bundle is a certifi 2026.11.20 snapshot; refresh `cacert.pem` regularly
  and rebuild when OpenSSL publishes security fixes.
