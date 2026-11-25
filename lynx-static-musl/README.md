# lynx-static-musl

Static, musl-linked [Lynx](https://lynx.invisible-island.net/) with TLS
(OpenSSL), for Linux machines whose glibc is too old to run a normal build
(for example glibc 2.8). The binary needs nothing from the host: no libc,
libssl, ncurses or zlib.

## Files

| File | Purpose |
| --- | --- |
| `lynx-2.9.0-static-x86_64-musl_pkg2.tar.gz` | Prebuilt x86_64 package (Lynx 2.9.0, OpenSSL 3.5.4, ncurses 6.4, zlib 1.3.1). |
| `build_lynx_static_v6.sh` | POSIX-sh build script. Builds everything statically against musl in an Alpine container (docker or podman) or directly on Alpine. Defaults to Lynx 2.9.3. |
| `local_build_v1.sh` | The manual build used to produce the prebuilt tarball on Ubuntu with `musl-tools`. It stops after `make install`; the packaging steps (launcher, CA bundle, terminfo, help files) are done by `build_lynx_static_v6.sh`, not by this file. |
| `lynx_static_v6_program_description.md` | Guide 1: what the package is, contents, versions, limits. |
| `lynx_static_v6_admin_guide.md` | Guide 2: install, rebuild, configure, certificates, security, troubleshooting. |
| `lynx_static_v6_user_guide.md` | Guide 3: keys, command-line options, bookmarks, cookies, certificate warnings. |

SHA-256 of the tarball:
`49e3cba5710c5b3e82561e5d5b2b1f454bf98986dcbdf3213680339a0b4f25f1`

## Install the prebuilt package

```sh
uname -m                      # must print x86_64
sha256sum lynx-2.9.0-static-x86_64-musl_pkg2.tar.gz
tar xzf lynx-2.9.0-static-x86_64-musl_pkg2.tar.gz -C /opt
ln -s /opt/lynx-2.9.0-static-x86_64-musl/lynx /usr/local/bin/lynx
lynx -version
```

Always start the `lynx` launcher, not `bin/lynx.bin`: it points Lynx at the
bundled CA file, config, colour-style file and terminfo.

## Rebuild from source

```sh
sh build_lynx_static_v6.sh                     # host architecture
ARCH=i686 sh build_lynx_static_v6.sh           # 32-bit target
SRC_DIR=$HOME/src sh build_lynx_static_v6.sh   # use pre-downloaded tarballs
```

Output: `./lynx-out/lynx-<version>-static-<arch>.tar.gz`.

## GitHub Actions

`.github/workflows/lynx-static.yml` runs on changes to this folder, on pull
requests, and on demand (Actions tab, "Run workflow"; you can set `lynx_ver`
and `openssl_ver`).

1. **lint**: `sh -n` and shellcheck on the scripts (shellcheck errors fail the job).
2. **build**: runs `build_lynx_static_v6.sh` for `x86_64` and `i686` in an Alpine
   container, then checks the package: static ELF with no dynamic section and no
   glibc symbols, all expected files present, `lynx -version`, an HTTPS fetch of
   `https://example.com` that must succeed with the bundled CA file, and the same
   fetch with no trusted roots that must fail. The tarball and a
   `SHA256SUMS-<arch>.txt` are uploaded as artifacts.
3. **release**: pushing a tag named `lynx-static-v*` (for example
   `lynx-static-v6.0`) attaches the tarballs and checksums to a GitHub release.

The workflow builds Lynx 2.9.3, the script's default, so its tarball differs
from the prebuilt 2.9.0 package committed here. Its first run is also the first
end-to-end run of `build_lynx_static_v6.sh`.

## Status and limits

- The prebuilt tarball is Lynx 2.9.0, not 2.9.3: it was built where the
  official download hosts were unreachable. Rebuild with the script for 2.9.3.
- Tested: statically linked, no glibc symbols, TLS 1.3 handshake with
  certificate verification (and rejection of an untrusted chain), UTF-8 output.
- Not tested: running on glibc 2.8 or an old kernel (musl expects roughly
  Linux 2.6.32 or newer), and a normal un-proxied HTTPS page.
- `build_lynx_static_v6.sh` is syntax-checked but has not been run end to end.
- x86_64 only for the prebuilt package.
- The CA bundle is a snapshot of the Mozilla roots from 1 October 2026; refresh
  `cacert.pem` regularly, and rebuild when OpenSSL publishes security fixes.
