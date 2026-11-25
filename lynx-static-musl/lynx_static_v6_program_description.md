# Static Lynx for Legacy Linux (v6): Program description

This package is a text-mode web browser (Lynx) with modern TLS that runs on an old Linux machine, including one with glibc 2.8, because it is one static file that needs nothing from the host's libraries. A companion build script, `build_lynx_static_v6.sh`, rebuilds it from source. Both live in the `lynx-static-musl` folder of the `evalrjcom/mitre-recon` repository on GitHub.

Related guides: [Administrator guide](lynx_static_v6_admin_guide.md), [User guide](lynx_static_v6_user_guide.md).

## Why it exists

A Lynx built on a current distribution needs newer glibc than 2.8 provides, so it will not start. The distribution's own OpenSSL on such a machine is also too old for current websites. This package avoids both problems by linking everything statically against musl libc, so it does not use the host's libc, OpenSSL, ncurses or zlib.

## Files in the repository folder

| File | Purpose |
| --- | --- |
| `lynx-2.9.0-static-x86_64-musl_pkg2.tar.gz` | Prebuilt x86_64 package. |
| `build_lynx_static_v6.sh` | Build script (Alpine/musl container). Defaults to Lynx 2.9.3. |
| `local_build_v1.sh` | The manual build used to produce the prebuilt package's binary. |
| `lynx_static_v6_*.md` | These guides. |

## What is in the tarball

| File | Purpose |
| --- | --- |
| `lynx` | Launcher script. Sets the CA file, config file, colour-style file and terminfo path, then starts the real binary. Always start Lynx through this. |
| `bin/lynx.bin` | The static Lynx executable (7.6 MB, stripped). |
| `lynx.cfg` | Lynx's configuration file, as installed by its build. |
| `lynx.lss` | Colour-style file. |
| `cacert.pem` | Mozilla root certificates (146), used to verify HTTPS sites. |
| `share/terminfo/` | Terminal database, so the screen works even if the host has none. |
| `share/lynx_help/` | Offline copy of Lynx's help pages and user guide. |

## Versions in the delivered build

| Component | Version |
| --- | --- |
| Lynx | 2.9.0 (15 Jan 2024), unmodified upstream source |
| OpenSSL | 3.5.4 (LTS line), TLS 1.3 supported |
| ncurses | 6.4 (20240113), wide-character build for UTF-8 |
| zlib | 1.3.1 |
| C library | musl 1.2.4, static |
| Platform | x86_64 Linux |
| Package revision | 2: adds the colour-style file and offline help that revision 1 left out |
| Tarball | `lynx-2.9.0-static-x86_64-musl_pkg2.tar.gz`, 4,140,952 bytes, SHA-256 `49e3cba5710c5b3e82561e5d5b2b1f454bf98986dcbdf3213680339a0b4f25f1` |

The build script defaults to Lynx 2.9.3, the 27 May 2026 stable release. The delivered binary is 2.9.0 because the sandbox that built it could not reach the official download hosts for 2.9.3.

## What was tested

- The binary is statically linked, with no dynamic section and no glibc symbols.
- It negotiated TLS 1.3 and verified a certificate chain, and it rejected a certificate that was not in its CA file.
- UTF-8 text rendered correctly.

## Limits

- **Architecture:** x86_64 only. A 32-bit machine needs a separate build (`ARCH=i686`).
- **Old kernels:** musl is expected to need Linux 2.6.32 or newer. This binary has not been run on glibc 2.8 or on an old kernel.
- **Version:** 2.9.0 lacks fixes made in 2.9.1 to 2.9.3. Rebuild with the script to get 2.9.3.
- **Build script:** `build_lynx_static_v6.sh` has been run end to end only on GitHub's Ubuntu runners (see the README), not on an old system.
- **Name lookups:** musl reads `/etc/hosts` and `/etc/resolv.conf` directly and ignores `nsswitch.conf`, so NIS or LDAP host lookups will not work.
- **Compression:** gzip responses are supported through zlib. bzip2 and brotli are not built in.
- **Web content:** like all Lynx builds, no images, JavaScript or CSS layout.
