# Static Lynx for Legacy Linux (v6): Administrator guide

An administrator can install the prebuilt package in a few minutes, or rebuild it from source with `build_lynx_static_v6.sh`. Because Lynx is linked statically, the host's package manager will never patch it: you own its security updates.

Related guides: [Program description](lynx_static_v6_program_description.md), [User guide](lynx_static_v6_user_guide.md).

## Install the prebuilt package

1. Confirm the machine matches the build: `uname -m` must print `x86_64`. `uname -r` should show a 2.6.32 or newer kernel.
2. Check the download: `sha256sum lynx-2.9.0-static-x86_64-musl_pkg2.tar.gz` must print `49e3cba5710c5b3e82561e5d5b2b1f454bf98986dcbdf3213680339a0b4f25f1`.
3. Unpack it: `tar xzf lynx-2.9.0-static-x86_64-musl_pkg2.tar.gz -C /opt`.
4. Put it on the path: `ln -s /opt/lynx-2.9.0-static-x86_64-musl/lynx /usr/local/bin/lynx`. The launcher follows symlinks, so this is safe.
5. Test it: `lynx -version`, then `lynx -dump https://example.com | head`.

No root is needed to run it from a home directory. Always start `lynx` (the launcher), not `bin/lynx.bin`, or it will not find its certificates, config and terminal database.

## Rebuild from source

Use `build_lynx_static_v6.sh`. It builds zlib, OpenSSL, ncurses and Lynx statically against musl inside an Alpine container, so the host's own libraries do not matter.

```sh
sh build_lynx_static_v6.sh                     # host architecture, needs docker or podman
ARCH=i686 sh build_lynx_static_v6.sh           # 32-bit target
SRC_DIR=$HOME/src sh build_lynx_static_v6.sh   # use tarballs you already downloaded
```

Run it directly on Alpine as root and it skips the container. Output goes to `./lynx-out/lynx-<version>-static-<arch>.tar.gz`. A build took about 2 minutes 20 seconds in the test environment.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ARCH` | host | `x86_64`, `i686` or `aarch64` |
| `OUT` | `./lynx-out` | Output folder. Downloads are cached in `OUT/.dl`. |
| `SRC_DIR` | unset | Folder of pre-downloaded tarballs, used before any download |
| `LYNX_VER` | 2.9.3 | Lynx release to build |
| `OPENSSL_VER` | 3.5.4 | OpenSSL release (3.5 is the long-term-support line) |
| `ZLIB_VER` / `NCURSES_VER` | 1.3.1 / 6.5 | Library versions |
| `ALPINE_TAG` | 3.20 | Alpine image used for the container build |
| `LYNX_URLS` | official mirrors | Space-separated mirror list for the Lynx tarball |

The script verifies OpenSSL and the CA bundle against their published SHA-256 files and stops on a mismatch. It only prints hashes for zlib, ncurses and Lynx, so record those yourself. It also fails if the final binary has any dynamic dependency.

Files needed with `SRC_DIR`: `zlib-1.3.1.tar.gz`, `openssl-3.5.4.tar.gz`, `ncurses-6.5.tar.gz`, `lynx2.9.3.tar.gz` and `cacert.pem`. Network needs: GitHub (zlib, OpenSSL), a GNU mirror or invisible-mirror.net (ncurses), invisible-island.net or invisible-mirror.net (Lynx), and curl.se (CA bundle).

v6 has been syntax-checked but not run end to end. The delivered tarball was built with an equivalent manual procedure (`local_build_v1.sh`) on Ubuntu with `musl-tools`.

## Configuration

The launcher sets four environment variables. Export your own value first to override any of them.

| Variable | Set to | Purpose |
| --- | --- | --- |
| `SSL_CERT_FILE` | `cacert.pem` in the install folder | Root certificates for HTTPS |
| `LYNX_CFG` | `lynx.cfg` in the install folder | Main configuration file |
| `LYNX_LSS` | `lynx.lss` in the install folder | Colour styles |
| `TERMINFO_DIRS` | bundled terminfo, then system paths | Terminal capabilities |

Edit `lynx.cfg` in the install folder for system-wide settings; remove the leading `#` from a line to activate it. Users can point at their own copy with `-cfg=FILE` or `LYNX_CFG`. Settings worth changing:

| Setting | Default | Recommendation |
| --- | --- | --- |
| `CONNECT_TIMEOUT` | 18000 s (5 h) | `30`, so dead hosts fail quickly |
| `READ_TIMEOUT` | 18000 s (5 h) | `60` |
| `FORCE_SSL_PROMPT` | `PROMPT` | `NO` refuses bad certificates outright; `YES` ignores them and should never be used |
| `FORCE_COOKIE_PROMPT` | `PROMPT` | Leave as is for interactive use |
| `ACCEPT_ALL_COOKIES` | `FALSE` | Leave `FALSE` |
| `PERSISTENT_COOKIES` / `COOKIE_FILE` | `FALSE` / `~/.lynx_cookies` | Enable only if users need to stay signed in |
| `STARTFILE` | `https://lynx.invisible-island.net/` | Set to an internal home page |
| `HELPFILE` | online help | For offline help use `file://localhost/opt/lynx-2.9.0-static-x86_64-musl/share/lynx_help/lynx_help_main.html` |
| `CHARACTER_SET` / `ASSUME_CHARSET` | `iso-8859-1` | `utf-8` for UTF-8 terminals |
| `http_proxy`, `https_proxy`, `no_proxy` | unset | Set in `lynx.cfg` or the environment; the environment wins |

## Certificates

`cacert.pem` holds the 146 Mozilla roots that were current on 1 October 2026. Refresh it at least quarterly: download `https://curl.se/ca/cacert.pem` together with its `.sha256` file, check the hash, and replace the file. To use the host's own store instead, set `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`. For an internal certificate authority, append its PEM certificate to `cacert.pem`.

## Security

- **Patch by rebuilding.** OpenSSL is compiled in. When OpenSSL publishes a security release, rebuild with a new `OPENSSL_VER` and redeploy.
- **Move to 2.9.3.** The delivered 2.9.0 lacks fixes from 2.9.1 to 2.9.3.
- **Keep certificate checking strict.** Set `FORCE_SSL_PROMPT:NO` on shared or automated systems.
- **No passwords on the command line.** `-auth=id:pw` shows up in `ps` and shell history. Lynx prompts for credentials when needed.
- **Protect cookies.** If persistent cookies are on, keep `~/.lynx_cookies` readable only by its owner (`chmod 600`).
- **Lock down shared accounts.** `-anonymous`, `-restrictions=...` (run it with no list to see the options), `-nobrowse` and `-localhost` limit what a user can do.
- **Do not run as root.**

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `Lynx file ... lynx.lss is not available` | `bin/lynx.bin` started directly, or package revision 1 | Start the `lynx` launcher; use revision 2 |
| `unable to get local issuer certificate` | Root missing from `cacert.pem`, or `SSL_CERT_FILE` points elsewhere | Refresh the bundle; check `echo $SSL_CERT_FILE` |
| `Exec format error` | Wrong CPU architecture, such as a 32-bit machine | Rebuild with `ARCH=i686` |
| Crash at start, or `Function not implemented` | Kernel older than musl supports (not tested here) | Report `uname -r`; try the build on a newer kernel |
| `Error opening terminal` or garbled screen | Unknown `TERM` | `TERM=xterm lynx` or `TERM=linux lynx` |
| Host names do not resolve | Resolution depends on NIS, LDAP or `nsswitch.conf`, which musl ignores | Add the name to `/etc/hosts`; set `nameserver` in `/etc/resolv.conf` |
| Pages hang for minutes | Default timeouts are 5 hours | Set `CONNECT_TIMEOUT` and `READ_TIMEOUT` |
| Build: `Connection timed out` while fetching | A source host is slow or blocked | Use v3 or later (mirrors, IPv4 retry) or `SRC_DIR` |
| Build: `cannot stat .../share/terminfo` | Script v4 or earlier | Use v5 or later |
| Build errors under gcc 15 | C23 is the default language level | v4 or later pins `-std=gnu17` |
| Build with plain Ubuntu `musl-gcc`: `linux/mman.h` not found | That wrapper has no kernel headers | Build in the Alpine container the script uses |

## Upgrade and remove

To upgrade, unpack the new folder beside the old one and repoint the `/usr/local/bin/lynx` symlink. To remove, delete the symlink and the install folder. Per-user files stay behind: `~/.lynxrc`, `~/.lynx_cookies` and `~/lynx_bookmarks.html`.
