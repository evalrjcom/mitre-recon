# Static Links for Legacy Linux (v1): Administrator guide

For whoever installs, configures, updates and rebuilds the package. Overview: [Program description](links_static_v1_program_description.md). Day-to-day use: [User guide](links_static_v1_user_guide.md).

## 1. Requirements

- x86_64 Linux with any glibc (or none) and a kernel new enough for musl (roughly 2.6.32 or later).
- A terminal; a 256-colour terminal gives the best result.
- No other packages. No root for a per-user install.

## 2. Install

Per user:

```sh
uname -m                                    # must print x86_64
sha256sum links-2.29-static-x86_64-musl_pkg1.tar.gz
tar xzf links-2.29-static-x86_64-musl_pkg1.tar.gz -C ~/
~/links-2.29-static-x86_64-musl_pkg1/links-color -version
```

System-wide:

```sh
tar xzf links-2.29-static-x86_64-musl_pkg1.tar.gz -C /opt
chown -R root:root /opt/links-2.29-static-x86_64-musl_pkg1
ln -s /opt/links-2.29-static-x86_64-musl_pkg1/links-color /usr/local/bin/links
```

Keep `links`, `links-color` and `cacert.pem` in the same directory. The launcher resolves symlinks, so the `/usr/local/bin/links` link above works. Verify files after any copy:

```sh
cd /opt/links-2.29-static-x86_64-musl_pkg1 && sha256sum -c SHA256SUMS
```

## 3. First-run check

```sh
links -version                                  # Links 2.29
links -ssl.certificates 2 -dump https://www.kernel.org | head
```

If the second command prints page text, TLS and certificate checking work. `Invalid certificate` means see section 8.

## 4. Certificate trust

| Start method | What is trusted |
| --- | --- |
| `links-color` (or the `links` symlink to it) | Only `cacert.pem` from the package directory. |
| The `links` binary run directly | `$SSL_CERT_FILE` / `$SSL_CERT_DIR` if set; otherwise `/etc/ssl/cert.pem` and `/etc/ssl/certs` on the host. |

To trust an extra private CA, append its PEM to `cacert.pem` (keep a copy of the original) and update `SHA256SUMS`. To use the host's store instead of the bundle, edit the two `SSL_CERT_*` lines in `links-color`.

## 5. Updating the CA bundle (quarterly, and after any root distrust news)

1. On a machine with modern TLS, get a current Mozilla bundle: `https://curl.se/ca/cacert.pem`, or the `certifi` Python package (`pip download certifi --no-deps`, then unzip `certifi/cacert.pem` from the wheel).
2. Check it: `grep -c 'BEGIN CERTIFICATE' cacert.pem` (about 110 to 150 is normal), and compare its SHA-256 with the publisher's value where one is given.
3. Back up and install:
   ```sh
   cp cacert.pem cacert.pem.bak
   install -m 644 new-cacert.pem cacert.pem
   sha256sum links cacert.pem links-color > SHA256SUMS
   ```
4. Re-run the first-run check. Restore `cacert.pem.bak` if it fails.

## 6. Configuration

| Item | Path |
| --- | --- |
| Per-user directory | `~/.links/` (created with mode 0700 on first run). |
| Override | `CONFIG_DIR=/some/dir` (the directory must already exist, otherwise Links falls back to `~/.links/`). |
| Option files | `links.cfg`, `html.cfg`, `user.cfg`, read in that order; later values win. |
| Written by Links | `links.cfg` and `html.cfg` (when a user chooses Setup > Save options). It never rewrites `user.cfg`, so keep administrator settings there. |

File syntax: one option per line, `<name> <value>`, no `set`, no `=`. A comment line starts with `#` at the start of the line. A typo prints `Unknown option in config file ...` at start-up.

Recommended hardening for `user.cfg` (or flags in `links-color`):

```
ssl.certificates 2
http_do_not_track 1
http_referer 0
enable_cookies 1
save_cookies 0
save_url_history 0
```

`ssl.certificates 2` rejects invalid certificates (the default, 1, only warns). `http_referer 0` never sends a Referer. `enable_cookies 1` keeps cookies for the session (0 refuses them). `save_cookies 0` and `save_url_history 0` stop cookies and history being written to disk.

Config names use underscores (`http_referer`), except dotted ones (`ssl.certificates`). Command-line flags use hyphens: `-ssl.certificates 2`, `-http.referer 0`, `-http.do-not-track 1`, `-enable-cookies 1`. Run `links -help` for the whole list.

Restricted use: `-anonymous` blocks local file browsing and downloads and stops users editing the association table. Combine it with `-ssl.certificates 2` in `links-color` for shared terminals.

Proxies: `-http-proxy host:port`, `-https-proxy host:port`, `-socks-proxy user@host:port`, `-no-proxy-domains a,b`, `-only-proxies 1`. The same settings are in Setup > Network options.

Useful tuning flags: `-receive-timeout` (120 s), `-retries` (3), `-max-connections` (10), `-max-connections-to-host` (2), `-memory-cache-size` (1048576), `-download-dir` (current directory).

## 7. Rebuilding from source

The script builds zlib, OpenSSL and Links against musl, packages them and checks the result.

```sh
# Debian/Ubuntu build host
apt-get install build-essential perl musl-tools curl linux-libc-dev
sh build_links_static_v1.sh                      # output: ./links-out/
OUT=$HOME/out sh build_links_static_v1.sh        # choose the output directory
SRC_DIR=$HOME/src sh build_links_static_v1.sh    # use tarballs you already downloaded
RUN_NET_TEST=1 sh build_links_static_v1.sh       # also fetch https://example.com (must pass with the bundle, must fail with no roots)
```

`SRC_DIR` may hold `links-2.29.tar.bz2` (or `links2_2.29.orig.tar.bz2`), `openssl-3.5.4.tar.gz`, `zlib-1.3.1.tar.gz` and `cacert.pem`.

What the script does:

1. Downloads each source from a mirror list, then checks the pinned SHA-256 for Links, OpenSSL and zlib (it stops on a mismatch) and prints the CA bundle's hash. If `curl.se` is unreachable it takes the same roots from the `certifi` Python package.
2. Builds static zlib, then static OpenSSL with `--openssldir=/etc/ssl`, then Links with `--with-ssl --with-zlib`, text mode only.
3. Checks that the binary has no dynamic section, no `GLIBC_` symbols and reports the right version.
4. Packages `links`, `links-color`, `cacert.pem`, `SHA256SUMS`, `README.txt` and the guides found beside the script.

Other versions: set `LINKS_VER`, `OPENSSL_VER` or `ZLIB_VER` together with the matching `LINKS_SHA256`, `OPENSSL_SHA256` or `ZLIB_SHA256`. Without a pinned hash the script only prints the hash for you to compare. Set `PKG_REV` to change the package suffix and `KEEP_WORK=1` to keep the build directory.

On Debian and Ubuntu the script links a small kernel-header shim into the build because `musl-gcc` cannot see `/usr/include/linux`. On Alpine the native toolchain is used (`apk add build-base perl linux-headers curl`); that path has not been run.

Bumping the package: when the build script gets a new version, rename the three guides to the same version and update the version in their titles and in the package name, so none are left stale.

## 8. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Invalid certificate` on every HTTPS site | Started the bare `links`, and the host has no current roots in `/etc/ssl` | Use `links-color`, or export `SSL_CERT_FILE` |
| `Invalid certificate` on one site | Chain not in the bundle, expired certificate, wrong system clock | Check `date`; refresh the bundle; press `=` in Links for connection details |
| Errors on every site after months | Stale bundle or clock skew | Section 5; fix the system time |
| Corporate proxy that re-signs TLS | The proxy's CA is not in the bundle | Append that CA to `cacert.pem` (section 4) |
| Garbled box-drawing | Terminal or charset mismatch | Setup > Terminal options; toggle UTF-8 and the frames options |
| Only 8 or 16 colours | `TERM` is not 256-colour | `export TERM=xterm-256color`, then Setup > Terminal options > 256 colors |
| `Illegal instruction` or exec format error | Not an x86_64 CPU | Use an x86_64 host |
| `Permission denied` on `~/.links` | Directory owned by another user | Fix ownership or set `CONFIG_DIR` |
| Build stops with `kernel headers not found` | `linux-libc-dev` missing | `apt-get install linux-libc-dev` |
| Build stops with `checksum mismatch` | Corrupt or different download | Re-download; do not override the pin without checking the publisher's hash |

## 9. Uninstall and operations

Remove the install directory and any symlink; remove each user's `~/.links/` if you also want bookmarks, history and cookies gone.

Links writes no log files. Treat `~/.links/` as sensitive. Do not browse as root. Rebuild when OpenSSL publishes security fixes and refresh `cacert.pem` regularly.
