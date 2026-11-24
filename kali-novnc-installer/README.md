# Kali multi-user noVNC lab (Alpine + Podman + nginx)

A remote desktop lab: **one** Kali container runs N independent XFCE sessions
(Xvnc `:1..:N`) with one noVNC/websockify per user on `127.0.0.1:6081..`.
nginx on the Alpine host gives each user a path on one HTTPS port:
`https://IP/<user>/` (protected by per-user HTTP basic auth + VNC password).
For legitimate lab/training use only. Nothing here goes beyond installing a standard Kali desktop.

## Install (as root on Alpine 3.x)
```sh
# copy the folder over, then:
USERS="alice,bob,carol" PUBLIC_PORT=443 sh install.sh
# or a single file:  curl -fsSL https://<your-host>/install.sh | USERS="alice,bob" sh
```
`install.sh` is self-contained: it has the Containerfile, entrypoint, nginx template and OpenRC script built in.

| Env var | Default | Meaning |
|---|---|---|
| `USERS` | `user1,user2,user3` | comma-separated usernames |
| `PASSWORD` | – | shared password for all users |
| `PASSWORDS` | – | per-user, comma-separated, same order as USERS |
| (none set) | random 16 chars | generated, printed once, stored in `/etc/kali-novnc/users.env` (0600) |
| `PUBLIC_PORT` | `443` | HTTPS port (e.g. 8443) |
| `CONTAINER_NAME` | `kali-novnc` | podman container name |
| `DOMAIN` / `EMAIL` | – | if both are set, certbot gets a Let's Encrypt cert; otherwise a self-signed cert is used |
| `KALI_META` | `kali-linux-core` | Kali metapackage, e.g. `kali-linux-default` (large image) |
| `BASE_PORT` | `6080` | internal noVNC ports start at BASE_PORT+1 |
| `REBUILD` | `0` | `1` forces an image rebuild |

Passwords stay the same on re-runs unless you set new ones. Re-running the script is safe.

## Connect
Open `https://<IP>/<user>/`, accept the self-signed cert, sign in with basic auth,
and noVNC connects on its own. If it asks for a VNC password, enter the same password
(VNC uses only the first 8 characters).

## Add or remove users later
Run it again with the full list: `USERS="alice,bob,carol,dave" sh install.sh`.
Existing passwords are kept, the container is recreated, and home dirs
(`/var/lib/kali-novnc/home`) persist.
Note: display numbers follow list order, so put new users at the end.

## Operations
`rc-service kali-novnc start|stop|status` (enabled at boot through OpenRC) · `podman logs kali-novnc`.

## Firewall (recommended)
Only 22, 80 and PUBLIC_PORT need to be reachable. noVNC/VNC ports listen on localhost only.
```sh
apk add nftables
cat > /etc/nftables.d/kali-novnc.nft <<'N'
table inet filter {
  chain input { type filter hook input priority 0; policy drop;
    ct state established,related accept; iif lo accept; meta l4proto icmp accept;
    meta l4proto ipv6-icmp accept; tcp dport { 22, 80, 443 } accept; }
}
N
rc-update add nftables && rc-service nftables restart
```
Podman uses host networking, so no podman NAT rules are involved.

## Files
`install.sh`, `Containerfile`, `entrypoint.sh`, `nginx.conf.tmpl`, `kali-novnc.initd`.
