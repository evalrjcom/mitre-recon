#!/bin/bash
# Starts one Xvnc (:N) + one websockify/noVNC (127.0.0.1:BASE_PORT+N) per user.
# Input: /etc/kali-novnc/users.env lines "name:password" (mounted read-only).
set -u
CREDS=${CREDS_FILE:-/run/creds/users.env}
BASE_PORT=${BASE_PORT:-6080}
GEOMETRY=${GEOMETRY:-1600x900}
pids=()
trap 'kill "${pids[@]}" 2>/dev/null; exit 0' TERM INT

supervise() {  # supervise <name> <cmd...> : restart forever
  local n=$1; shift
  ( while true; do "$@"; echo "[$n] exited ($?), restarting in 2s" >&2; sleep 2; done ) &
  pids+=($!)
}

i=0
while IFS=: read -r user pass; do
  [ -z "$user" ] && continue; case $user in \#*) continue;; esac
  i=$((i+1)); disp=$i; port=$((BASE_PORT+i))
  id "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user"
  [ -d "/home/$user" ] || { mkdir -p "/home/$user"; cp -rT /etc/skel "/home/$user"; }
  echo "$user:$pass" | chpasswd
  install -d -o "$user" -g "$user" -m 700 "/home/$user/.vnc"
  printf '%s\n' "$pass" | vncpasswd -f > "/home/$user/.vnc/passwd"
  chown "$user:$user" "/home/$user/.vnc/passwd"; chmod 600 "/home/$user/.vnc/passwd"
  cat > "/home/$user/.vnc/xstartup" <<X
#!/bin/sh
unset SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS
exec dbus-launch --exit-with-session startxfce4
X
  chown "$user:$user" "/home/$user/.vnc/xstartup"; chmod 755 "/home/$user/.vnc/xstartup"
  rm -f "/tmp/.X$disp-lock" "/tmp/.X11-unix/X$disp"
  supervise "vnc-$user" su - "$user" -c \
    "Xvnc :$disp -geometry $GEOMETRY -depth 24 -localhost -rfbport $((5900+disp)) \
       -SecurityTypes VncAuth -PasswordFile \$HOME/.vnc/passwd -AlwaysShared & XP=\$!; \
     sleep 2; DISPLAY=:$disp \$HOME/.vnc/xstartup; kill \$XP; wait \$XP"
  supervise "novnc-$user" websockify --web /usr/share/novnc "127.0.0.1:$port" "127.0.0.1:$((5900+disp))"
  echo "user=$user display=:$disp novnc=127.0.0.1:$port"
done < "$CREDS"
[ "$i" -eq 0 ] && { echo "no users in $CREDS" >&2; exit 1; }
wait
