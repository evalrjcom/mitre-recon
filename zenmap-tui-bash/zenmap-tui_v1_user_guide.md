# Zenmap TUI v1 — User Guide

A pure-bash, Zenmap-style terminal interface for `nmap`. No `dialog`, no `tput`, no external TUI library — just ANSI escape codes and `stty raw` mode. Runs anywhere bash 4+ and `nmap` are available.

## Requirements

- `bash` 4.0+
- `nmap`
- `awk`, `stty`, `mktemp`, `wc` (standard on nearly every Linux/macOS/BSD system)

On first run, `zenmap-tui_v1.sh` checks for all of the above. If anything is missing it detects your package manager (`apt-get`, `dnf`, `yum`, `pacman`, `brew`, `pkg`, `apk`, `zypper`) and offers to install the missing pieces for you.

## Launching

```bash
chmod +x zenmap-tui_v1.sh
./zenmap-tui_v1.sh
```

The script takes over the full terminal (alternate screen buffer) and restores your shell exactly as it was on exit — no matter whether you quit normally, press `Ctrl+C`, or the terminal is closed.

## Layout

```
┌─────────────────────────────────────────────────────────────┐
│  ZENMAP TUI   Target: ... Profile: ... ○ idle                │  ← title bar
│  [S]Scan  [T]Target  [P]Profile  ←→Tabs  ↑↓Scroll  [Q]Quit   │  ← menu bar
├───────────────┬─────────────────────────────────────────────┤
│  HOSTS (n)    │ [Nmap Output] Ports  Host Details  Topology  │  ← tabs
│  ─────────────┤─────────────────────────────────────────────┤
│  ◉ 10.0.0.1   │                                              │
│  ◉ 10.0.0.5   │           (active tab content)               │
│  ○ 10.0.0.9   │                                              │
│               │                                              │
├───────────────┴─────────────────────────────────────────────┤
│  Hosts up: 2   Open ports: 7   Tab:←→  Scroll:↑↓             │  ← status bar
└─────────────────────────────────────────────────────────────┘
```

- **Sidebar** — every host discovered so far. `◉` = up, `○` = down.
- **Tabs** — switch between five views of the current scan (see below).
- **Status bar** — live counters, always visible.

## Keybindings

| Key        | Action                                              |
|------------|------------------------------------------------------|
| `S`        | Start a scan — or stop the one currently running     |
| `T`        | Edit the target (IP, CIDR range, or hostname)         |
| `P`        | Open the scan profile picker                          |
| `←` / `→`  | Switch tabs                                           |
| `↑` / `↓`  | Scroll the active pane, or move selection in Host Details / sidebar |
| `Tab`      | Cycle to the next tab                                 |
| `1`–`5`    | Jump directly to a tab by number                      |
| `R`        | Force a full screen redraw (useful after terminal resize glitches) |
| `Q`        | Quit                                                   |

## The five tabs

1. **Nmap Output** — the raw, color-coded `nmap` console output as it streams in. Open ports green, filtered yellow, closed red, host banners bold.
2. **Ports** — a flat table of every port found on every host: host, port, state, protocol, service, version.
3. **Host Details** — full detail on one host at a time (IP, hostname, status, OS guess, MAC address, open-port count, and its service list). Use `↑`/`↓` while this tab is active to move between hosts.
4. **Topology** — a simple tree view: gateway at the top, discovered hosts branching below it, each annotated with its up/down status and open-port count.
5. **Scan Info** — summary of the current/last scan: target, profile, the actual `nmap` command run, elapsed time, and host/port totals.

## Scan profiles

Press `P` to choose one:

| Profile      | Equivalent `nmap` flags | Use for                          |
|--------------|---------------------------|-----------------------------------|
| Quick Scan   | `-T4 -F`                  | Fast scan of the 100 most common ports |
| Regular      | `-sV -T4`                 | Default — service/version detection |
| Intense Scan | `-T4 -A -v`                | OS detection, scripts, traceroute, verbose |
| Ping Scan    | `-sn`                       | Host discovery only, no port scan |
| UDP Scan     | `-sU -T4`                   | UDP ports (usually needs root)     |
| OS Detection | `-O`                        | OS fingerprinting (usually needs root) |

Some profiles (UDP Scan, OS Detection, and parts of Intense Scan) require elevated privileges. Run the script with `sudo` if a scan reports permission errors.

## Setting a target

Press `T` and type any target `nmap` accepts:

- Single host: `192.168.1.10`
- CIDR range: `192.168.1.0/24`
- Hostname: `scanme.nmap.org`
- Range: `192.168.1.1-50`

## Stopping a scan

Press `S` again while a scan is running. The TUI kills the entire `nmap` process group (not just its own background job), so nothing is left running in the background after you stop it.

## Tips

- The elapsed-time clock and host list update live while a scan runs — you don't need to press anything.
- If your terminal is resized mid-scan, the layout recalculates automatically; press `R` if anything looks visually out of sync.
- All scan artifacts live in a private temporary directory (`umask 077`) that is deleted automatically on exit.
