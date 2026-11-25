# stream-live-ps v3.2.0 - Windows PowerShell Twitch streamer

**Script:** `stream_live_v3.2.0.ps1`  |  **Platform:** Windows, PowerShell 5.1+  |  **Companion to:** `stream_live.sh` (Alpine/ash)

Captures the primary Windows desktop with FFmpeg `gdigrab` and streams it to Twitch over RTMP(S), supervised by a reconnect loop.

## Requirements

| Tool | Purpose |
|------|---------|
| FFmpeg (full/GPL build, in `PATH` or `FfmpegPath`) | libx264 + aac + gdigrab (+ dshow for audio) |
| VB-Audio Virtual Cable *(optional)* | Audio capture via DirectShow |
| TightVNC Server *(optional)* | Remote desktop; opt-in with `EnableVnc` |

## Quick start

```powershell
.\stream_live_v3.2.0.ps1 -ListDevices      # find your audio device name
.\stream_live_v3.2.0.ps1 -DryRun           # validate + print the ffmpeg command (key redacted)
.\stream_live_v3.2.0.ps1                   # go live; Ctrl+C stops cleanly
```

Stream key, in order of precedence: `TwitchStreamKey` in `stream_config.psd1`, then `$env:TWITCH_STREAM_KEY`, then a masked prompt.
Copy `stream_config.example.psd1` to `stream_config.psd1` (git-ignored) to change defaults. It is a data-only file; unknown keys are rejected.

## Key changes v3.1.0 -> v3.2.0

**Bugs fixed**
- Script now pure ASCII. v3.1.0's UTF-8 em dashes inside strings broke parsing on Windows PowerShell 5.1.
- Removed `lock (...)` (not PowerShell syntax).
- Removed script-block delegates on raw threads / `CancelKeyPress` / Process events (no Runspace there). Async work moved into a compiled C# helper.
- Two writers on one log file caused sharing violations; one thread-safe sink now, with rotation.
- TightVNC start (`-controlservice -start`) exited at once and aborted the script; now `Start-Service` / `-run`. Port is verified, and only what the script started is stopped.
- "Stale process cleanup" was documented but missing; implemented (same-key ffmpeg only).
- `2>&1` on native commands threw under `$ErrorActionPreference='Stop'` (PS 5.1); native calls use captured Process I/O.
- DPI scaling gave the wrong capture size; odd sizes broke yuv420p. Process is DPI-aware, sizes rounded to even.
- `-reconnect*` flags do nothing for RTMP output; removed.
- Stall detection now requires the frame counter to advance (log growth is meaningless: ffmpeg prints progress even when blocked).
- Correct Windows argument quoting; ffmpeg launched by absolute path.
- Crash loops abort after `MaxFastFailures`; ffmpeg cannot be orphaned (Job Object) and stops gracefully (`q`).

**Security**
- Stream key redacted from every log/console line (ffmpeg echoes the full URL; v3.1.0 logged it).
- Key never printed on validation failure; env var / masked prompt supported.
- Config is `.psd1` data (v3.1.0 dot-sourced a `.ps1`), validated and whitelisted.
- Single-instance mutex per key. VNC is opt-in and warns if bound to all interfaces.

**Behaviour changes to know about**
- Default preset `veryfast` (was `ultrafast`), `BufSize` 12000k (was 6000k), VNC off, `VncPort` 5900, sidecar is `stream_config.psd1`.

## Known limits
- Stream key is still on ffmpeg's command line (visible to same-user/admin processes); RTMP (not RTMPS) sends it unencrypted.
- gdigrab captures black on a locked workstation or disconnected RDP session.
- Not executed on a live Windows host or against Twitch in this review (no PowerShell available here); run `-DryRun` first.
