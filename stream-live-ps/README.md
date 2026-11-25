# stream-live-ps — Windows PowerShell Twitch Streamer

**Version:** v3.1.0  
**Platform:** Windows (PowerShell 5.1+)  
**Companion to:** `stream_live.sh` (Alpine/ash, Linux)

---

## What It Does

Captures your primary Windows desktop with FFmpeg's `gdigrab` and streams it to Twitch over RTMP, with:

- Auto-reconnect + exponential backoff (5 → 10 → 20 → 40 → 60s)
- Interruptible backoff sleeps — Ctrl+C responds instantly even during a 60s wait
- Health monitor thread that **kills and restarts** a stalled ffmpeg (not just logs a warning)
- Log rotation at ~5MB
- Config sidecar (`stream_config.ps1`) for keeping secrets out of version control
- Stream key validated before launch
- Primary monitor bounds auto-detected via `System.Windows.Forms.Screen`
- dshow audio (VB-Audio Virtual Cable) with video-only or abort fallback
- Thread-safe log writer closed in `finally` — no file-handle leaks
- `WaitForExit(timeout)` with force-kill on stall
- Atomic double-cleanup guard (Ctrl+C + `finally` both safe)

---

## Requirements

| Tool | Purpose | Download |
|------|---------|----------|
| **FFmpeg** | Encode + stream | https://ffmpeg.org/download.html |
| **TightVNC Server** *(optional)* | Remote desktop access | https://www.tightvnc.com/ |
| **VB-Audio Virtual Cable** *(optional)* | Audio capture | https://vb-audio.com/Cable/ |

FFmpeg must be in `PATH`.

---

## Quick Start

1. Set your stream key inside the script (or override in `stream_config.ps1`):
   ```powershell
   $TwitchStreamKey = "live_xxxxxxxxxxxxxxxxxxxx"
   ```

2. Run:
   ```powershell
   .\stream_live_v3.1.0.ps1
   ```

3. Stop with **Ctrl+C** — cleanup is immediate regardless of backoff state.

---

## Config Sidecar

Create `stream_config.ps1` in the same folder to override defaults without touching the main script:

```powershell
# stream_config.ps1
$TwitchStreamKey = "live_your_real_key_here"
$FPS             = 60
$Bitrate         = "8000k"
$AudioDevice     = "My Audio Device"
```

---

## Key Differences from v3.0.0

| Area | v3.0.0 | v3.1.0 |
|------|--------|--------|
| Health monitor | `Start-Job` (full PS process) | `System.Threading.Thread` (lightweight) |
| Health monitor action | Log warning only | **Kill stalled ffmpeg** so loop restarts it |
| Backoff sleep | `Start-Sleep` (blocks Ctrl+C up to 60s) | 500ms poll — Ctrl+C responds instantly |
| Monitor geometry | `-offset_x 0 -offset_y 0` (re-evals every frame) | Auto-detected once at startup via `Screen.PrimaryScreen` |
| ffmpeg arg quoting | Fragile regex with backtick quoting | Proper `\"` escaping, PS 5.1 compat |
| Log writer lifetime | Leaked on start failure | Closed in `finally` block |
| ffmpeg WaitForExit | No timeout (can hang forever) | 1s poll with `ShouldExit` / health-kill check |
| Cleanup race | Could run twice on fast exits | Atomic `Interlocked.Exchange` guard |
| Audio regex | Re-compiled on every call | Compiled once at startup |
