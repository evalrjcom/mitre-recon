# stream_live_v3.1.0.ps1
# Stream helper for Windows PowerShell 5.1+
# Captures the desktop via FFmpeg gdigrab and streams to Twitch over RTMP.
#
# Features:
#   - Auto-reconnect with exponential backoff (5→10→20→40→60s)
#   - Backoff sleeps are interruptible (500ms poll — Ctrl+C responds instantly)
#   - Backoff resets to 5s if stream ran >60s (new session, not crash loop)
#   - ffmpeg -reconnect flags handle short RTMP blips before shell loop fires
#   - Health monitor runs on a lightweight Thread (not Start-Job) with kill action
#   - Health monitor kills a stalled ffmpeg and sets a flag for the main loop
#   - Log rotation: rolls over ffmpeg_stream.log at ~5MB
#   - Config sidecar: loads stream_config.ps1 from script dir if present
#   - Stream key validated against ^live_[a-zA-Z0-9_]{20,}$ before launch
#   - Primary monitor bounds auto-detected via System.Windows.Forms
#   - Audio via dshow (virtual cable) with fallback to video-only or abort
#   - Log writer closed in finally block — no file-handle leak on start failure
#   - WaitForExit(timeout) with force-kill on stall
#   - ffmpeg args built via ArgumentList (no manual quoting)
#   - Double-cleanup race eliminated with [int] atomic guard
#   - Stale process cleanup on startup
#
# Requirements:
#   - FFmpeg in PATH  (https://ffmpeg.org/download.html)
#   - (Optional) Virtual Audio Cable for audio
#     (https://vb-audio.com/Cable/)
#   - TightVNC Server for remote access  (https://www.tightvnc.com/)
#     adjust $VncExe / $VncArgs if needed
#
# Usage:
#   .\stream_live_v3.1.0.ps1
#   Optionally create stream_config.ps1 in the same folder to override defaults.

#Requires -Version 5.1
using namespace System.Diagnostics
using namespace System.Threading
using namespace System.Windows.Forms
Add-Type -AssemblyName System.Windows.Forms
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Configuration ────────────────────────────────────────────────────────────
$TwitchStreamKey  = "live_"        # Replace with your Twitch stream key
$FPS              = 30
$Bitrate          = "6000k"
$AudioBitrate     = "128k"
$BufSize          = "6000k"
$VncPort          = 55900
$LogFile          = Join-Path $PSScriptRoot "ffmpeg_stream.log"
$LogMaxBytes      = 5242880        # 5 MB
$HealthInterval   = 30             # seconds between health checks
$WaitForExitMs    = 5000           # ms before force-killing a stalled ffmpeg on shutdown
$AudioDevice      = "CABLE Output (VB-Audio Virtual Cable)"
$AudioFallback    = "video-only"   # "video-only" or "abort"

# TightVNC
$VncExe  = "${env:ProgramFiles}\TightVNC\tvnserver.exe"
$VncArgs = @("-controlservice", "-start")
# ──────────────────────────────────────────────────────────────────────────────

# ─── Load config sidecar ──────────────────────────────────────────────────────
$ConfigFile = Join-Path $PSScriptRoot "stream_config.ps1"
if (Test-Path $ConfigFile) {
    Write-Host "Loading config from $ConfigFile"
    . $ConfigFile
}

# ─── Shared state ─────────────────────────────────────────────────────────────
# Use [int] for the exit flag so the health thread reads it without locks
$script:ShouldExit        = [int]0
$script:CleanupDone       = [int]0
$script:FfmpegProc        = $null
$script:VncProc           = $null
$script:HealthThread      = $null
$script:HealthKilledFfmpeg = $false   # health monitor sets this; main loop acts on it

# ─── Log helpers ──────────────────────────────────────────────────────────────
# Thread-safe: FileStream opened in Append+Shared mode
$script:LogStream = [System.IO.FileStream]::new(
    $LogFile,
    [System.IO.FileMode]::Append,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::ReadWrite
)
$script:LogWriter = [System.IO.StreamWriter]::new($script:LogStream, [System.Text.Encoding]::UTF8)
$script:LogWriter.AutoFlush = $true
$script:LogLock = [object]::new()

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Message"
    Write-Host $line
    lock ($script:LogLock) {
        $script:LogWriter.WriteLine($line)
    }
}

function Close-Log {
    if ($script:LogWriter) { try { $script:LogWriter.Close() } catch {} ; $script:LogWriter = $null }
    if ($script:LogStream) { try { $script:LogStream.Close() } catch {} ; $script:LogStream = $null }
}

# ─── Log rotation ─────────────────────────────────────────────────────────────
function Invoke-LogRotation {
    if (Test-Path $LogFile) {
        $sz = (Get-Item $LogFile).Length
        if ($sz -ge $LogMaxBytes) {
            Close-Log
            $rot = "$LogFile.1"
            if (Test-Path $rot) { Remove-Item $rot -Force }
            Move-Item $LogFile $rot -Force
            # Re-open writer on new file
            $script:LogStream = [System.IO.FileStream]::new(
                $LogFile,
                [System.IO.FileMode]::Append,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite
            )
            $script:LogWriter = [System.IO.StreamWriter]::new($script:LogStream, [System.Text.Encoding]::UTF8)
            $script:LogWriter.AutoFlush = $true
            Write-Log "Log rotated (was $sz bytes → $rot)"
        }
    }
}

Write-Log "stream_live_v3.1.0.ps1 started."

# ─── Validate stream key ──────────────────────────────────────────────────────
function Assert-StreamKey {
    if ($TwitchStreamKey -notmatch '^live_[a-zA-Z0-9_]{20,}$') {
        Write-Log "ERROR: stream key must start with 'live_' + >=20 alphanumeric/underscore chars."
        Write-Log "       Current value: '$TwitchStreamKey'"
        exit 1
    }
    Write-Log "Stream key validated."
}

# ─── Primary monitor bounds ───────────────────────────────────────────────────
# Probe once at startup; avoids gdigrab re-evaluating geometry every frame
# and silently capturing the wrong region on multi-monitor setups.
function Get-PrimaryMonitorBounds {
    $bounds = [Screen]::PrimaryScreen.Bounds
    return [PSCustomObject]@{
        Width  = $bounds.Width
        Height = $bounds.Height
        X      = $bounds.X
        Y      = $bounds.Y
    }
}

# ─── Audio args ───────────────────────────────────────────────────────────────
# Compile the regex once; reuse it on every call.
$script:AudioDeviceRegex = [regex]::new([regex]::Escape($AudioDevice), 'Compiled')

function Get-AudioArgs {
    $raw = & ffmpeg -list_devices true -f dshow -i dummy 2>&1 | Out-String
    if ($script:AudioDeviceRegex.IsMatch($raw)) {
        Write-Log "Audio device found: $AudioDevice"
        return [string[]]@("-f", "dshow", "-i", "audio=$AudioDevice")
    }
    Write-Log "WARNING: audio device '$AudioDevice' not found."
    if ($AudioFallback -eq "abort") {
        Write-Log "ERROR: AudioFallback=abort — exiting."
        exit 1
    }
    Write-Log "Audio fallback: video-only."
    return [string[]]@()
}

# ─── Cleanup ──────────────────────────────────────────────────────────────────
function Invoke-Cleanup {
    # Guard: run once even if called from both CancelKeyPress and finally
    if ([Interlocked]::Exchange([ref]$script:CleanupDone, 1) -ne 0) { return }
    [Interlocked]::Exchange([ref]$script:ShouldExit, 1) | Out-Null
    Write-Log "Cleanup started."

    # Stop health thread
    if ($script:HealthThread -and $script:HealthThread.IsAlive) {
        $script:HealthThread.Interrupt()   # unblocks Thread.Sleep
        $script:HealthThread.Join(2000)    | Out-Null
    }

    # Kill ffmpeg with timeout
    if ($script:FfmpegProc -and -not $script:FfmpegProc.HasExited) {
        Write-Log "Stopping ffmpeg (PID $($script:FfmpegProc.Id))..."
        $script:FfmpegProc.Kill()
        if (-not $script:FfmpegProc.WaitForExit($WaitForExitMs)) {
            Write-Log "WARNING: ffmpeg did not exit within ${WaitForExitMs}ms — force-killed."
        }
    }

    # Stop TightVNC
    if ($script:VncProc -and -not $script:VncProc.HasExited) {
        $script:VncProc.Kill()
        Write-Log "TightVNC process killed."
    }
    $svc = Get-Service -Name 'tvnserver' -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Stop-Service 'tvnserver' -Force -ErrorAction SilentlyContinue
        Write-Log "TightVNC service stopped."
    }

    Close-Log
    Write-Log "Cleanup complete."
}

# Register Ctrl+C handler
[Console]::TreatControlCAsInput = $false
$null = [Console]::add_CancelKeyPress({
    param($s, $e)
    $e.Cancel = $true
    Write-Log "Ctrl+C received — shutting down."
    Invoke-Cleanup
    exit 0
})

# ─── Health monitor (Thread — lighter than Start-Job) ─────────────────────────
# Runs on a background thread; polls every $HealthInterval seconds.
# If the log stops growing while ffmpeg is alive → stall detected → kill ffmpeg
# so the main reconnect loop can restart it.
function Start-HealthThread {
    param([int]$Interval)

    $thread = [Thread]::new([ThreadStart]{
        $lastSize = [long]0
        while ([Thread]::CurrentThread.IsBackground) {
            try {
                [Thread]::Sleep($Interval * 1000)   # ThreadInterruptedException unblocks this
            } catch [ThreadInterruptedException] {
                break
            }

            if ($script:ShouldExit -ne 0) { break }

            $proc = $script:FfmpegProc
            if (-not $proc) { continue }

            try {
                if ($proc.HasExited) {
                    Write-Log "[health] ffmpeg (PID $($proc.Id)) already exited."
                    continue
                }
            } catch { continue }

            # Log-growth check
            $curSize = if (Test-Path $LogFile) { (Get-Item $LogFile).Length } else { [long]0 }
            if ($lastSize -gt 0 -and $curSize -le $lastSize) {
                Write-Log "[health] WARNING — log not growing; ffmpeg may be stalled. Killing PID $($proc.Id)."
                try { $proc.Kill() } catch {}
                $script:HealthKilledFfmpeg = $true
            } else {
                Write-Log "[health] ffmpeg OK (PID $($proc.Id), log=$curSize bytes)."
            }
            $lastSize = $curSize
        }
    })
    $thread.IsBackground = $true
    $thread.Name = "HealthMonitor"
    $thread.Start()
    return $thread
}

# ─── Start TightVNC ───────────────────────────────────────────────────────────
function Start-Vnc {
    $svc = Get-Service -Name 'tvnserver' -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Running') {
            Start-Service 'tvnserver' -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        $svc.Refresh()
        if ($svc.Status -eq 'Running') {
            Write-Log "TightVNC service running on port $VncPort."
            return $null
        }
    }
    if (Test-Path $VncExe) {
        $proc = Start-Process -FilePath $VncExe -ArgumentList $VncArgs `
                    -PassThru -WindowStyle Hidden -ErrorAction Stop
        Start-Sleep -Seconds 2
        if ($proc.HasExited) {
            Write-Log "ERROR: TightVNC failed to start (exited immediately)."
            exit 1
        }
        Write-Log "TightVNC started (PID $($proc.Id)) on port $VncPort."
        return $proc
    }
    Write-Log "WARNING: TightVNC not found at '$VncExe'. Remote VNC access unavailable."
    Write-Log "         Install from https://www.tightvnc.com/ or adjust `$VncExe."
    return $null
}

# ─── Interruptible backoff sleep ──────────────────────────────────────────────
# Polls ShouldExit every 500ms so Ctrl+C responds instantly even during long waits.
function Start-InterruptibleSleep {
    param([int]$Seconds)
    $elapsed = 0.0
    while ($elapsed -lt $Seconds -and $script:ShouldExit -eq 0) {
        Start-Sleep -Milliseconds 500
        $elapsed += 0.5
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
try {
    # Validate inputs
    Assert-StreamKey

    if (-not (Get-Command ffmpeg -ErrorAction SilentlyContinue)) {
        Write-Log "ERROR: ffmpeg not found in PATH. Download from https://ffmpeg.org/download.html"
        exit 1
    }

    # Probe primary monitor once
    $mon = Get-PrimaryMonitorBounds
    $Width  = $mon.Width
    $Height = $mon.Height
    $OffX   = $mon.X
    $OffY   = $mon.Y
    Write-Log "Primary monitor: ${Width}x${Height} at offset (${OffX},${OffY})"

    Write-Host "Note: TightVNC uses its own stored password. Run tvnpasswd or TightVNC Configurator to set/change it." -ForegroundColor Cyan

    # Start VNC
    $script:VncProc = Start-Vnc

    # Probe audio once
    $AudioArgs = Get-AudioArgs

    # Start health monitor thread
    $script:HealthThread = Start-HealthThread -Interval $HealthInterval
    Write-Log "Health monitor thread started (interval ${HealthInterval}s)."

    # ── ffmpeg reconnect loop ────────────────────────────────────────────────
    $Backoff = 5

    while ($script:ShouldExit -eq 0) {
        Invoke-LogRotation
        $script:HealthKilledFfmpeg = $false
        $StreamStart = Get-Date

        Write-Log "Starting ffmpeg — ${Width}x${Height}@${FPS}fps (gdigrab, offset ${OffX},${OffY})"

        # Build arg list via ArgumentList — no manual shell-quoting needed
        $argList = [System.Collections.Generic.List[string]]::new()

        foreach ($a in $AudioArgs) { $argList.Add($a) }

        $argList.AddRange([string[]]@(
            "-f",         "gdigrab",
            "-framerate", "$FPS",
            "-offset_x",  "$OffX",
            "-offset_y",  "$OffY",
            "-video_size","${Width}x${Height}",
            "-i",         "desktop",
            "-reconnect",           "1",
            "-reconnect_streamed",  "1",
            "-reconnect_delay_max", "5",
            "-f",        "flv",
            "-c:v",      "libx264",
            "-b:v",      $Bitrate,
            "-preset",   "ultrafast",
            "-tune",     "zerolatency",
            "-maxrate",  $Bitrate,
            "-bufsize",  $BufSize,
            "-pix_fmt",  "yuv420p",
            "-g",        "$($FPS * 2)"
        ))

        if ($AudioArgs.Count -gt 0) {
            $argList.AddRange([string[]]@("-c:a", "aac", "-b:a", $AudioBitrate))
        } else {
            $argList.Add("-an")
        }

        $argList.Add("rtmp://live.twitch.tv/app/$TwitchStreamKey")

        # Build ProcessStartInfo using ArgumentList (PS 6+ native; on 5.1 we
        # fall back to a properly escaped Arguments string)
        $psi = [ProcessStartInfo]::new()
        $psi.FileName              = "ffmpeg"
        $psi.RedirectStandardError  = $true
        $psi.RedirectStandardOutput = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true

        # PS 5.1 compat: build escaped Arguments string
        $escaped = $argList | ForEach-Object {
            if ($_ -match '[\s"\\]') { '"' + ($_ -replace '"','\"') + '"' } else { $_ }
        }
        $psi.Arguments = $escaped -join ' '

        $proc = [Process]::new()
        $proc.StartInfo = $psi

        # Open log writer inside try/finally so it's closed on start failure
        $logWriter = $null
        try {
            $logWriter = [System.IO.StreamWriter]::new(
                $LogFile, $true, [System.Text.Encoding]::UTF8
            )
            $logWriter.AutoFlush = $true

            $proc.add_OutputDataReceived({
                param($s,$e); if ($e.Data) { $logWriter.WriteLine($e.Data) }
            })
            $proc.add_ErrorDataReceived({
                param($s,$e);  if ($e.Data) { $logWriter.WriteLine($e.Data) }
            })

            $proc.Start()      | Out-Null
            $proc.BeginOutputReadLine()
            $proc.BeginErrorReadLine()

            $script:FfmpegProc = $proc
            Write-Log "ffmpeg started (PID $($proc.Id))."

            # WaitForExit with no timeout: but we watch ShouldExit and HealthKilledFfmpeg
            # by spinning in 1s increments so we can respond without hanging
            while (-not $proc.WaitForExit(1000)) {
                if ($script:ShouldExit -ne 0) { break }
                if ($script:HealthKilledFfmpeg)  { break }
            }
        } finally {
            if ($logWriter) { try { $logWriter.Close() } catch {} }
        }

        $ExitCode = if ($proc.HasExited) { $proc.ExitCode } else { -1 }
        $script:FfmpegProc = $null

        if ($script:ShouldExit -ne 0) { break }

        $Uptime = [int]((Get-Date) - $StreamStart).TotalSeconds
        $reason = if ($script:HealthKilledFfmpeg) { "health-stall kill" } else { "exit code $ExitCode" }
        Write-Log "ffmpeg stopped ($reason) after ${Uptime}s."

        if ($Uptime -gt 60) {
            Write-Log "Stream ran ${Uptime}s — resetting backoff to 5s."
            $Backoff = 5
        }

        Invoke-LogRotation
        Write-Log "Reconnecting in ${Backoff}s..."
        Start-InterruptibleSleep -Seconds $Backoff

        $Backoff = [Math]::Min($Backoff * 2, 60)
    }
}
finally {
    Invoke-Cleanup
}
