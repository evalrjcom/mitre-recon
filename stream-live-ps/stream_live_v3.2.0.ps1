# stream_live_v3.2.0.ps1
# ------------------------------------------------------------------------------
# Windows PowerShell (5.1+) Twitch desktop streamer: FFmpeg gdigrab -> RTMP(S).
# Companion doc: README.md ("stream-live-ps v3.2.0")
#
# Usage:
#   .\stream_live_v3.2.0.ps1                 # stream (key from config/env/prompt)
#   .\stream_live_v3.2.0.ps1 -ListDevices    # list DirectShow audio/video devices
#   .\stream_live_v3.2.0.ps1 -DryRun         # validate everything, print ffmpeg
#                                            #   command (key redacted), exit
#   .\stream_live_v3.2.0.ps1 -ConfigPath C:\path\stream_config.psd1
#   If blocked by execution policy:
#     powershell -ExecutionPolicy Bypass -File .\stream_live_v3.2.0.ps1
#
# Changes from v3.1.0 (full audit; "FIX" = bug, "SEC" = security, "NEW" = feature)
#   FIX  File is now pure ASCII. v3.1.0 had UTF-8 em dashes inside strings; Windows
#        PowerShell 5.1 reads BOM-less files as ANSI, where byte 0x94 is a curly
#        quote, so the strings broke and the script failed to parse.
#   FIX  Removed `lock (...)`: not a PowerShell keyword (syntax error).
#   FIX  Removed script-block delegates on a raw Thread / CancelKeyPress /
#        Process events: they run with no Runspace ("There is no Runspace
#        available") and can crash the host. All async work (ffmpeg output
#        capture, stall detection, log rotation) now lives in a small compiled
#        C# helper; the PowerShell loop only polls.
#   FIX  Two writers opened the same log file (second one threw a sharing
#        violation). One shared, thread-safe LogSink now.
#   FIX  `-controlservice -start` exits immediately, so v3.1.0 aborted on a
#        healthy TightVNC. Service is started via Start-Service; app mode uses -run.
#   FIX  VncPort was only printed, never applied or checked. It is now verified
#        by probing the listening sockets, with an honest warning if absent.
#   FIX  Cleanup stopped a TightVNC service that was already running before the
#        script started. Now only stops what this script started.
#   FIX  Header claimed "stale process cleanup" that was never implemented. Done.
#   FIX  PS 5.1: `2>&1` on a native command under $ErrorActionPreference='Stop'
#        throws NativeCommandError. Native calls now use captured Process I/O.
#   FIX  Display size ignored DPI scaling (wrong capture region on 125%/150%
#        displays) and could be odd (libx264 yuv420p needs even dimensions).
#        Process is made DPI-aware; width/height are rounded down to even.
#   FIX  -reconnect* flags are HTTP-input options and do nothing for an RTMP
#        output; removed (the supervisor loop is the real reconnect logic).
#   FIX  Stall detection used "log file grew", but ffmpeg prints a progress line
#        constantly even when blocked. Now: the ffmpeg frame counter must advance.
#   FIX  Ffmpeg arg quoting follows CommandLineToArgvW rules (backslashes/quotes).
#   FIX  Ffmpeg is launched by absolute path (CreateProcess searches the current
#        directory first for a bare name -> planted ffmpeg.exe risk).
#   FIX  Fast crash loops (bad key/args) retried forever; now abort after
#        MaxFastFailures consecutive exits under 15 s.
#   FIX  Ctrl+C / console close: ffmpeg is stopped gracefully ("q") and also
#        attached to a kill-on-close Job Object so it cannot be orphaned.
#   SEC  Stream key redacted from EVERY log line and console line (ffmpeg echoes
#        the full output URL in its banner; v3.1.0 wrote it to the log).
#   SEC  Key never printed on validation failure; key can come from env var or a
#        masked prompt instead of a file.
#   SEC  Config is a data-only .psd1 (Import-PowerShellDataFile) with a key
#        whitelist and range checks; v3.1.0 dot-sourced a .ps1 (code execution).
#   SEC  Single-instance mutex per stream key; stale ffmpeg using the same key
#        is stopped at startup.
#   NEW  -DryRun / -ListDevices switches; capability preflight (libx264, aac,
#        gdigrab, dshow, rtmps); ingest TCP reachability check before each launch;
#        fixed CFR via the fps filter; optional ScaleTo; log flood guard;
#        throttled progress logging; graceful 'q' shutdown.
# ------------------------------------------------------------------------------

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$DryRun,
    [switch]$ListDevices
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Identity ------------------------------------------------------------------
# NEW(v3.2.0): single source of truth for the version string (bump with filename).
$ScriptVersion = '3.2.0'
$ScriptName    = if ($PSCommandPath) { Split-Path -Leaf $PSCommandPath } else { "stream_live_v$ScriptVersion.ps1" }
$ScriptDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:ConfigExplicit = $PSBoundParameters.ContainsKey('ConfigPath')
if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'stream_config.psd1' }

# --- Defaults (override in stream_config.psd1; see stream_config.example.psd1) --
$Config = [ordered]@{
    TwitchStreamKey    = ''                 # SEC: prefer $env:TWITCH_STREAM_KEY or the prompt
    IngestUrl          = 'rtmp://live.twitch.tv/app'
    FfmpegPath         = ''                 # '' = first ffmpeg.exe found on PATH
    Fps                = 30
    Bitrate            = '6000k'
    BufSize            = '12000k'           # FIX: 2x bitrate (Twitch guidance); was 1x
    Preset             = 'veryfast'         # CHANGE: was ultrafast (much better quality/bit)
    AudioBitrate       = '128k'
    AudioDevice        = 'CABLE Output (VB-Audio Virtual Cable)'
    AudioFallback      = 'video-only'       # 'video-only' | 'abort'
    ScaleTo            = ''                 # e.g. '1920x1080'; '' = native size
    EnableVnc          = $false             # SEC: opt-in; exposes your desktop
    VncPort            = 5900               # port TightVNC is configured to use (verified only)
    LogFile            = 'ffmpeg_stream.log'
    LogMaxBytes        = 5242880            # 5 MB, one rollover (.1)
    ProgressLogSeconds = 30                 # how often a ffmpeg progress line is logged
    HealthInterval     = 30                 # seconds between [health] log lines
    StallSeconds       = 45                 # no new frames for this long => restart ffmpeg
    MaxFastFailures    = 10                 # consecutive exits < 15 s before aborting (0 = never)
}

# --- Shared state (single-threaded: no handlers, no background threads) --------
$script:Log                = $null
$script:Job                = $null
$script:Mutex              = $null
$script:MutexOwned         = $false
$script:VncProc            = $null
$script:VncStartedService  = $false
$script:FfmpegPath         = $null
$script:CleanedUp          = $false
$script:ExitCode           = 0

# --- Compiled helper (C# 5 compatible so Windows PowerShell 5.1 can build it) ---
# FIX: replaces Thread/Start-Job/Process-event script blocks (no Runspace on those
# threads). Everything asynchronous is inside this class; PowerShell only polls.
$script:CSharpSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace StreamLive
{
    public static class Native
    {
        public const string Build = "__VERSION__";

        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();

        // FIX: without this, Screen.Bounds is DPI-virtualised and gdigrab captures
        // the wrong region on scaled displays.
        public static bool EnableDpiAwareness()
        {
            try { return SetProcessDPIAware(); }
            catch (Exception) { return false; }
        }
    }

    public static class ArgQuoter
    {
        // CommandLineToArgvW-compatible quoting (FIX: v3.1.0 regex broke on \ and ").
        public static string Quote(string a)
        {
            if (a == null) a = "";
            if (a.Length > 0 && a.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) return a;
            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            int bs = 0;
            foreach (char c in a)
            {
                if (c == '\\') { bs++; }
                else if (c == '"') { sb.Append('\\', bs * 2 + 1); sb.Append('"'); bs = 0; }
                else { if (bs > 0) { sb.Append('\\', bs); bs = 0; } sb.Append(c); }
            }
            if (bs > 0) sb.Append('\\', bs * 2);
            sb.Append('"');
            return sb.ToString();
        }

        public static string Join(string[] args)
        {
            string[] parts = new string[args.Length];
            for (int i = 0; i < args.Length; i++) parts[i] = Quote(args[i]);
            return string.Join(" ", parts);
        }
    }

    // Thread-safe log with rotation and stream-key redaction (SEC).
    public sealed class LogSink : IDisposable
    {
        private static readonly Regex KeyRx = new Regex(@"live_[A-Za-z0-9_]{12,}", RegexOptions.Compiled);
        private readonly object _lock = new object();
        private readonly string _path;
        private readonly long _maxBytes;
        private readonly string _secret;
        private StreamWriter _w;
        private long _size;

        public LogSink(string path, long maxBytes, string secret)
        {
            _path = path; _maxBytes = maxBytes; _secret = secret;
            Open();
        }

        private void Open()
        {
            // FileShare.ReadWrite|Delete: you can tail/rotate the log while it is open.
            FileStream fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            _size = fs.Length;
            _w = new StreamWriter(fs, new UTF8Encoding(false));
            _w.AutoFlush = true;
        }

        public string Redact(string s)
        {
            if (s == null) return "";
            if (!string.IsNullOrEmpty(_secret)) s = s.Replace(_secret, "live_********");
            return KeyRx.Replace(s, "live_********");
        }

        // Returns the redacted, timestamped line so PowerShell can echo the same text.
        public string Write(string message)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + Redact(message);
            lock (_lock)
            {
                if (_w != null)
                {
                    try
                    {
                        if (_size >= _maxBytes) Rotate();
                        if (_w != null)
                        {
                            _w.WriteLine(line);
                            _size += Encoding.UTF8.GetByteCount(line) + 2;
                        }
                    }
                    catch (IOException) { }
                    catch (ObjectDisposedException) { }
                }
            }
            return line;
        }

        private void Rotate()
        {
            try
            {
                _w.Dispose();
                _w = null;
                string old = _path + ".1";
                if (File.Exists(old)) File.Delete(old);
                File.Move(_path, old);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            Open();                              // always continue logging
            if (_size >= _maxBytes) _size = 0;   // rename failed: avoid rotating on every line
        }

        public void Dispose()
        {
            lock (_lock)
            {
                if (_w != null) { try { _w.Dispose(); } catch (IOException) { } _w = null; }
            }
        }
    }

    // FIX: ffmpeg cannot be orphaned if PowerShell dies or the window is closed.
    public sealed class KillOnCloseJob : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
            public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
            public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr hJob, int infoType, IntPtr lpInfo, uint cbInfo);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        private IntPtr _h;
        public bool Ready { get { return _h != IntPtr.Zero; } }

        public KillOnCloseJob()
        {
            try
            {
                _h = CreateJobObject(IntPtr.Zero, null);
                if (_h == IntPtr.Zero) return;
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                info.BasicLimitInformation.LimitFlags = 0x2000;      // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr p = Marshal.AllocHGlobal(len);
                try
                {
                    Marshal.StructureToPtr(info, p, false);
                    if (!SetInformationJobObject(_h, 9, p, (uint)len))    // 9 = ExtendedLimitInformation
                    {
                        CloseHandle(_h);
                        _h = IntPtr.Zero;
                    }
                }
                finally { Marshal.FreeHGlobal(p); }
            }
            catch (Exception) { _h = IntPtr.Zero; }
        }

        public bool Add(Process proc)
        {
            if (_h == IntPtr.Zero) return false;
            try { return AssignProcessToJobObject(_h, proc.Handle); }
            catch (Exception) { return false; }
        }

        public void Dispose()
        {
            if (_h != IntPtr.Zero) { CloseHandle(_h); _h = IntPtr.Zero; }
        }
    }

    // Owns one ffmpeg process: async output capture, progress parsing, stall clock.
    public sealed class FfmpegRunner : IDisposable
    {
        private static readonly Regex FrameRx = new Regex(@"^frame=\s*(\d+)", RegexOptions.Compiled);
        private static readonly Regex SpeedRx = new Regex(@"speed=\s*(\S+)", RegexOptions.Compiled);
        private const int MaxLinesPerSecond = 100;   // flood guard for non-progress lines
        private const int MaxLineChars = 2000;

        private readonly string _exe;
        private readonly string _args;
        private readonly LogSink _log;
        private readonly long _progressLogTicks;
        private readonly object _sync = new object();
        private Process _p;
        private long _frames;
        private long _lastAdvance;
        private long _lastProgressLog;
        private string _speed = "n/a";
        private long _winStart;
        private int _winCount;
        private int _dropped;

        public FfmpegRunner(string exe, string args, LogSink log, int progressLogSeconds)
        {
            _exe = exe; _args = args; _log = log;
            _progressLogTicks = (long)progressLogSeconds * Stopwatch.Frequency;
        }

        public int Id { get { return _p == null ? 0 : _p.Id; } }

        public bool HasExited
        {
            get { try { return _p == null || _p.HasExited; } catch (InvalidOperationException) { return true; } }
        }

        public int ExitCode
        {
            get { try { return (_p != null && _p.HasExited) ? _p.ExitCode : -1; } catch (InvalidOperationException) { return -1; } }
        }

        // Seconds since the frame counter last increased (the stall clock).
        public double SecondsSinceProgress
        {
            get { lock (_sync) { return (Stopwatch.GetTimestamp() - _lastAdvance) / (double)Stopwatch.Frequency; } }
        }

        public string Status
        {
            get { lock (_sync) { return "frames=" + _frames + " speed=" + _speed; } }
        }

        public void Start(KillOnCloseJob job)
        {
            ProcessStartInfo psi = new ProcessStartInfo(_exe, _args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardInput = true;     // lets us send "q" for a graceful stop and
            psi.RedirectStandardOutput = true;    // stops ffmpeg from reading our console
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;

            long now = Stopwatch.GetTimestamp();
            lock (_sync)
            {
                _frames = 0; _lastAdvance = now; _winStart = now; _winCount = 0; _dropped = 0;
                _lastProgressLog = now - _progressLogTicks;   // log first progress line right away
            }

            _p = new Process();
            _p.StartInfo = psi;
            _p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e) { OnLine(e.Data); };
            _p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) { OnLine(e.Data); };
            _p.Start();
            if (job != null && !job.Add(_p))
                _log.Write("[WARN] Could not attach ffmpeg to the kill-on-close job (orphan protection off).");
            _p.BeginOutputReadLine();
            _p.BeginErrorReadLine();
        }

        public bool WaitForExit(int ms)
        {
            bool exited = _p.WaitForExit(ms);
            if (exited) _p.WaitForExit();     // drain async readers
            return exited;
        }

        // Graceful: send "q" (ffmpeg flushes and closes the RTMP session), then Kill.
        public bool Stop(int graceMs)
        {
            if (_p == null) return true;
            try
            {
                if (_p.HasExited) return true;
                try { _p.StandardInput.WriteLine("q"); _p.StandardInput.Flush(); }
                catch (IOException) { }
                catch (InvalidOperationException) { }
                if (_p.WaitForExit(graceMs)) { _p.WaitForExit(); return true; }
                _p.Kill();
                return _p.WaitForExit(3000);
            }
            catch (InvalidOperationException) { return true; }      // never started / already gone
            catch (System.ComponentModel.Win32Exception) { return false; }
        }

        private void OnLine(string raw)
        {
            if (raw == null) return;
            string line = raw.Trim();
            if (line.Length == 0) return;
            if (line.Length > MaxLineChars) line = line.Substring(0, MaxLineChars) + "...";

            Match fm = FrameRx.Match(line);
            if (fm.Success)
            {
                long f;
                long now = Stopwatch.GetTimestamp();
                bool logIt = false;
                lock (_sync)
                {
                    if (long.TryParse(fm.Groups[1].Value, out f) && f > _frames) { _frames = f; _lastAdvance = now; }
                    Match sm = SpeedRx.Match(line);
                    if (sm.Success) _speed = sm.Groups[1].Value;
                    if (now - _lastProgressLog >= _progressLogTicks) { _lastProgressLog = now; logIt = true; }
                }
                if (logIt) _log.Write("[ffmpeg] " + line);   // throttled: progress is ~2 lines/s otherwise
                return;
            }

            long t = Stopwatch.GetTimestamp();
            int suppressed = 0;
            bool allow;
            lock (_sync)
            {
                if (t - _winStart >= Stopwatch.Frequency) { suppressed = _dropped; _dropped = 0; _winStart = t; _winCount = 0; }
                allow = _winCount < MaxLinesPerSecond;
                if (allow) _winCount++; else _dropped++;
            }
            if (suppressed > 0) _log.Write("[ffmpeg] (" + suppressed + " lines suppressed by flood guard)");
            if (allow) _log.Write("[ffmpeg] " + line);
        }

        public void Dispose()
        {
            if (_p != null) { try { _p.Dispose(); } catch (InvalidOperationException) { } _p = null; }
        }
    }
}
'@

# --- Logging ------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    if ($script:Log) {
        $line = $script:Log.Write("[$Level] $Message")   # redacted + timestamped
    } else {
        $line = "[$Level] $Message"                      # before the sink exists (no key yet)
    }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

# --- Config -------------------------------------------------------------------
function Import-StreamConfig {
    param([string]$Path, [bool]$Required)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        if ($Required) { throw "Config file not found: $Path" }
        return
    }
    # SEC: data-only parse; a .psd1 cannot execute code (v3.1.0 dot-sourced a .ps1).
    $user = Import-PowerShellDataFile -LiteralPath $Path
    foreach ($k in @($user.Keys)) {
        if (-not $Config.Contains($k)) {
            throw "Unknown setting '$k' in $Path. Valid: $($Config.Keys -join ', ')"
        }
        $Config[$k] = $user[$k]
    }
}

function Test-StreamConfig {
    # FIX: every value that reaches the ffmpeg command line is validated first,
    # so a typo or hostile config cannot inject extra ffmpeg arguments.
    $e = New-Object System.Collections.Generic.List[string]
    $c = $Config
    if ($c.Fps -isnot [int] -or $c.Fps -lt 1 -or $c.Fps -gt 120)                     { $e.Add('Fps must be an integer 1-120') }
    foreach ($n in 'Bitrate','BufSize','AudioBitrate') {
        if ($c[$n] -isnot [string] -or $c[$n] -cnotmatch '^[1-9][0-9]{1,5}[kKmM]$')  { $e.Add("$n must look like 6000k or 6M") }
    }
    if ($c.Preset -notin 'ultrafast','superfast','veryfast','faster','fast','medium') { $e.Add('Preset must be ultrafast|superfast|veryfast|faster|fast|medium') }
    if ($c.AudioFallback -notin 'video-only','abort')                                 { $e.Add("AudioFallback must be 'video-only' or 'abort'") }
    if ($c.AudioDevice -isnot [string] -or $c.AudioDevice.Length -gt 200 -or $c.AudioDevice.Contains('"')) { $e.Add('AudioDevice must be a string without double quotes (max 200 chars)') }
    if ($c.ScaleTo -isnot [string] -or ($c.ScaleTo -ne '' -and $c.ScaleTo -cnotmatch '^[1-9][0-9]{2,4}x[1-9][0-9]{2,4}$')) { $e.Add("ScaleTo must be '' or WIDTHxHEIGHT (e.g. 1920x1080)") }
    if ($c.IngestUrl -isnot [string] -or $c.IngestUrl -cnotmatch '^rtmps?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[A-Za-z0-9/_-]+$') { $e.Add('IngestUrl must look like rtmp://host/app or rtmps://host:443/app (no key)') }
    if ($c.EnableVnc -isnot [bool])                                                   { $e.Add('EnableVnc must be $true or $false') }
    if ($c.VncPort -isnot [int] -or $c.VncPort -lt 1 -or $c.VncPort -gt 65535)       { $e.Add('VncPort must be 1-65535') }
    if ($c.LogMaxBytes -isnot [int] -or $c.LogMaxBytes -lt 65536)                     { $e.Add('LogMaxBytes must be an integer >= 65536') }
    if ($c.ProgressLogSeconds -isnot [int] -or $c.ProgressLogSeconds -lt 1)          { $e.Add('ProgressLogSeconds must be >= 1') }
    if ($c.HealthInterval -isnot [int] -or $c.HealthInterval -lt 5 -or $c.HealthInterval -gt 600) { $e.Add('HealthInterval must be 5-600') }
    if ($c.StallSeconds -isnot [int] -or $c.StallSeconds -lt 10 -or $c.StallSeconds -gt 600)      { $e.Add('StallSeconds must be 10-600') }
    if ($c.MaxFastFailures -isnot [int] -or $c.MaxFastFailures -lt 0)                { $e.Add('MaxFastFailures must be >= 0') }
    if ($c.FfmpegPath -isnot [string])                                                { $e.Add('FfmpegPath must be a string') }
    if ($e.Count -gt 0) { throw ("Invalid configuration: " + ($e -join '; ')) }
}

function Resolve-StreamKey {
    # SEC: key from config, then $env:TWITCH_STREAM_KEY, then a masked prompt.
    # The value is NEVER echoed (v3.1.0 printed it on validation failure).
    $k = [string]$Config.TwitchStreamKey
    if (-not $k -or $k -eq 'live_') { $k = [string]$env:TWITCH_STREAM_KEY }
    if (-not $k -or $k -eq 'live_') {
        $sec  = Read-Host -Prompt 'Twitch stream key' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try   { $k = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    $k = $k.Trim()
    if ($k -cnotmatch '^live_[A-Za-z0-9_]{20,}$') {
        throw "Stream key rejected: must be 'live_' followed by 20+ letters/digits/underscores (value withheld)."
    }
    return $k
}

# --- ffmpeg helpers -----------------------------------------------------------
function Initialize-Native {
    if (-not ('StreamLive.Native' -as [type])) {
        Add-Type -TypeDefinition $script:CSharpSource.Replace('__VERSION__', $ScriptVersion) -Language CSharp
    }
    # FIX: re-running after an upgrade in the same console would silently use the
    # old compiled helper; detect that instead of misbehaving.
    if ([StreamLive.Native]::Build -ne $ScriptVersion) {
        throw "Helper type from v$([StreamLive.Native]::Build) is loaded in this session. Close this PowerShell window and start a new one."
    }
}

function Resolve-FfmpegPath {
    if ($Config.FfmpegPath) {
        if (-not (Test-Path -LiteralPath $Config.FfmpegPath -PathType Leaf)) { throw "FfmpegPath not found: $($Config.FfmpegPath)" }
        return (Resolve-Path -LiteralPath $Config.FfmpegPath).Path
    }
    # SEC: absolute path from PATH lookup; Get-Command does not search the CWD.
    $cmd = Get-Command ffmpeg -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { throw 'ffmpeg not found in PATH. Install a full build (e.g. https://www.gyan.dev/ffmpeg/builds/) or set FfmpegPath.' }
    return $cmd.Source
}

function Invoke-FfmpegCapture {
    # FIX: PS 5.1 turns native stderr into terminating errors under 'Stop'; capture via Process.
    param([string[]]$Arguments, [int]$TimeoutMs = 20000)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $script:FfmpegPath
    $psi.Arguments              = [StreamLive.ArgQuoter]::Join($Arguments)
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.RedirectStandardInput  = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding  = [Text.Encoding]::UTF8
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        $p.StandardInput.Close()
        $so = $p.StandardOutput.ReadToEndAsync()   # read both pipes concurrently: no deadlock
        $se = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutMs)) {
            try { $p.Kill() } catch { }
            throw "ffmpeg timed out after ${TimeoutMs}ms running: $($Arguments -join ' ')"
        }
        return ($se.Result + "`n" + $so.Result)
    }
    finally { $p.Dispose() }
}

function Test-FfmpegCapabilities {
    # NEW: fail early with a clear message instead of a cryptic ffmpeg exit later.
    $enc = Invoke-FfmpegCapture @('-hide_banner', '-encoders')
    if ($enc -cnotmatch '\blibx264\b') { throw 'This ffmpeg build lacks libx264. Use a "full"/GPL build.' }
    if ($enc -cnotmatch '\baac\b')     { throw 'This ffmpeg build lacks the aac encoder.' }
    $dev = Invoke-FfmpegCapture @('-hide_banner', '-devices')
    if ($dev -cnotmatch '\bgdigrab\b') { throw 'This ffmpeg build lacks gdigrab (Windows desktop capture).' }
    $hasDshow = ($dev -cmatch '\bdshow\b')
    $proto = Invoke-FfmpegCapture @('-hide_banner', '-protocols')
    if ($Config.IngestUrl.StartsWith('rtmps://') -and $proto -cnotmatch '\brtmps\b') {
        throw 'IngestUrl uses rtmps:// but this ffmpeg build has no TLS/rtmps support.'
    }
    return [pscustomobject]@{ HasDshow = $hasDshow }
}

function Get-CaptureGeometry {
    [void][StreamLive.Native]::EnableDpiAwareness()      # FIX: before any Screen query
    Add-Type -AssemblyName System.Windows.Forms
    $scr = [System.Windows.Forms.Screen]::PrimaryScreen
    if (-not $scr) { throw 'No primary screen found (locked workstation or disconnected RDP session?).' }
    $b = $scr.Bounds
    $w = $b.Width  -band -2                              # FIX: even size required by yuv420p
    $h = $b.Height -band -2
    if ($w -lt 160 -or $h -lt 120) { throw "Screen too small to capture (${w}x${h})." }
    return [pscustomobject]@{ X = $b.X; Y = $b.Y; Width = $w; Height = $h }
}

function Get-AudioArgs {
    param($Caps)
    $noAudio = {
        param($why)
        Write-Log $why 'WARN'
        if ($Config.AudioFallback -eq 'abort') { throw 'AudioFallback = abort and audio is unavailable.' }
        Write-Log 'Audio fallback: streaming video-only.'
        return [string[]]@()
    }
    if (-not $Caps.HasDshow) { return (& $noAudio 'ffmpeg has no dshow input; cannot capture audio.') }

    $out  = Invoke-FfmpegCapture @('-hide_banner', '-list_devices', 'true', '-f', 'dshow', '-i', 'dummy')
    $devs = @([regex]::Matches($out, '"([^"]+)"\s+\(audio\)') | ForEach-Object { $_.Groups[1].Value })
    $name = [string]$Config.AudioDevice
    $found = ($devs -contains $name)
    if (-not $found -and $devs.Count -eq 0) {
        # Older ffmpeg builds do not tag "(audio)": fall back to a plain quoted-name search.
        $found = ($out.IndexOf('"' + $name + '"', [StringComparison]::OrdinalIgnoreCase) -ge 0)
    }
    if ($found) {
        Write-Log "Audio device: $name"
        return [string[]]@('-thread_queue_size', '512', '-f', 'dshow', '-i', "audio=$name")
    }
    $avail = if ($devs.Count -gt 0) { ($devs | Select-Object -First 8) -join ' | ' } else { '(none detected)' }
    return (& $noAudio "Audio device '$name' not found. Available: $avail")
}

function New-FfmpegArgs {
    param($Geo, [string[]]$AudioArgs, [string]$Key)
    $fps = [int]$Config.Fps
    $outW = $Geo.Width; $outH = $Geo.Height
    $vf = "fps=$fps"                                      # NEW: forces constant frame rate (Twitch wants CFR)
    if ($Config.ScaleTo) {
        $m = [regex]::Match($Config.ScaleTo, '^(\d+)x(\d+)$')
        $outW = [int]$m.Groups[1].Value -band -2
        $outH = [int]$m.Groups[2].Value -band -2
        $srcAr = $Geo.Width / [double]$Geo.Height
        $dstAr = $outW / [double]$outH
        if ([Math]::Abs($srcAr - $dstAr) / $srcAr -gt 0.02) {
            Write-Log "ScaleTo ${outW}x${outH} has a different aspect ratio than the screen ($($Geo.Width)x$($Geo.Height)); output will be stretched." 'WARN'
        }
        if ($outW -ne $Geo.Width -or $outH -ne $Geo.Height) { $vf += ",scale=${outW}:${outH}:flags=bicubic" }
    }

    $ff = New-Object System.Collections.Generic.List[string]
    $ff.AddRange([string[]]@('-hide_banner'))
    if ($AudioArgs.Count -gt 0) { $ff.AddRange($AudioArgs) }
    $ff.AddRange([string[]]@(
        '-thread_queue_size', '512',
        '-f', 'gdigrab', '-framerate', "$fps",
        '-offset_x', "$($Geo.X)", '-offset_y', "$($Geo.Y)",
        '-video_size', "$($Geo.Width)x$($Geo.Height)",
        '-i', 'desktop',
        '-vf', $vf,
        '-c:v', 'libx264', '-preset', $Config.Preset, '-tune', 'zerolatency',
        '-b:v', $Config.Bitrate, '-maxrate', $Config.Bitrate, '-bufsize', $Config.BufSize,
        '-pix_fmt', 'yuv420p', '-g', "$($fps * 2)"
    ))
    if ($AudioArgs.Count -gt 0) {
        # aresample=async keeps dshow audio and gdigrab video clocks from drifting apart.
        $ff.AddRange([string[]]@('-c:a', 'aac', '-b:a', $Config.AudioBitrate, '-ar', '44100', '-ac', '2',
                                  '-af', 'aresample=async=1:first_pts=0'))
    } else {
        $ff.Add('-an')
    }
    $ff.AddRange([string[]]@('-f', 'flv', ($Config.IngestUrl.TrimEnd('/') + '/' + $Key)))
    return $ff.ToArray()
}

# --- Process / network helpers -------------------------------------------------
function Stop-StaleFfmpeg {
    # FIX: v3.1.0 advertised this but never did it. Only ffmpeg processes carrying
    # THIS stream key are touched, so unrelated ffmpeg jobs are safe.
    param([string]$Key)
    try { $procs = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='ffmpeg.exe'" -ErrorAction Stop) }
    catch { Write-Log "Stale-process scan skipped: $($_.Exception.Message)" 'WARN'; return }
    foreach ($p in $procs) {
        if ($p.CommandLine -and $p.CommandLine.Contains($Key)) {
            Write-Log "Stopping leftover ffmpeg PID $($p.ProcessId) that is using this stream key." 'WARN'
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }
            catch { Write-Log "Could not stop PID $($p.ProcessId): $($_.Exception.Message)" 'WARN' }
        }
    }
}

function Test-IngestReachable {
    # NEW: do not spin up the encoder while the network or ingest host is down.
    param([string]$Url, [int]$TimeoutMs = 5000)
    $u = [uri]$Url
    $port = if ($u.Port -gt 0) { $u.Port } elseif ($u.Scheme -eq 'rtmps') { 443 } else { 1935 }
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($u.Host, $port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $c.EndConnect($iar)
        return $true
    }
    catch { return $false }
    finally { $c.Close() }
}

function Get-TcpListeners {
    $out = @()
    foreach ($ep in [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()) {
        $out += $ep
    }
    return $out
}

# --- VNC (optional, TightVNC) --------------------------------------------------
function Start-VncIfEnabled {
    if (-not $Config.EnableVnc) { Write-Log 'VNC: disabled (EnableVnc = $false).'; return }
    $svc = Get-Service -Name 'tvnserver' -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') {
            Write-Log 'VNC: tvnserver service already running; it will be left running on exit.'
        } else {
            try { Start-Service -Name 'tvnserver'; $script:VncStartedService = $true; Write-Log 'VNC: started tvnserver service.' }
            catch { Write-Log "VNC: cannot start service (admin rights needed?): $($_.Exception.Message)" 'WARN'; return }
        }
    } else {
        $exe = Join-Path $env:ProgramFiles 'TightVNC\tvnserver.exe'
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Write-Log "VNC: TightVNC not found at '$exe'." 'WARN'; return }
        # FIX: '-run' = application mode. '-controlservice -start' exits at once.
        $script:VncProc = Start-Process -FilePath $exe -ArgumentList '-run' -PassThru -WindowStyle Hidden
    }
    # FIX: verify the port instead of just printing it.
    $listen = $null
    for ($i = 0; $i -lt 10 -and -not $listen; $i++) {
        Start-Sleep -Seconds 1
        $listen = @(Get-TcpListeners | Where-Object { $_.Port -eq $Config.VncPort }) | Select-Object -First 1
    }
    if (-not $listen) {
        Write-Log "VNC: nothing is listening on port $($Config.VncPort). Set VncPort to the port TightVNC is configured for." 'WARN'
        return
    }
    Write-Log "VNC: listening on $($listen.Address):$($listen.Port)."
    if ($listen.Address.Equals([System.Net.IPAddress]::Any) -or $listen.Address.Equals([System.Net.IPAddress]::IPv6Any)) {
        Write-Log 'VNC: bound to ALL interfaces. Restrict with Windows Firewall or use a VPN/SSH tunnel; set a strong VNC password.' 'WARN'
    }
}

function Stop-VncWeStarted {
    # FIX: only stop what this script started (v3.1.0 stopped a pre-existing service).
    if ($script:VncProc) {
        try { if (-not $script:VncProc.HasExited) { $script:VncProc.Kill() } } catch { }
        $script:VncProc = $null
    }
    if ($script:VncStartedService) {
        try { Stop-Service -Name 'tvnserver' -Force -ErrorAction Stop; Write-Log 'VNC: stopped tvnserver service.' }
        catch { Write-Log "VNC: could not stop service: $($_.Exception.Message)" 'WARN' }
        $script:VncStartedService = $false
    }
}

# --- Cleanup (idempotent; runs from finally, which also runs on Ctrl+C) ---------
function Invoke-Cleanup {
    if ($script:CleanedUp) { return }
    $script:CleanedUp = $true
    try { Stop-VncWeStarted } catch { }
    if ($script:Job)   { try { $script:Job.Dispose() } catch { }; $script:Job = $null }   # backstop: kills any surviving ffmpeg
    if ($script:Mutex) {
        try { if ($script:MutexOwned) { $script:Mutex.ReleaseMutex() } } catch { }
        try { $script:Mutex.Dispose() } catch { }
        $script:Mutex = $null
    }
    if ($script:Log) { try { Write-Log 'Cleanup complete.' } catch { }; try { $script:Log.Dispose() } catch { }; $script:Log = $null }
}

# --- Main ----------------------------------------------------------------------
function Invoke-Main {
    # FIX: PS 5.1 has no $IsWindows; guard so StrictMode does not choke on it.
    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { throw 'Windows only (gdigrab/dshow).' }

    Import-StreamConfig -Path $ConfigPath -Required $script:ConfigExplicit
    Test-StreamConfig
    Initialize-Native
    $script:FfmpegPath = Resolve-FfmpegPath

    if ($ListDevices) {
        Write-Host (Invoke-FfmpegCapture @('-hide_banner', '-list_devices', 'true', '-f', 'dshow', '-i', 'dummy'))
        return
    }

    $key = Resolve-StreamKey

    $logPath = if ([IO.Path]::IsPathRooted($Config.LogFile)) { $Config.LogFile } else { Join-Path $ScriptDir $Config.LogFile }
    $logDir  = Split-Path -Parent $logPath
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $script:Log = New-Object -TypeName StreamLive.LogSink -ArgumentList $logPath, ([long]$Config.LogMaxBytes), $key
    Write-Log "$ScriptName (v$ScriptVersion) starting. ffmpeg: $script:FfmpegPath"

    $caps  = Test-FfmpegCapabilities
    $geo   = Get-CaptureGeometry
    Write-Log "Capture: $($geo.Width)x$($geo.Height) at offset ($($geo.X),$($geo.Y)), $($Config.Fps) fps, preset $($Config.Preset), $($Config.Bitrate)"
    $audio = @(Get-AudioArgs -Caps $caps)
    $ffArgs = [string[]](New-FfmpegArgs -Geo $geo -AudioArgs $audio -Key $key)
    $argString = [StreamLive.ArgQuoter]::Join($ffArgs)

    if ($DryRun) {
        Write-Log 'DRY RUN - would execute (key redacted):'
        Write-Log ("`"$script:FfmpegPath`" " + $argString)
        return
    }

    # SEC: one instance per stream key (a second ffmpeg would fight for the ingest slot).
    $sha  = [System.Security.Cryptography.SHA256]::Create()
    $hex  = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key))) -replace '-', '').Substring(0, 12)
    $script:Mutex = New-Object -TypeName System.Threading.Mutex -ArgumentList $false, "Local\StreamLive-$hex"
    try { $script:MutexOwned = $script:Mutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $script:MutexOwned = $true }   # previous owner crashed
    if (-not $script:MutexOwned) { throw 'Another stream_live instance is already using this stream key.' }

    Stop-StaleFfmpeg -Key $key
    $script:Job = New-Object -TypeName StreamLive.KillOnCloseJob
    if (-not $script:Job.Ready) { Write-Log 'Job object unavailable; ffmpeg could outlive a force-closed window.' 'WARN' }
    Start-VncIfEnabled

    # --- Supervisor loop -------------------------------------------------------
    $backoff   = 5
    $fastFails = 0
    while ($true) {
        if (-not (Test-IngestReachable -Url $Config.IngestUrl)) {
            # Network problem, not an encoder problem: wait without counting a crash.
            Write-Log "Ingest $($Config.IngestUrl) unreachable; retrying in ${backoff}s." 'WARN'
            Start-Sleep -Seconds $backoff                 # interruptible by Ctrl+C
            $backoff = [Math]::Min($backoff * 2, 60)
            continue
        }

        $runner   = New-Object -TypeName StreamLive.FfmpegRunner -ArgumentList $script:FfmpegPath, $argString, $script:Log, ([int]$Config.ProgressLogSeconds)
        $started  = [DateTime]::UtcNow
        $nextBeat = $started.AddSeconds($Config.HealthInterval)
        $stalled  = $false
        $grace    = 5000
        $exitCode = -1
        try {
            $runner.Start($script:Job)
            Write-Log "ffmpeg started (PID $($runner.Id))."
            # Poll once a second: responsive to Ctrl+C, no threads, no handlers.
            while (-not $runner.WaitForExit(1000)) {
                if ($runner.SecondsSinceProgress -gt $Config.StallSeconds) {
                    $stalled = $true
                    $grace   = 1500                        # a stalled ffmpeg will not honour 'q' quickly
                    Write-Log "No new frames for $([int]$runner.SecondsSinceProgress)s (limit $($Config.StallSeconds)s): restarting ffmpeg." 'WARN'
                    break
                }
                if ([DateTime]::UtcNow -ge $nextBeat) {
                    Write-Log "[health] ffmpeg PID $($runner.Id) $($runner.Status); last new frame $([int]$runner.SecondsSinceProgress)s ago."
                    $nextBeat = [DateTime]::UtcNow.AddSeconds($Config.HealthInterval)
                }
            }
        }
        finally {
            # Runs on normal exit, stall, error AND Ctrl+C: graceful 'q', then Kill.
            [void]$runner.Stop($grace)
            $exitCode = $runner.ExitCode
            $runner.Dispose()
        }

        $uptime = [int]([DateTime]::UtcNow - $started).TotalSeconds
        $why = if ($stalled) { 'stall restart' } else { "exit code $exitCode" }
        Write-Log "ffmpeg stopped ($why) after ${uptime}s."

        if ($uptime -gt 60) {
            Write-Log "Stream ran ${uptime}s: resetting backoff to 5s."
            $backoff = 5; $fastFails = 0
        } elseif ($uptime -lt 15) {
            $fastFails++
            if ($Config.MaxFastFailures -gt 0 -and $fastFails -ge $Config.MaxFastFailures) {
                Write-Log "ffmpeg failed $fastFails times in a row within 15s (bad key, device or settings?). Giving up; see the log." 'ERROR'
                $script:ExitCode = 2
                break
            }
        }

        Write-Log "Reconnecting in ${backoff}s..."
        Start-Sleep -Seconds $backoff                      # interruptible by Ctrl+C
        $backoff = [Math]::Min($backoff * 2, 60)
    }
}

try {
    Invoke-Main | Out-Null
}
catch {
    $msg = "FATAL: $($_.Exception.Message)"
    if ($script:Log) { Write-Log $msg 'ERROR' } else { Write-Host $msg -ForegroundColor Red }
    $script:ExitCode = 1
}
finally {
    Invoke-Cleanup
}
exit $script:ExitCode
