# stream_config.example.psd1  (stream-live-ps v3.2.0)
# Copy to stream_config.psd1 (git-ignored) and edit. Only list what you change.
# Data-only file: PowerShell cannot run code from it.
@{
    # TwitchStreamKey = 'live_xxxxxxxxxxxxxxxxxxxxxxxx'   # or set $env:TWITCH_STREAM_KEY, or leave unset to be prompted
    # IngestUrl       = 'rtmp://live.twitch.tv/app'       # key is appended automatically; rtmps:// needs a TLS-enabled ffmpeg
    # FfmpegPath      = 'C:\tools\ffmpeg\bin\ffmpeg.exe'
    Fps             = 30
    Bitrate         = '6000k'
    BufSize         = '12000k'
    Preset          = 'veryfast'
    AudioBitrate    = '128k'
    AudioDevice     = 'CABLE Output (VB-Audio Virtual Cable)'   # run with -ListDevices to see names
    AudioFallback   = 'video-only'                                # or 'abort'
    # ScaleTo       = '1920x1080'
    EnableVnc       = $false
    VncPort         = 5900
    StallSeconds    = 45
    MaxFastFailures = 10
}
