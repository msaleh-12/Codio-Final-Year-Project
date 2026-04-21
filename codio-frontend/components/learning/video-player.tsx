"use client"

import { useEffect, useRef, useState, useCallback, forwardRef, useImperativeHandle } from "react"
import { Button } from "@/components/ui/button"
import {
  Volume2, VolumeX, Maximize2, Play, Pause, Code2, Loader2,
  Bookmark, BookmarkCheck, SkipBack, SkipForward, Gauge,
} from "lucide-react"
import { api } from "@/lib/api"
import { toast } from "sonner"

interface VideoPlayerProps {
  videoId: string
  onPause?: (currentTime: number) => void
  onPauseToCoding?: (currentTime: number) => void
  onFullscreen?: (isFullscreen: boolean) => void
  onTimeUpdate?: (currentTime: number, isPlaying: boolean) => void
  resumeFromTime?: number
  title: string
  videoReady?: boolean
  downloadProgress?: number
  downloadStage?: string
}

export interface VideoPlayerHandle {
  pauseVideo: () => void
  playVideo: () => void
  getCurrentTime: () => number
  forcePause: () => void
}

const SPEED_OPTIONS = [0.5, 0.75, 1, 1.25, 1.5, 1.75, 2]

const VideoPlayer = forwardRef<VideoPlayerHandle, VideoPlayerProps>(({
  videoId,
  onPause,
  onPauseToCoding,
  onFullscreen,
  onTimeUpdate,
  resumeFromTime,
  title,
  videoReady = false,
  downloadProgress = 0,
  downloadStage = "",
}, ref) => {
  const playerRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const timeUpdateIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const pauseSourceRef = useRef<"click" | "keyboard" | "button" | "pauseToCode" | "none">("none")
  const [isPlaying, setIsPlaying] = useState(false)
  const [isMuted, setIsMuted] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(0)
  const [isReady, setIsReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [showControls, setShowControls] = useState(true)

  // New enhancement states
  const [playbackSpeed, setPlaybackSpeed] = useState(1)
  const [showSpeedMenu, setShowSpeedMenu] = useState(false)
  const [bookmarks, setBookmarks] = useState<Array<{ id: string; timestamp: number; note: string }>>([])
  const [showBookmarks, setShowBookmarks] = useState(false)
  const [isCurrentTimeBookmarked, setIsCurrentTimeBookmarked] = useState(false)
  const [volume, setVolume] = useState(100)
  const [showVolumeSlider, setShowVolumeSlider] = useState(false)

  const canPlay = videoReady

  // Load bookmarks
  useEffect(() => {
    if (videoId) {
      loadBookmarks()
      // Auto-resume from localStorage
      const savedTime = localStorage.getItem(`codio-resume-${videoId}`)
      if (savedTime && !resumeFromTime) {
        const t = parseFloat(savedTime)
        if (t > 5 && playerRef.current && isReady) {
          playerRef.current.seekTo(t, true)
          toast.info(`Resumed from ${formatTime(t)}`)
        }
      }
    }
  }, [videoId, isReady])

  // Save progress periodically for auto-resume
  useEffect(() => {
    const interval = setInterval(() => {
      if (videoId && isPlaying && currentTime > 5) {
        localStorage.setItem(`codio-resume-${videoId}`, currentTime.toString())
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [videoId, isPlaying, currentTime])

  // Check if current time is near a bookmark
  useEffect(() => {
    const isNear = bookmarks.some(b => Math.abs(b.timestamp - currentTime) < 3)
    setIsCurrentTimeBookmarked(isNear)
  }, [currentTime, bookmarks])

  const loadBookmarks = async () => {
    try {
      const res = await api.getBookmarks(videoId)
      if (res.success) setBookmarks(res.bookmarks || [])
    } catch { /* ignore */ }
  }

  // Expose pause/play methods to parent via ref
  useImperativeHandle(ref, () => ({
    pauseVideo: () => {
      if (playerRef.current) {
        try { playerRef.current.pauseVideo() } catch (e) { console.warn("[VideoPlayer] Failed to pause:", e) }
      }
    },
    playVideo: () => {
      if (playerRef.current && canPlay) {
        try { playerRef.current.playVideo() } catch (e) { console.warn("[VideoPlayer] Failed to play:", e) }
      }
    },
    getCurrentTime: () => {
      if (playerRef.current) {
        try { return playerRef.current.getCurrentTime() || 0 } catch { return 0 }
      }
      return 0
    },
    forcePause: () => {
      const doPause = () => {
        if (playerRef.current) {
          try { playerRef.current.pauseVideo() } catch { /* ignore */ }
        }
        try {
          const iframe = document.querySelector('#youtube-player iframe, #youtube-player') as HTMLIFrameElement
          if (iframe?.contentWindow) {
            iframe.contentWindow.postMessage(JSON.stringify({ event: 'command', func: 'pauseVideo', args: [] }), '*')
          }
        } catch { /* ignore */ }
      }
      doPause()
      setTimeout(doPause, 100)
      setTimeout(doPause, 300)
      setTimeout(doPause, 600)
      setTimeout(doPause, 1000)
    },
  }), [canPlay])

  useEffect(() => {
    if (!videoId || videoId.trim() === "") { setError("No video ID provided"); return }
    setError(null)
    if ((window as any).YT) { initializePlayer(); return }
    const tag = document.createElement("script")
    tag.src = "https://www.youtube.com/iframe_api"
    document.body.appendChild(tag)
    ;(window as any).onYouTubeIframeAPIReady = () => { initializePlayer() }
    return () => {
      if (document.body.contains(tag)) document.body.removeChild(tag)
      if (timeUpdateIntervalRef.current) clearInterval(timeUpdateIntervalRef.current)
    }
  }, [videoId])

  useEffect(() => {
    const handleFullscreenChange = () => {
      const isFs = !!document.fullscreenElement
      setIsFullscreen(isFs)
      onFullscreen?.(isFs)
    }
    document.addEventListener("fullscreenchange", handleFullscreenChange)
    return () => document.removeEventListener("fullscreenchange", handleFullscreenChange)
  }, [onFullscreen])

  useEffect(() => {
    if (resumeFromTime !== undefined && playerRef.current && isReady) {
      playerRef.current.seekTo(resumeFromTime, true)
      if (canPlay) { try { playerRef.current.playVideo() } catch { /* ignore */ } }
    }
  }, [resumeFromTime, isReady, canPlay])

  // Enhanced keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (["INPUT", "TEXTAREA", "SELECT"].includes((e.target as HTMLElement)?.tagName || "")) return
      if (!playerRef.current || !isReady || !canPlay) return

      switch (e.code) {
        case "Space":
          e.preventDefault()
          const state = playerRef.current.getPlayerState()
          if (state === 1) { pauseSourceRef.current = "keyboard"; playerRef.current.pauseVideo() }
          else { pauseSourceRef.current = "none"; playerRef.current.playVideo() }
          break
        case "ArrowLeft":
          e.preventDefault()
          playerRef.current.seekTo(Math.max(0, playerRef.current.getCurrentTime() - 10), true)
          break
        case "ArrowRight":
          e.preventDefault()
          playerRef.current.seekTo(Math.min(duration, playerRef.current.getCurrentTime() + 10), true)
          break
        case "ArrowUp":
          e.preventDefault()
          if (playerRef.current) {
            const newVol = Math.min(100, volume + 10)
            playerRef.current.setVolume(newVol)
            setVolume(newVol)
            if (isMuted) { playerRef.current.unMute(); setIsMuted(false) }
          }
          break
        case "ArrowDown":
          e.preventDefault()
          if (playerRef.current) {
            const newVol = Math.max(0, volume - 10)
            playerRef.current.setVolume(newVol)
            setVolume(newVol)
          }
          break
        case "KeyM":
          e.preventDefault()
          handleMute()
          break
        case "KeyF":
          e.preventDefault()
          handleFullscreen()
          break
        case "KeyB":
          e.preventDefault()
          handleAddBookmark()
          break
        case "Period":
          if (e.shiftKey) {
            e.preventDefault()
            cycleSpeed(1)
          }
          break
        case "Comma":
          if (e.shiftKey) {
            e.preventDefault()
            cycleSpeed(-1)
          }
          break
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [isReady, canPlay, volume, isMuted, playbackSpeed, duration])

  const cycleSpeed = (direction: number) => {
    const currentIdx = SPEED_OPTIONS.indexOf(playbackSpeed)
    const newIdx = Math.max(0, Math.min(SPEED_OPTIONS.length - 1, currentIdx + direction))
    const newSpeed = SPEED_OPTIONS[newIdx]
    setPlaybackSpeed(newSpeed)
    if (playerRef.current) {
      try { playerRef.current.setPlaybackRate(newSpeed) } catch { /* ignore */ }
    }
    toast.info(`Speed: ${newSpeed}x`)
  }

  const initializePlayer = () => {
    try {
      if (!videoId || videoId.trim() === "") { setError("Invalid video ID"); return }
      if (playerRef.current) playerRef.current.destroy()

      playerRef.current = new (window as any).YT.Player("youtube-player", {
        videoId,
        playerVars: { controls: 0, modestbranding: 1, rel: 0, fs: 1, cc_load_policy: 0, iv_load_policy: 3, autohide: 0, disablekb: 1 },
        events: {
          onReady: (event: any) => {
            setIsReady(true)
            setDuration(event.target.getDuration())
            setError(null)
            if (timeUpdateIntervalRef.current) clearInterval(timeUpdateIntervalRef.current)
            timeUpdateIntervalRef.current = setInterval(() => {
              if (playerRef.current) {
                try {
                  const time = playerRef.current.getCurrentTime()
                  const playing = playerRef.current.getPlayerState() === 1
                  setCurrentTime(time)
                  onTimeUpdate?.(time, playing)
                } catch { /* ignore */ }
              }
            }, 1000)
          },
          onStateChange: (event: any) => {
            const playing = event.data === 1
            const paused = event.data === 2
            setIsPlaying(playing)
            if (paused) {
              const ct = event.target.getCurrentTime()
              const source = pauseSourceRef.current
              if (source === "click" || source === "pauseToCode") {
                pauseSourceRef.current = "none"
                if (onPauseToCoding) onPauseToCoding(ct)
              } else if (source === "keyboard" || source === "button") {
                pauseSourceRef.current = "none"
                if (onPause) onPause(ct)
              } else {
                pauseSourceRef.current = "none"
                if (onPause) onPause(ct)
              }
            }
            if (playerRef.current) {
              try {
                const time = playerRef.current.getCurrentTime()
                setCurrentTime(time)
                onTimeUpdate?.(time, playing)
              } catch { /* ignore */ }
            }
          },
          onError: (event: any) => {
            const c = event.data
            setError(c === 2 ? "Invalid video ID" : c === 5 ? "HTML5 player error" : c === 100 ? "Video not found" : (c === 101 || c === 150) ? "Video cannot be played" : "Error loading video")
          },
        },
      })
    } catch (err) { setError("Failed to initialize video player"); console.error(err) }
  }

  const handleOverlayClick = useCallback(() => {
    if (!playerRef.current || !isReady || !canPlay) return
    const state = playerRef.current.getPlayerState()
    if (state === 1) {
      pauseSourceRef.current = "click"
      playerRef.current.pauseVideo()
      setTimeout(() => {
        if (playerRef.current) {
          try { if (playerRef.current.getPlayerState() === 1) playerRef.current.pauseVideo() } catch { /* ignore */ }
        }
      }, 200)
    } else {
      pauseSourceRef.current = "none"
      playerRef.current.playVideo()
    }
  }, [isReady, canPlay])

  const handlePlayPause = useCallback(() => {
    if (!playerRef.current || !canPlay) return
    if (isPlaying) { pauseSourceRef.current = "button"; playerRef.current.pauseVideo() }
    else { pauseSourceRef.current = "none"; playerRef.current.playVideo() }
  }, [isPlaying, canPlay])

  const handlePauseToCode = useCallback(() => {
    if (!playerRef.current || !canPlay) return
    if (isPlaying) {
      pauseSourceRef.current = "pauseToCode"
      playerRef.current.pauseVideo()
      setTimeout(() => {
        if (playerRef.current) {
          try { if (playerRef.current.getPlayerState() === 1) playerRef.current.pauseVideo() } catch { /* ignore */ }
        }
      }, 200)
    } else {
      const ct = playerRef.current.getCurrentTime()
      if (onPauseToCoding) onPauseToCoding(ct)
    }
  }, [isPlaying, canPlay, onPauseToCoding])

  const handleMute = () => {
    if (!playerRef.current) return
    if (isMuted) { playerRef.current.unMute(); playerRef.current.setVolume(volume) }
    else { playerRef.current.mute() }
    setIsMuted(!isMuted)
  }

  const handleVolumeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseInt(e.target.value)
    setVolume(val)
    if (playerRef.current) {
      playerRef.current.setVolume(val)
      if (val === 0) { playerRef.current.mute(); setIsMuted(true) }
      else if (isMuted) { playerRef.current.unMute(); setIsMuted(false) }
    }
  }

  const handleFullscreen = () => {
    const el = containerRef.current
    if (el?.requestFullscreen) el.requestFullscreen()
  }

  const handleSpeedChange = (speed: number) => {
    setPlaybackSpeed(speed)
    if (playerRef.current) {
      try { playerRef.current.setPlaybackRate(speed) } catch { /* ignore */ }
    }
    setShowSpeedMenu(false)
  }

  const handleAddBookmark = async () => {
    const ts = playerRef.current?.getCurrentTime() || currentTime
    try {
      await api.addBookmark(videoId, ts, `Bookmark at ${formatTime(ts)}`)
      await loadBookmarks()
      toast.success(`Bookmark added at ${formatTime(ts)}`)
    } catch {
      // Fallback to localStorage
      const saved = JSON.parse(localStorage.getItem(`codio-bookmarks-${videoId}`) || '[]')
      saved.push({ id: Date.now().toString(), timestamp: ts, note: `Bookmark at ${formatTime(ts)}` })
      localStorage.setItem(`codio-bookmarks-${videoId}`, JSON.stringify(saved))
      setBookmarks(saved)
      toast.success(`Bookmark added at ${formatTime(ts)}`)
    }
  }

  const handleJumpToBookmark = (ts: number) => {
    if (playerRef.current) {
      playerRef.current.seekTo(ts, true)
      setShowBookmarks(false)
    }
  }

  const handleDeleteBookmark = async (id: string) => {
    try {
      await api.deleteBookmark(id)
      await loadBookmarks()
    } catch {
      const saved = JSON.parse(localStorage.getItem(`codio-bookmarks-${videoId}`) || '[]')
      const filtered = saved.filter((b: any) => b.id !== id)
      localStorage.setItem(`codio-bookmarks-${videoId}`, JSON.stringify(filtered))
      setBookmarks(filtered)
    }
    toast.success("Bookmark removed")
  }

  const handleSkip = (seconds: number) => {
    if (!playerRef.current || !canPlay) return
    const newTime = Math.max(0, Math.min(duration, playerRef.current.getCurrentTime() + seconds))
    playerRef.current.seekTo(newTime, true)
  }

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const handleProgressClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!playerRef.current || !duration || !canPlay) return
    const rect = e.currentTarget.getBoundingClientRect()
    const x = e.clientX - rect.left
    const seekTime = (x / rect.width) * duration
    playerRef.current.seekTo(seekTime, true)
  }

  const progressPercentage = duration > 0 ? (currentTime / duration) * 100 : 0

  return (
    <div ref={containerRef} className="w-full h-full flex flex-col bg-black"
      onMouseEnter={() => setShowControls(true)} onMouseLeave={() => setShowControls(false)}>

      {/* Title bar */}
      <div className="px-4 py-3 border-b border-border/50 bg-card/50 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-foreground truncate flex-1">{title}</h2>
        <div className="flex items-center gap-1.5 ml-2">
          {playbackSpeed !== 1 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400 font-mono">{playbackSpeed}x</span>
          )}
          {bookmarks.length > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400">{bookmarks.length} bookmarks</span>
          )}
        </div>
      </div>

      {/* Video area */}
      <div className="flex-1 relative bg-black overflow-hidden">
        {error ? (
          <div className="w-full h-full flex items-center justify-center bg-black">
            <div className="text-center">
              <p className="text-red-500 mb-2">{error}</p>
              <p className="text-sm text-muted-foreground">Please check the video ID and try again</p>
            </div>
          </div>
        ) : (
          <>
            <div className="w-full h-full" style={{ position: "relative", zIndex: 1, pointerEvents: "none" }}>
              <div id="youtube-player" className="w-full h-full" />
            </div>

            {!canPlay && (
              <div className="absolute inset-0 z-30 bg-black/70 backdrop-blur-sm flex items-center justify-center cursor-not-allowed">
                <div className="text-center max-w-sm">
                  <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
                  <p className="text-white text-lg font-semibold mb-2">{downloadStage || "Preparing video..."}</p>
                  {downloadProgress > 0 && (
                    <div className="w-64 mx-auto">
                      <div className="flex justify-between text-xs text-white/70 mb-1">
                        <span>Downloading</span><span>{downloadProgress.toFixed(1)}%</span>
                      </div>
                      <div className="w-full h-2 bg-white/20 rounded-full overflow-hidden">
                        <div className="h-full bg-cyan-400 rounded-full transition-all duration-300" style={{ width: `${downloadProgress}%` }} />
                      </div>
                    </div>
                  )}
                  <p className="text-white/50 text-xs mt-3">Video playback will be available once download completes</p>
                </div>
              </div>
            )}

            {canPlay && (
              <div className="absolute inset-0 z-20 cursor-pointer" onClick={handleOverlayClick}
                title={isPlaying ? "Click to pause and open code editor" : "Click to play"} />
            )}
          </>
        )}

        {/* Bookmark markers on progress bar */}
        {canPlay && duration > 0 && bookmarks.length > 0 && (
          <div className="absolute bottom-[52px] left-0 right-0 z-30 pointer-events-none">
            {bookmarks.map(b => (
              <div key={b.id} className="absolute w-1.5 h-3 bg-amber-400 rounded-sm -translate-x-1/2"
                style={{ left: `${(b.timestamp / duration) * 100}%`, bottom: 0 }}
                title={`${formatTime(b.timestamp)} - ${b.note}`} />
            ))}
          </div>
        )}

        {/* Bookmarks dropdown */}
        {showBookmarks && bookmarks.length > 0 && (
          <div className="absolute bottom-16 right-4 z-50 w-64 max-h-48 overflow-y-auto bg-black/95 border border-white/20 rounded-lg p-2 space-y-1">
            <p className="text-[10px] text-white/50 px-2 mb-1">Bookmarks ({bookmarks.length})</p>
            {bookmarks.sort((a, b) => a.timestamp - b.timestamp).map(b => (
              <div key={b.id} className="flex items-center justify-between gap-2 px-2 py-1.5 rounded hover:bg-white/10 cursor-pointer group"
                onClick={() => handleJumpToBookmark(b.timestamp)}>
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-[10px] font-mono text-amber-400 flex-shrink-0">{formatTime(b.timestamp)}</span>
                  <span className="text-[10px] text-white/70 truncate">{b.note}</span>
                </div>
                <button className="text-white/30 hover:text-red-400 opacity-0 group-hover:opacity-100 text-[10px] flex-shrink-0"
                  onClick={(e) => { e.stopPropagation(); handleDeleteBookmark(b.id) }}>x</button>
              </div>
            ))}
          </div>
        )}

        {/* Speed menu */}
        {showSpeedMenu && (
          <div className="absolute bottom-16 right-20 z-50 bg-black/95 border border-white/20 rounded-lg p-1.5 space-y-0.5">
            <p className="text-[10px] text-white/50 px-2 mb-1">Playback Speed</p>
            {SPEED_OPTIONS.map(s => (
              <button key={s} onClick={() => handleSpeedChange(s)}
                className={`w-full text-left px-3 py-1 rounded text-xs ${s === playbackSpeed ? 'bg-cyan-500/30 text-cyan-400' : 'text-white/70 hover:bg-white/10'}`}>
                {s}x {s === 1 && "(Normal)"}
              </button>
            ))}
          </div>
        )}

        {/* Controls bar */}
        <div className={`absolute bottom-0 left-0 right-0 z-40 bg-gradient-to-t from-black/90 via-black/60 to-transparent transition-opacity duration-300 ${showControls || !isPlaying ? "opacity-100" : "opacity-0"}`}>
          {canPlay && (
            <div className="w-full h-1.5 bg-white/20 cursor-pointer hover:h-3 transition-all group" onClick={handleProgressClick}>
              <div className="h-full bg-cyan-400 rounded-r-full transition-all" style={{ width: `${progressPercentage}%` }} />
            </div>
          )}

          <div className="flex items-center justify-between gap-2 px-3 py-2">
            <div className="flex items-center gap-1.5">
              {/* Skip back */}
              <Button onClick={() => handleSkip(-10)} disabled={!isReady || !canPlay} variant="ghost" size="sm"
                className="text-white hover:bg-white/20 h-7 w-7 p-0" title="Back 10s (←)">
                <SkipBack className="w-3.5 h-3.5" />
              </Button>

              {/* Play/Pause */}
              <Button onClick={handlePlayPause} disabled={!isReady || !canPlay} variant="ghost" size="sm"
                className="text-white hover:bg-white/20 h-8 w-8 p-0" title={isPlaying ? "Pause (Space)" : "Play (Space)"}>
                {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              </Button>

              {/* Skip forward */}
              <Button onClick={() => handleSkip(10)} disabled={!isReady || !canPlay} variant="ghost" size="sm"
                className="text-white hover:bg-white/20 h-7 w-7 p-0" title="Forward 10s (→)">
                <SkipForward className="w-3.5 h-3.5" />
              </Button>

              {/* Volume */}
              <div className="relative flex items-center" onMouseEnter={() => setShowVolumeSlider(true)} onMouseLeave={() => setShowVolumeSlider(false)}>
                <Button onClick={handleMute} disabled={!isReady} variant="ghost" size="sm"
                  className="text-white hover:bg-white/20 h-7 w-7 p-0" title="Mute (M)">
                  {isMuted || volume === 0 ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5" />}
                </Button>
                {showVolumeSlider && (
                  <input type="range" min="0" max="100" value={isMuted ? 0 : volume} onChange={handleVolumeChange}
                    className="w-16 h-1 ml-1 accent-cyan-400 cursor-pointer" />
                )}
              </div>

              {/* Time */}
              <span className="text-[10px] text-white/70 font-mono ml-1">{formatTime(currentTime)} / {formatTime(duration)}</span>
            </div>

            <div className="flex items-center gap-1">
              {/* Bookmark */}
              <Button onClick={handleAddBookmark} disabled={!isReady || !canPlay} variant="ghost" size="sm"
                className={`h-7 w-7 p-0 ${isCurrentTimeBookmarked ? 'text-amber-400' : 'text-white'} hover:bg-white/20`} title="Bookmark (B)">
                {isCurrentTimeBookmarked ? <BookmarkCheck className="w-3.5 h-3.5" /> : <Bookmark className="w-3.5 h-3.5" />}
              </Button>

              {/* Show bookmarks */}
              {bookmarks.length > 0 && (
                <Button onClick={() => { setShowBookmarks(!showBookmarks); setShowSpeedMenu(false) }}
                  variant="ghost" size="sm" className="text-amber-400 hover:bg-white/20 h-7 px-1.5 text-[10px] gap-0.5">
                  <BookmarkCheck className="w-3 h-3" /> {bookmarks.length}
                </Button>
              )}

              {/* Speed */}
              <Button onClick={() => { setShowSpeedMenu(!showSpeedMenu); setShowBookmarks(false) }}
                variant="ghost" size="sm"
                className={`h-7 px-1.5 text-[10px] hover:bg-white/20 ${playbackSpeed !== 1 ? 'text-cyan-400' : 'text-white'}`}
                title="Speed (Shift+>/Shift+<)">
                <Gauge className="w-3 h-3 mr-0.5" /> {playbackSpeed}x
              </Button>

              {/* Pause to Code */}
              {canPlay && (
                <Button onClick={handlePauseToCode} variant="ghost" size="sm"
                  className="text-cyan-400 hover:bg-cyan-400/20 text-[10px] gap-1 h-7 px-2" title="Pause and extract code">
                  <Code2 className="w-3.5 h-3.5" /> Code
                </Button>
              )}

              {/* Fullscreen */}
              <Button onClick={handleFullscreen} disabled={!isReady} variant="ghost" size="sm"
                className="text-white hover:bg-white/20 h-7 w-7 p-0" title="Fullscreen (F)">
                <Maximize2 className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-border/50 bg-card/50 text-[10px] text-muted-foreground flex items-center justify-between">
        <p>
          {canPlay
            ? "Space: Play/Pause | Arrows: Seek/Volume | B: Bookmark | M: Mute | F: Fullscreen | Shift+>/<: Speed"
            : "Video is downloading... playback will start when ready"}
        </p>
        {canPlay && (
          <div className="flex items-center gap-1.5 text-emerald-500">
            <div className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[10px] font-medium">Ready</span>
          </div>
        )}
      </div>
    </div>
  )
})

VideoPlayer.displayName = "VideoPlayer"

export default VideoPlayer
