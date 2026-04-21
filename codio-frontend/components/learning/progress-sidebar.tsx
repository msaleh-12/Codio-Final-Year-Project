"use client"

import { useState } from "react"
import { ChevronDown } from "lucide-react"

interface ProgressSidebarProps {
  videos: any[]
  currentVideoIndex: number
  onSelectVideo: (index: number) => void
  watchedTime?: number  // seconds actually watched
  totalTime?: number    // total video duration in seconds
  videoProgress?: Record<string, { watchedSeconds: number, duration: number, completed: boolean }>
}

interface VideoStats {
  watched: number
  coded: number
  completed: number
}

export default function ProgressSidebar({ videos, currentVideoIndex, onSelectVideo, watchedTime = 0, totalTime = 0, videoProgress = {} }: ProgressSidebarProps) {
  const [expandedStats, setExpandedStats] = useState(true)
  const getVideoKey = (video: any) => video.id ?? video.video_id

  // Calculate actual completed videos (90%+ watched)
  const completedCount = videos.filter((video) => videoProgress[getVideoKey(video)]?.completed).length
  const totalCount = videos.length
  const progressPercent = totalCount > 0 ? (completedCount / totalCount) * 100 : 0
  
  // Debug logging
  console.log(`[ProgressSidebar] Completed: ${completedCount}/${totalCount} (${progressPercent.toFixed(1)}%)`, videoProgress)

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const remainingTime = Math.max(0, totalTime - watchedTime)

  const getCompletionStatus = (index: number) => {
    const video = videos[index]
    const progress = videoProgress[getVideoKey(video)]
    
    if (index === currentVideoIndex) return "current"
    if (progress?.completed) return "completed"
    if (progress?.watchedSeconds > 0) return "in-progress"
    return "pending"
  }

  return (
    <div className="h-full min-h-0 bg-card/50 flex flex-col overflow-hidden">
      {/* Progress Header */}
      <div className="px-6 py-6 border-b border-border/50">
        <h3 className="text-sm font-semibold text-foreground mb-4">Playlist Progress</h3>

        {/* Main Progress */}
        <div className="space-y-3 mb-6">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">
              {completedCount} of {totalCount} videos
            </span>
            <span className="font-semibold text-primary">{Math.round(progressPercent)}%</span>
          </div>
          <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
            <div className="h-full bg-primary transition-all duration-300" style={{ width: `${progressPercent}%` }} />
          </div>
        </div>

        {/* Stats Toggle */}
        <button
          onClick={() => setExpandedStats(!expandedStats)}
          className="w-full flex items-center justify-between text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <span className="font-medium">Statistics</span>
          <ChevronDown className={`w-3 h-3 transition-transform ${expandedStats ? "rotate-180" : ""}`} />
        </button>

        {/* Stats Details */}
        {expandedStats && (
          <div className="mt-3 space-y-2 text-xs">
            <div className="flex justify-between p-2 rounded bg-muted/50">
              <span className="text-muted-foreground">Watched:</span>
              <span className="font-semibold text-primary font-mono">{formatTime(watchedTime)}</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-muted/50">
              <span className="text-muted-foreground">Total:</span>
              <span className="font-semibold text-foreground font-mono">{formatTime(totalTime)}</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-muted/50">
              <span className="text-muted-foreground">Remaining:</span>
              <span className="font-semibold text-muted-foreground font-mono">{formatTime(remainingTime)}</span>
            </div>
          </div>
        )}
      </div>

      {/* Video List */}
      <div className="theme-scrollbar flex-1 min-h-0 overflow-y-auto px-4 py-4 space-y-2">
        {videos.map((video, index) => {
          const status = getCompletionStatus(index)
          return (
            <button
              key={getVideoKey(video) ?? index}
              onClick={() => onSelectVideo(index)}
              className={`w-full text-left p-3 rounded-lg transition-all ${
                status === "current"
                  ? "bg-primary/20 border border-primary/50"
                  : status === "completed"
                    ? "bg-green-500/10 border border-green-500/30 hover:bg-green-500/20"
                    : status === "in-progress"
                      ? "bg-yellow-500/10 border border-yellow-500/30 hover:bg-yellow-500/20"
                      : "bg-muted/30 border border-border/50 hover:bg-muted/50 opacity-60"
              }`}
            >
              <div className="flex items-start gap-3">
                {/* Status Indicator */}
                <div className="shrink-0 mt-1">
                  {status === "completed" ? (
                    <div className="w-5 h-5 rounded-full bg-green-500 flex items-center justify-center">
                      <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                  ) : status === "current" ? (
                    <div className="w-5 h-5 rounded-full border-2 border-primary bg-primary/20 flex items-center justify-center">
                      <div className="w-2 h-2 rounded-full bg-primary" />
                    </div>
                  ) : status === "in-progress" ? (
                    <div className="w-5 h-5 rounded-full border-2 border-yellow-500 bg-yellow-500/20 flex items-center justify-center">
                      <div className="w-2 h-2 rounded-full bg-yellow-500" />
                    </div>
                  ) : (
                    <div className="w-5 h-5 rounded-full border-2 border-muted-foreground/30" />
                  )}
                </div>

                {/* Video Info */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">
                    {index + 1}. {video.title}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">{video.duration}</p>
                </div>
              </div>
            </button>
          )
        })}
      </div>

      {/* Footer Stats */}
      <div className="px-6 py-4 border-t border-border/50 bg-muted/30 space-y-2 text-xs text-muted-foreground">
        <div className="flex justify-between">
          <span>Completion Rate:</span>
          <span className="font-semibold text-foreground">{Math.round(progressPercent)}%</span>
        </div>
        <div className="flex justify-between">
          <span>Videos Remaining:</span>
          <span className="font-semibold text-foreground">{totalCount - completedCount}</span>
        </div>
      </div>
    </div>
  )
}
