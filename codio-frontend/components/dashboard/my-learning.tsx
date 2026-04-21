"use client"

import { useEffect, useState } from "react"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { api, getAccessToken } from "@/lib/api"
import { toast } from "sonner"
import {
  Play,
  Trash2,
  BookOpen,
  CheckCircle2,
  Clock,
  Search,
  ArrowRight,
  Trophy,
  BarChart3,
} from "lucide-react"
import type { PreloadedVideoMeta } from "./dashboard"

interface MyLearningProps {
  userEmail: string
  onStartLearning: (url: string, title: string, videoMeta?: PreloadedVideoMeta) => void
  filter: "in-progress" | "completed"
}

interface PlaylistItem {
  playlist_id: string
  playlist_url: string
  playlist_title: string
  total_videos: number
  completed_videos: number
  progress_percentage: number
  first_accessed: string
  last_accessed: string
}

export default function MyLearning({ userEmail, onStartLearning, filter }: MyLearningProps) {
  const [playlists, setPlaylists] = useState<PlaylistItem[]>([])
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const fetchPlaylists = async () => {
      if (!getAccessToken()) {
        setIsLoading(false)
        return
      }

      try {
        const response = await api.getUserPlaylists(userEmail)
        if (response.success && response.playlists) {
          setPlaylists(response.playlists)
        }
      } catch (error) {
        console.error("[MyLearning] Error fetching playlists:", error)
      } finally {
        setIsLoading(false)
      }
    }

    fetchPlaylists()
  }, [userEmail])

  const handleDelete = async (playlistId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!getAccessToken()) {
      toast.error("Please log in again")
      return
    }

    try {
      const response = await api.deleteUserPlaylist(userEmail, playlistId)
      if (response.success) {
        setPlaylists(playlists.filter((p) => p.playlist_id !== playlistId))
        toast.success("Playlist removed")
      }
    } catch (error) {
      toast.error("Failed to delete playlist")
    }
  }

  const filteredPlaylists = playlists.filter((p) => {
    if (filter === "completed") return p.progress_percentage >= 100
    return p.progress_percentage < 100
  })

  const sortedPlaylists = [...filteredPlaylists].sort(
    (a, b) => new Date(b.last_accessed).getTime() - new Date(a.last_accessed).getTime()
  )

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-b-2 border-primary" />
          <p className="mt-4 text-sm text-muted-foreground">Loading your courses...</p>
        </div>
      </div>
    )
  }

  const isCompleted = filter === "completed"

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">
            {isCompleted ? "Completed Courses" : "My Learning"}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {isCompleted
              ? `${sortedPlaylists.length} course${sortedPlaylists.length !== 1 ? "s" : ""} completed`
              : `${sortedPlaylists.length} course${sortedPlaylists.length !== 1 ? "s" : ""} in progress`}
          </p>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card className="border-border/60 bg-card/75 p-4">
          <div className="flex items-center gap-3">
            <div className={`rounded-lg p-2 ${isCompleted ? "bg-emerald-400/15" : "bg-amber-400/15"}`}>
              {isCompleted ? (
                <Trophy className="h-5 w-5 text-emerald-400" />
              ) : (
                <BookOpen className="h-5 w-5 text-amber-400" />
              )}
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{sortedPlaylists.length}</p>
              <p className="text-xs text-muted-foreground">
                {isCompleted ? "Completed" : "In Progress"}
              </p>
            </div>
          </div>
        </Card>

        <Card className="border-border/60 bg-card/75 p-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-blue-400/15 p-2">
              <Play className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">
                {sortedPlaylists.reduce((sum, p) => sum + p.completed_videos, 0)}
              </p>
              <p className="text-xs text-muted-foreground">Videos Watched</p>
            </div>
          </div>
        </Card>

        <Card className="border-border/60 bg-card/75 p-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-purple-400/15 p-2">
              <BarChart3 className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">
                {sortedPlaylists.length > 0
                  ? Math.round(
                      sortedPlaylists.reduce((sum, p) => sum + p.progress_percentage, 0) /
                        sortedPlaylists.length
                    )
                  : 0}
                %
              </p>
              <p className="text-xs text-muted-foreground">Avg. Progress</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Playlist Cards */}
      {sortedPlaylists.length > 0 ? (
        <div className="grid gap-4">
          {sortedPlaylists.map((playlist) => (
            <Card
              key={playlist.playlist_id}
              className="group cursor-pointer border-border/60 bg-card/75 p-5 transition-all hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5"
              onClick={() => onStartLearning(playlist.playlist_url, playlist.playlist_title)}
            >
              <div className="flex items-center gap-4">
                {/* Icon */}
                <div className={`flex-shrink-0 rounded-xl p-3 ${
                  playlist.progress_percentage >= 100
                    ? "bg-emerald-400/15"
                    : playlist.progress_percentage > 50
                    ? "bg-amber-400/15"
                    : "bg-blue-400/15"
                }`}>
                  {playlist.progress_percentage >= 100 ? (
                    <CheckCircle2 className="h-6 w-6 text-emerald-400" />
                  ) : (
                    <BookOpen className={`h-6 w-6 ${
                      playlist.progress_percentage > 50 ? "text-amber-400" : "text-blue-400"
                    }`} />
                  )}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-3">
                    <h4 className="truncate text-base font-semibold text-foreground transition-colors group-hover:text-primary">
                      {playlist.playlist_title}
                    </h4>
                    <span className={`flex-shrink-0 rounded-full px-2.5 py-1 text-xs font-semibold ${
                      playlist.progress_percentage >= 100
                        ? "bg-emerald-400/15 text-emerald-400"
                        : "bg-primary/15 text-primary"
                    }`}>
                      {playlist.progress_percentage.toFixed(0)}%
                    </span>
                  </div>

                  {/* Progress Bar */}
                  <div className="mt-3 space-y-1.5">
                    <div className="h-2 overflow-hidden rounded-full bg-muted/60">
                      <div
                        className={`h-full rounded-full transition-all ${
                          playlist.progress_percentage >= 100
                            ? "bg-gradient-to-r from-emerald-400 to-emerald-400/70"
                            : "bg-gradient-to-r from-primary to-primary/70"
                        }`}
                        style={{ width: `${Math.min(playlist.progress_percentage, 100)}%` }}
                      />
                    </div>
                  </div>

                  {/* Meta */}
                  <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Play className="h-3 w-3" />
                      {playlist.completed_videos} / {playlist.total_videos} videos
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(playlist.last_accessed).toLocaleDateString()}
                    </span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="opacity-0 transition-opacity group-hover:opacity-100 text-primary hover:bg-primary/10"
                    onClick={(e) => {
                      e.stopPropagation()
                      onStartLearning(playlist.playlist_url, playlist.playlist_title)
                    }}
                  >
                    {isCompleted ? "Review" : "Continue"}
                    <ArrowRight className="ml-1 h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="opacity-0 transition-opacity group-hover:opacity-100 text-destructive hover:bg-destructive/10"
                    onClick={(e) => handleDelete(playlist.playlist_id, e)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <div className="rounded-2xl border border-dashed border-border/60 px-6 py-16 text-center">
          {isCompleted ? (
            <>
              <Trophy className="mx-auto h-12 w-12 text-muted-foreground/40" />
              <h3 className="mt-4 text-lg font-semibold text-foreground">No completed courses yet</h3>
              <p className="mt-2 text-sm text-muted-foreground">
                Complete all videos in a course to see it here
              </p>
            </>
          ) : (
            <>
              <Search className="mx-auto h-12 w-12 text-muted-foreground/40" />
              <h3 className="mt-4 text-lg font-semibold text-foreground">No courses in progress</h3>
              <p className="mt-2 text-sm text-muted-foreground">
                Search for a coding tutorial to start learning
              </p>
            </>
          )}
        </div>
      )}
    </div>
  )
}
