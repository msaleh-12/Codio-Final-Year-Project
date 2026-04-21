"use client"

import type React from "react"

import { useState, useEffect, useRef, useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { Trash2, Plus, Sparkles, Rocket, Code2, BrainCircuit, Search, Clock, Eye, X, Loader2, Link2 } from "lucide-react"
import { api, getAccessToken } from "@/lib/api"
import { toast } from "sonner"
import type { PreloadedVideoMeta } from "./dashboard"

interface PlaylistInputProps {
  onStartLearning: (url: string, playlistTitle: string, videoMeta?: PreloadedVideoMeta) => void
  userEmail: string
}

interface SavedPlaylist {
  playlist_id: string
  playlist_url: string
  playlist_title: string
  total_videos: number
  completed_videos: number
  progress_percentage: number
  first_accessed: string
  last_accessed: string
}

interface YouTubeSearchResult {
  video_id: string
  title: string
  channel: string
  channel_id: string
  thumbnail: string
  duration: number
  views: number
  views_text: string
  published: string
  description: string
  url: string
}

function formatDuration(seconds: number): string {
  if (!seconds || seconds <= 0) return ""
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60
  if (h > 0) return `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`
  return `${m}:${s.toString().padStart(2, "0")}`
}

function formatViews(views: number): string {
  if (!views || views <= 0) return ""
  if (views >= 1_000_000) return `${(views / 1_000_000).toFixed(1)}M views`
  if (views >= 1_000) return `${(views / 1_000).toFixed(1)}K views`
  return `${views} views`
}

export default function PlaylistInput({ onStartLearning, userEmail }: PlaylistInputProps) {
  const [searchQuery, setSearchQuery] = useState("")
  const [isSearching, setIsSearching] = useState(false)
  const [searchResults, setSearchResults] = useState<YouTubeSearchResult[]>([])
  const [hasSearched, setHasSearched] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [savedPlaylists, setSavedPlaylists] = useState<SavedPlaylist[]>([])
  const [inputMode, setInputMode] = useState<"search" | "url">("search")
  const [url, setUrl] = useState("")
  const [urlError, setUrlError] = useState("")
  const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  // Fetch user playlists on mount
  useEffect(() => {
    const fetchUserPlaylists = async () => {
      if (!getAccessToken()) {
        setSavedPlaylists([])
        setIsLoading(false)
        return
      }

      setIsLoading(true)
      try {
        const response = await api.getUserPlaylists(userEmail)
        if (response.success && response.playlists) {
          setSavedPlaylists(response.playlists)
        }
      } catch (error) {
        console.error("[PlaylistInput] Error fetching playlists:", error)
      } finally {
        setIsLoading(false)
      }
    }

    fetchUserPlaylists()
  }, [userEmail])

  const handleSearch = useCallback(async (query: string) => {
    if (!query.trim() || query.trim().length < 2) {
      setSearchResults([])
      setHasSearched(false)
      return
    }

    setIsSearching(true)
    setHasSearched(true)

    try {
      const response = await api.searchYouTube(query.trim())
      if (response.success && response.videos) {
        setSearchResults(response.videos)
      } else {
        setSearchResults([])
        toast.error("Search failed", { description: response.error || "No results found" })
      }
    } catch (error: any) {
      console.error("[PlaylistInput] Search error:", error)
      setSearchResults([])
      toast.error("Search failed", { description: error?.message || "Could not search YouTube" })
    } finally {
      setIsSearching(false)
    }
  }, [])

  const handleSearchInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setSearchQuery(value)

    // Debounce search
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }

    if (value.trim().length >= 2) {
      searchTimeoutRef.current = setTimeout(() => {
        handleSearch(value)
      }, 500)
    } else {
      setSearchResults([])
      setHasSearched(false)
    }
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }
    handleSearch(searchQuery)
  }

  const handleVideoSelect = (video: YouTubeSearchResult) => {
    console.log("[PlaylistInput] Selected video:", video.title, video.url)
    // Pass video metadata directly to bypass yt-dlp extraction for search results
    const videoMeta: PreloadedVideoMeta = {
      video_id: video.video_id,
      title: video.title,
      thumbnail: video.thumbnail,
      duration: video.duration,
      url: video.url,
    }
    onStartLearning(video.url, video.title, videoMeta)
  }

  const clearSearch = () => {
    setSearchQuery("")
    setSearchResults([])
    setHasSearched(false)
  }

  const validateYouTubeUrl = (urlString: string): boolean => {
    try {
      const urlObj = new URL(urlString)
      return urlObj.hostname.includes("youtube.com") || urlObj.hostname.includes("youtu.be")
    } catch {
      return false
    }
  }

  const handleUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setUrlError("")

    if (!url.trim()) {
      setUrlError("Please enter a YouTube URL")
      return
    }

    if (!validateYouTubeUrl(url)) {
      setUrlError("Please enter a valid YouTube URL")
      return
    }

    onStartLearning(url, "Loading...")
    setUrl("")
  }

  const handleDeletePlaylist = async (playlistId: string, e: React.MouseEvent) => {
    e.stopPropagation()

    if (!getAccessToken()) {
      toast.error("Please log in again to manage playlists")
      return
    }

    try {
      const response = await api.deleteUserPlaylist(userEmail, playlistId)
      if (response.success) {
        setSavedPlaylists(savedPlaylists.filter((p) => p.playlist_id !== playlistId))
        toast.success("Playlist removed")
      } else {
        toast.error("Failed to delete playlist")
      }
    } catch (error) {
      console.error("[PlaylistInput] Error deleting playlist:", error)
      toast.error("Failed to delete playlist")
    }
  }

  return (
    <div className="space-y-8">
      {/* Hero Section */}
      <section className="relative overflow-hidden rounded-3xl border border-border/50 px-6 py-10 surface-glass sm:px-10">
        <div className="absolute -left-16 -top-16 h-40 w-40 rounded-full bg-primary/20 blur-3xl" />
        <div className="absolute -right-24 top-8 h-48 w-48 rounded-full bg-accent/20 blur-3xl" />

        <div className="relative space-y-5 text-center">
          <div className="stagger-in inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-4 py-1 text-xs font-semibold uppercase tracking-[0.15em] text-primary">
            <Sparkles className="h-3.5 w-3.5" />
            Learn Faster Than Passive Watching
          </div>

          <h2 className="stagger-in glow-title text-balance text-4xl font-semibold leading-tight text-foreground sm:text-5xl" style={{ animationDelay: "80ms" }}>
            Turn Any Coding Video Into a Hands-On Studio
          </h2>

          <p className="stagger-in mx-auto max-w-2xl text-pretty text-base text-muted-foreground sm:text-lg" style={{ animationDelay: "120ms" }}>
            Search for any coding tutorial and Codio builds an interactive workspace where your video, practice editor, transcript intelligence, and adaptive quiz work together.
          </p>
        </div>
      </section>

      {/* Search / URL Input Card */}
      <Card className="stagger-in surface-glass mx-auto max-w-3xl border-border/60 p-7" style={{ animationDelay: "150ms" }}>
        {/* Mode Toggle */}
        <div className="mb-4 flex items-center gap-2">
          <button
            onClick={() => setInputMode("search")}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-all ${
              inputMode === "search"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
            }`}
          >
            <Search className="h-4 w-4" />
            Search YouTube
          </button>
          <button
            onClick={() => setInputMode("url")}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-all ${
              inputMode === "url"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
            }`}
          >
            <Link2 className="h-4 w-4" />
            Paste URL
          </button>
        </div>

        {inputMode === "search" ? (
          <form onSubmit={handleSearchSubmit} className="space-y-4">
            <div className="flex items-center justify-between gap-2">
              <label htmlFor="search-query" className="text-sm font-medium text-foreground">
                Search for coding tutorials
              </label>
              <span className="text-xs text-muted-foreground">Powered by YouTube</span>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="search-query"
                  type="text"
                  placeholder="e.g. Python tutorial for beginners, React hooks..."
                  value={searchQuery}
                  onChange={handleSearchInputChange}
                  className="h-11 flex-1 border-border/70 bg-background/70 pl-10 pr-10 text-base"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={clearSearch}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>
              <Button
                type="submit"
                disabled={isSearching || !searchQuery.trim()}
                className="h-11 min-w-36 bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
              >
                {isSearching ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Searching...
                  </>
                ) : (
                  <>
                    <Search className="mr-2 h-4 w-4" />
                    Search
                  </>
                )}
              </Button>
            </div>

            <div className="shimmer-line h-1 w-full rounded-full" />
          </form>
        ) : (
          <form onSubmit={handleUrlSubmit} className="space-y-4">
            <div className="flex items-center justify-between gap-2">
              <label htmlFor="playlist-url" className="text-sm font-medium text-foreground">
                YouTube Playlist or Video URL
              </label>
              <span className="text-xs text-muted-foreground">Single videos also supported</span>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row">
              <Input
                id="playlist-url"
                type="url"
                placeholder="https://www.youtube.com/playlist?list=..."
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="h-11 flex-1 border-border/70 bg-background/70 text-base"
              />
              <Button
                type="submit"
                className="h-11 min-w-36 bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
              >
                <Plus className="mr-2 h-4 w-4" />
                Launch Session
              </Button>
            </div>

            {urlError && <p className="text-sm text-destructive">{urlError}</p>}

            <div className="shimmer-line h-1 w-full rounded-full" />
          </form>
        )}
      </Card>

      {/* Search Results */}
      {inputMode === "search" && hasSearched && (
        <div className="mx-auto max-w-3xl">
          {isSearching ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="ml-3 text-muted-foreground">Searching YouTube...</span>
            </div>
          ) : searchResults.length > 0 ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-foreground">
                  Search Results
                </h3>
                <span className="text-xs text-muted-foreground">
                  {searchResults.length} videos found
                </span>
              </div>
              <div className="grid gap-3">
                {searchResults.map((video) => (
                  <Card
                    key={video.video_id}
                    className="interactive-lift group cursor-pointer border-border/60 bg-card/75 p-0 overflow-hidden transition-all hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5"
                    onClick={() => handleVideoSelect(video)}
                  >
                    <div className="flex gap-0">
                      {/* Thumbnail */}
                      <div className="relative flex-shrink-0 w-48 sm:w-56">
                        <div className="aspect-video w-full overflow-hidden bg-muted">
                          <img
                            src={video.thumbnail}
                            alt={video.title}
                            className="h-full w-full object-cover transition-transform group-hover:scale-105"
                            loading="lazy"
                          />
                        </div>
                        {video.duration > 0 && (
                          <span className="absolute bottom-1.5 right-1.5 rounded bg-black/80 px-1.5 py-0.5 text-xs font-medium text-white">
                            {formatDuration(video.duration)}
                          </span>
                        )}
                      </div>

                      {/* Info */}
                      <div className="flex flex-1 flex-col justify-between p-3 sm:p-4">
                        <div>
                          <h4 className="line-clamp-2 text-sm font-semibold leading-snug text-foreground transition-colors group-hover:text-primary sm:text-base">
                            {video.title}
                          </h4>
                          <p className="mt-1 text-xs text-muted-foreground sm:text-sm">
                            {video.channel}
                          </p>
                        </div>
                        <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                          {video.views > 0 && (
                            <span className="flex items-center gap-1">
                              <Eye className="h-3 w-3" />
                              {formatViews(video.views)}
                            </span>
                          )}
                          {video.published && (
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {video.published}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            </div>
          ) : (
            <div className="py-12 text-center">
              <Search className="mx-auto h-10 w-10 text-muted-foreground/50" />
              <p className="mt-3 text-muted-foreground">No videos found for &ldquo;{searchQuery}&rdquo;</p>
              <p className="mt-1 text-xs text-muted-foreground/70">Try different keywords or switch to URL mode</p>
            </div>
          )}
        </div>
      )}

      {/* Feature Cards - only show when no search results */}
      {!(inputMode === "search" && hasSearched && searchResults.length > 0) && (
        <div className="grid gap-5 md:grid-cols-3">
          <Card className="interactive-lift stagger-in surface-glass border-border/60 p-5" style={{ animationDelay: "210ms" }}>
            <Rocket className="mb-3 h-6 w-6 text-primary" />
            <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-foreground">Momentum Learning</h3>
            <p className="text-sm text-muted-foreground">Stay in flow while navigating videos, snippets, and experiments in a single immersive environment.</p>
          </Card>

          <Card className="interactive-lift stagger-in surface-glass border-border/60 p-5" style={{ animationDelay: "260ms" }}>
            <Code2 className="mb-3 h-6 w-6 text-primary" />
            <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-foreground">Pause-to-Code Engine</h3>
            <p className="text-sm text-muted-foreground">Extract code ideas directly from moments in the tutorial and execute them instantly.</p>
          </Card>

          <Card className="interactive-lift stagger-in surface-glass border-border/60 p-5" style={{ animationDelay: "310ms" }}>
            <BrainCircuit className="mb-3 h-6 w-6 text-primary" />
            <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-foreground">Adaptive Quiz Layer</h3>
            <p className="text-sm text-muted-foreground">Reinforce understanding with dynamic questions that react to your performance.</p>
          </Card>
        </div>
      )}

      {/* Saved Playlists */}
      {isLoading ? (
        <div className="max-w-4xl mx-auto text-center py-8">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          <p className="text-sm text-muted-foreground mt-2">Loading your playlists...</p>
        </div>
      ) : savedPlaylists.length > 0 ? (
        <div className="mx-auto max-w-4xl">
          <h3 className="mb-4 text-xl font-semibold text-foreground">Recent Playlists</h3>
          <div className="grid gap-3">
            {savedPlaylists.map((playlist) => (
              <Card
                key={playlist.playlist_id}
                className="interactive-lift group cursor-pointer border-border/60 bg-card/75 p-4"
                onClick={() => onStartLearning(playlist.playlist_url, playlist.playlist_title)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <h4 className="font-medium text-foreground transition-colors group-hover:text-primary">
                        {playlist.playlist_title}
                      </h4>
                      <span className="rounded-full border border-primary/30 bg-primary/10 px-2 py-1 text-xs font-medium text-primary">
                        {playlist.progress_percentage.toFixed(0)}% Complete
                      </span>
                    </div>
                    <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
                      <span>{playlist.completed_videos} / {playlist.total_videos} videos completed</span>
                      <span>&bull;</span>
                      <span>Last accessed: {new Date(playlist.last_accessed).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <Button
                    onClick={(e) => handleDeletePlaylist(playlist.playlist_id, e)}
                    variant="ghost"
                    size="sm"
                    className="text-destructive hover:bg-destructive/10"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        </div>
      ) : (
        <div className="max-w-4xl mx-auto text-center py-8">
          <p className="text-muted-foreground">No playlists yet. Search for a video above to get started!</p>
        </div>
      )}
    </div>
  )
}
