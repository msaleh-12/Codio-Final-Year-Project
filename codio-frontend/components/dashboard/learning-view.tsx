"use client"

import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Code2 } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import VideoPlayer, { VideoPlayerHandle } from "@/components/learning/video-player"
import PythonCompiler from "@/components/learning/python-compiler"
import ProgressSidebar from "@/components/learning/progress-sidebar"
import TranscriptSearch from "@/components/learning/transcript-search"
import ConceptDetector from "@/components/learning/concept-detector"
import QuizPanel from "@/components/learning/quiz-panel"
import { api, getAccessToken, ProcessVideoResponse, VideoStatusResponse } from "@/lib/api"
import { toast } from "sonner"
import type { PreloadedVideoMeta } from "./dashboard"

interface LearningViewProps {
  playlistUrl: string
  playlistTitle: string
  userEmail: string
  onBack: () => void
  preloadedVideo?: PreloadedVideoMeta | null
}

interface Video {
  video_id: string
  title: string
  thumbnail: string
  duration: number
  url: string
}

export default function LearningView({ playlistUrl, playlistTitle, userEmail, onBack, preloadedVideo }: LearningViewProps) {
  console.log(`[LearningView] Component mounted/rendered with playlistUrl: ${playlistUrl}, user: ${userEmail}`)
  
  const [showCompiler, setShowCompiler] = useState(false)
  const [isTransitioning, setIsTransitioning] = useState(false)
  const [videos, setVideos] = useState<Video[]>([])
  const [currentVideoIndex, setCurrentVideoIndex] = useState(0)
  const [isVideoFullscreen, setIsVideoFullscreen] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [extractedCode, setExtractedCode] = useState<string | undefined>(undefined)
  const [pausedTime, setPausedTime] = useState<number | undefined>(undefined)
  const [processingStatus, setProcessingStatus] = useState<string>("")
  const [videoStatus, setVideoStatus] = useState<string>("not_found")
  const [transcriptAvailable, setTranscriptAvailable] = useState<boolean>(true)
  const [currentVideoId, setCurrentVideoId] = useState<string>("")
  const [playlistId, setPlaylistId] = useState<string>("") // Playlist ID extracted from URL
  const [processingProgress, setProcessingProgress] = useState<number>(0)
  const [processingStage, setProcessingStage] = useState<string>("")
  const [watchTime, setWatchTime] = useState<number>(0) // seconds watched
  const [videoDuration, setVideoDuration] = useState<number>(0) // total video duration
  const [isVideoPlaying, setIsVideoPlaying] = useState<boolean>(false)
  const [showLoadingOverlay, setShowLoadingOverlay] = useState<boolean>(false)

  console.log(`[LearningView] Current state - currentVideoId: ${currentVideoId}, videoStatus: ${videoStatus}`)
  const [isExtractingCode, setIsExtractingCode] = useState<boolean>(false)
  // Track watch progress for each video: { video_id: { watchedSeconds: number, duration: number, completed: boolean } }
  const [videoProgress, setVideoProgress] = useState<Record<string, { watchedSeconds: number, duration: number, completed: boolean }>>({})
  const processingIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const videoPlayerRef = useRef<VideoPlayerHandle>(null)

  useEffect(() => {
    if (preloadedVideo) {
      // When we have preloaded video metadata from search results, skip yt-dlp extraction entirely
      console.log(`[LearningView] Using preloaded video metadata, skipping yt-dlp extraction`)
      initFromPreloadedVideo(preloadedVideo)
    } else {
      fetchPlaylistVideos()
    }
    
    return () => {
      if (processingIntervalRef.current) {
        clearInterval(processingIntervalRef.current)
      }
    }
  }, []) // Empty dependency array - only run once on mount

  // Initialize directly from preloaded search result metadata (no yt-dlp needed)
  const initFromPreloadedVideo = async (meta: PreloadedVideoMeta) => {
    console.log(`[LearningView] initFromPreloadedVideo: ${meta.video_id} - ${meta.title}`)
    try {
      setIsLoading(true)
      setProcessingStatus("Preparing video...")

      const video: Video = {
        video_id: meta.video_id,
        title: meta.title,
        thumbnail: meta.thumbnail,
        duration: meta.duration,
        url: meta.url,
      }
      setVideos([video])

      const extractedPlaylistId = meta.url
      setPlaylistId(extractedPlaylistId)

      // Save playlist to backend
      try {
        if (getAccessToken()) {
          await api.saveUserPlaylist(
            userEmail,
            extractedPlaylistId,
            meta.url,
            meta.title,
            1
          )
          console.log(`[LearningView] Playlist saved to backend successfully`)
        }
      } catch (saveError) {
        console.error(`[LearningView] Error saving playlist (continuing anyway):`, saveError)
      }

      setCurrentVideoId(meta.video_id)
      setVideoDuration(meta.duration || 0)
      toast.success(`Video loaded: ${meta.title}`)
    } catch (error: any) {
      console.error(`[LearningView] Error in initFromPreloadedVideo:`, error)
      toast.error(error?.message || "Error loading video")
      setProcessingStatus(`Error: ${error?.message || "Failed to load video"}`)
    } finally {
      setIsLoading(false)
    }
  }

  // Helper function to extract playlist ID from URL
  const extractPlaylistId = (url: string): string => {
    try {
      const urlObj = new URL(url)
      const listParam = urlObj.searchParams.get('list')
      return listParam || url // Use list parameter or fallback to URL if single video
    } catch {
      return url
    }
  }

  // Load saved progress when playlist ID is set
  useEffect(() => {
    const loadSavedProgress = async () => {
      if (!playlistId || !userEmail) return;
      if (!getAccessToken()) {
        console.log("[LearningView] No auth token found, skipping protected progress fetch")
        return
      }
      
      try {
        const response = await api.getPlaylistProgress(userEmail, playlistId)
        console.log(`[LearningView] Loaded saved progress:`, response)
        
        if (response.success && response.progress) {
          setVideoProgress(response.progress)
          console.log(`[LearningView] Restored progress for ${Object.keys(response.progress).length} videos`)
        }
      } catch (error) {
        console.error(`[LearningView] Error loading saved progress:`, error)
        // Continue without saved progress
      }
    };
    
    if (playlistId && userEmail) {
      console.log(`[LearningView] Loading saved progress for ${userEmail}/${playlistId}`)
      loadSavedProgress()
    }
  }, [playlistId, userEmail])

  useEffect(() => {
    console.log(`[LearningView] ========== useEffect [currentVideoId] TRIGGERED ==========`)
    console.log(`[LearningView] useEffect dependency - currentVideoId: "${currentVideoId}"`)
    console.log(`[LearningView] Current videoStatus: ${videoStatus}`)
    
    if (currentVideoId) {
      console.log(`[LearningView] currentVideoId is truthy, calling startVideoProcessing...`)
      startVideoProcessing(currentVideoId)
    } else {
      console.log(`[LearningView] currentVideoId is empty/falsy, skipping processing`)
    }
    console.log(`[LearningView] ========== useEffect [currentVideoId] END ==========\n`)
  }, [currentVideoId])

  const fetchPlaylistVideos = async () => {
    console.log(`[LearningView] fetchPlaylistVideos called with URL: ${playlistUrl}`)
    console.log(`[LearningView] Step 1: Starting playlist fetch process...`)
    try {
      setIsLoading(true)
      console.log(`[LearningView] Step 2: Set isLoading = true`)
      setProcessingStatus("Fetching playlist information...")
      console.log(`[LearningView] Step 3: Calling backend API to get playlist videos...`)

      // Extract videos from playlist or single video URL
      const response = await api.getPlaylistVideos(playlistUrl)
      console.log(`[LearningView] Step 4: Received API response:`, response)

      if (response.success && response.videos.length > 0) {
        console.log(`[LearningView] Step 5: Success! Found ${response.videos.length} video(s)`)
        console.log(`[LearningView] Step 6: Playlist title: ${response.playlist_title}`)
        console.log(`[LearningView] Step 7: Video details:`, response.videos.map((v: Video) => ({ id: v.video_id, title: v.title })))
        setVideos(response.videos)
        
        // Extract and save playlist ID
        const extractedPlaylistId = extractPlaylistId(playlistUrl)
        setPlaylistId(extractedPlaylistId)
        console.log(`[LearningView] Step 8: Extracted playlist ID: ${extractedPlaylistId}`)
        
        // Use the playlist title from API response instead of the passed title
        const actualPlaylistTitle = response.playlist_title || playlistTitle
        console.log(`[LearningView] Step 9: Using playlist title: ${actualPlaylistTitle}`)
        
        // Save playlist to backend for this user
        console.log(`[LearningView] Step 10: Saving playlist to backend for user ${userEmail}...`)
        try {
          if (getAccessToken()) {
            await api.saveUserPlaylist(
              userEmail,
              extractedPlaylistId,
              playlistUrl,
              actualPlaylistTitle,
              response.videos.length
            )
            console.log(`[LearningView] Playlist saved to backend successfully`)
          } else {
            console.log(`[LearningView] No auth token found, skipping protected save playlist call`)
          }
        } catch (saveError) {
          console.error(`[LearningView] Error saving playlist (continuing anyway):`, saveError)
        }
        
        const firstVideoId = response.videos[0].video_id
        console.log(`[LearningView] Step 11: Setting first video ID: ${firstVideoId}`)
        setCurrentVideoId(firstVideoId)
        console.log(`[LearningView] Step 12: Set currentVideoId state to: ${firstVideoId}`)
        setVideoDuration(response.videos[0].duration || 0)
        console.log(`[LearningView] Step 13: Set video duration: ${response.videos[0].duration}s`)
        toast.success(`Found ${response.videos.length} video${response.videos.length > 1 ? 's' : ''}`)
      } else {
        console.log(`[LearningView] ERROR: No videos found in response`)
        console.log(`[LearningView] Response details:`, { success: response.success, videoCount: response.videos?.length })
        toast.error("No videos found")
        setProcessingStatus("No videos found")
      }
    } catch (error: any) {
      console.error(`[LearningView] EXCEPTION in fetchPlaylistVideos:`, error)
      console.error(`[LearningView] Error details:`, { message: error?.message, stack: error?.stack })
      const errorMessage = error?.message || "Error connecting to backend"
      toast.error(errorMessage)
      setProcessingStatus(`Error: ${errorMessage}`)
    } finally {
      setIsLoading(false)
      console.log(`[LearningView] fetchPlaylistVideos completed (finally block)`)
    }
  }

  const startVideoProcessing = async (videoId: string) => {
    console.log(`[LearningView] startVideoProcessing called for video ID: ${videoId}`)
    console.log(`[LearningView] Processing Step 1: Checking video status with backend...`)
    try {
      console.log(`[LearningView] Processing Step 2: Calling api.getVideoStatus(${videoId})...`)
      
      // Check current status
      const statusResponse: VideoStatusResponse = await api.getVideoStatus(videoId)
      const hasTranscript = statusResponse.transcript_available !== false
      console.log(`[LearningView] Processing Step 3: Backend returned status:`, {
        status: statusResponse.status,
        progress: statusResponse.progress,
        stage: statusResponse.stage,
        transcript_available: statusResponse.transcript_available
      })
      
      console.log(`[LearningView] Processing Step 4: Updating component state...`)
      setVideoStatus(statusResponse.status)
      setTranscriptAvailable(hasTranscript)
      setProcessingProgress(statusResponse.progress || 0)
      setProcessingStage(statusResponse.stage || "")
      console.log(`[LearningView] Processing Step 5: State updated - videoStatus=${statusResponse.status}, progress=${statusResponse.progress}`)

      if (statusResponse.status === "completed") {
        console.log(`[LearningView] Processing Step 6: Video already completed and ready for pause-to-code!`)
        setProcessingStatus(hasTranscript ? "Video ready!" : "Video ready with limited features (no transcript).")
        if (!hasTranscript) {
          toast.warning("Transcript not available", {
            description: "Pause-to-code and transcript tools may be limited for this video."
          })
        }
        console.log(`[LearningView] Video is ready - user can now pause to extract code`)
        return
      }

      if (statusResponse.status === "not_found") {
        // Start processing in background
        console.log(`[LearningView] Processing Step 6: Video not found in backend, initiating download...`)
        setProcessingStatus("Starting video download...")
        
        const videoUrl = `https://www.youtube.com/watch?v=${videoId}`
        console.log(`[LearningView] Processing Step 7: Calling processVideo API with URL: ${videoUrl}`)
        
        api.processVideo(videoUrl).then((response: ProcessVideoResponse) => {
          const hasTranscriptInResult = response.transcript_available !== false
          console.log(`[LearningView] Processing Step 8: processVideo API response received:`, response)
          setTranscriptAvailable(hasTranscriptInResult)
          setProcessingStatus(hasTranscriptInResult ? "Video downloaded successfully!" : "Video downloaded, but transcript is unavailable for this video.")
          setVideoStatus("completed")
          setProcessingProgress(100)
          if (!hasTranscriptInResult) {
            toast.warning("Video downloaded without transcript", {
              description: "Pause-to-code extraction may not work for this video."
            })
          }
          console.log(`[LearningView] Processing Step 9: Video download completed, status set to 'completed'`)
        }).catch((error) => {
          console.error(`[LearningView] ERROR in processVideo API:`, error)
          console.error(`[LearningView] Error details:`, { message: error?.message, stack: error?.stack })
          setProcessingStatus("Processing failed")
        })
      }

      if (statusResponse.status === "failed") {
        // Retry once when backend has a stale failed state for this video.
        console.log(`[LearningView] Processing Step 6b: Backend status is failed, retrying processVideo...`)
        setProcessingStatus(statusResponse.stage || "Previous attempt failed. Retrying download...")

        const videoUrl = `https://www.youtube.com/watch?v=${videoId}`
        api.processVideo(videoUrl).then((response: ProcessVideoResponse) => {
          const hasTranscriptInResult = response.transcript_available !== false
          setTranscriptAvailable(hasTranscriptInResult)
          setProcessingStatus(hasTranscriptInResult ? "Video downloaded successfully!" : "Video downloaded, but transcript is unavailable for this video.")
          setVideoStatus("completed")
          setProcessingProgress(100)
        }).catch((error) => {
          console.error(`[LearningView] ERROR retrying processVideo API:`, error)
          setProcessingStatus(error?.message || "Processing failed")
        })
      }

      // Poll for status updates
      if (processingIntervalRef.current) {
        console.log(`[LearningView] Processing Step 10: Clearing existing polling interval`)
        clearInterval(processingIntervalRef.current)
      }

      console.log(`[LearningView] Processing Step 11: Starting status polling (every 2 seconds)...`)
      processingIntervalRef.current = setInterval(async () => {
        console.log(`[LearningView] Poll: Checking video status...`)
        try {
          const status = await api.getVideoStatus(videoId)
          console.log(`[LearningView] Poll: Status update received:`, {
            status: status.status,
            progress: status.progress,
            stage: status.stage
          })
          
          setVideoStatus(status.status)
          setTranscriptAvailable(status.transcript_available !== false)
          setProcessingProgress(status.progress || 0)
          setProcessingStage(status.stage || "Processing...")
          
          if (status.status === "completed") {
            console.log(`[LearningView] Poll: Video processing COMPLETED! Stopping poll.`)
            setProcessingStatus(status.transcript_available === false ? "Video ready with limited features (no transcript)." : "Video ready!")
            if (processingIntervalRef.current) {
              clearInterval(processingIntervalRef.current)
              console.log(`[LearningView] Poll: Polling interval cleared successfully`)
            }
          } else if (status.status === "failed") {
            console.log(`[LearningView] Poll: Processing FAILED. Stopping poll.`)
            setProcessingStatus(status.stage || "Processing failed")
            if (processingIntervalRef.current) {
              clearInterval(processingIntervalRef.current)
            }
            toast.error("Video processing failed", {
              description: status.stage || "Please try again"
            })
          } else if (status.status === "downloading") {
            const progressText = status.stage || `Downloading... ${status.progress.toFixed(0)}%`
            setProcessingStatus(progressText)
            console.log(`[LearningView] Poll: Downloading progress: ${status.progress.toFixed(1)}%`)
          } else {
            console.log(`[LearningView] Poll: Current status: ${status.status}`)
          }
        } catch (error) {
          console.error(`[LearningView] Poll: ERROR checking status:`, error)
        }
      }, 2000) // Check every 2 seconds
    } catch (error) {
      console.error("[startVideoProcessing] Error:", error)
    }
  }

  // CRITICAL: Whenever compiler is shown, aggressively force-pause the video
  // This useEffect catches ALL cases where showCompiler becomes true
  useEffect(() => {
    if (showCompiler && videoPlayerRef.current) {
      console.log("[LearningView] showCompiler=true → forcePause video")
      videoPlayerRef.current.forcePause()
    }
  }, [showCompiler])

  const handlePauseToCoding = async (currentTime: number) => {
    // FORCE pause the video immediately via ref to ensure it actually stops
    if (videoPlayerRef.current) {
      videoPlayerRef.current.forcePause()
    }
    console.log(`\n=================================================`)
    console.log(`[LearningView] handlePauseToCoding TRIGGERED`)
    console.log(`  Timestamp: ${currentTime.toFixed(2)}s`)
    console.log(`  Video ID: ${currentVideoId}`)
    console.log(`  Current videoStatus (cached): ${videoStatus}`)
    console.log(`  Processing Progress: ${processingProgress}%`)
    console.log(`  Processing Stage: ${processingStage}`)
    console.log(`=================================================\n`)
    
    console.log(`[LearningView] Pause-to-Code Step 1: Re-checking video status from backend...`)
    try {
      // Always re-check status from backend to avoid stale state
      const freshStatus = await api.getVideoStatus(currentVideoId)
      console.log(`[LearningView] Pause-to-Code Step 2: Fresh status from backend: ${freshStatus.status}`)
      const hasTranscript = freshStatus.transcript_available !== false
      setTranscriptAvailable(hasTranscript)
      
      // Check if video is completed and ready for code extraction
      if (freshStatus.status !== "completed") {
        console.log(`[LearningView] Pause-to-Code Step 3: Video NOT ready for code extraction`)
        console.log(`  Current status: '${freshStatus.status}' (required: 'completed')`)
        console.log(`  Showing info toast to user...`)
        toast.info("Video is still processing. Please wait or continue watching.", {
          description: freshStatus.stage || "Download in progress...",
          duration: 3000
        })
        console.log(`[LearningView] Exiting handlePauseToCoding - video not ready\n`)
        return
      }

      if (!hasTranscript) {
        toast.info("Transcript missing, trying frame-only extraction", {
          description: "Pause-to-code will use visual frame analysis only and may be less accurate."
        })
      }
      
      // Update local state with fresh status
      setVideoStatus(freshStatus.status)
      console.log(`[LearningView] Pause-to-Code Step 4: Updated local videoStatus to: ${freshStatus.status}`)
    } catch (error) {
      console.error(`[LearningView] ERROR checking video status:`, error)
      toast.error("Failed to check video status")
      return
    }

    console.log(`[LearningView] Pause-to-Code Step 5: Video IS ready! Proceeding with code extraction...`)
    // Video is ready, extract code at this timestamp
    console.log(`[LearningView] Pause-to-Code Step 6: Setting paused time to ${currentTime}s`)
    setPausedTime(currentTime)
    console.log(`[LearningView] Pause-to-Code Step 7: Setting extraction flags...`)
    setIsExtractingCode(true)
    setShowLoadingOverlay(true)
    console.log(`[LearningView] Pause-to-Code Step 8: Loading overlay displayed`)

    try {
      console.log(`[LearningView] Pause-to-Code Step 9: Calling backend API to extract frame...`)
      console.log(`  Endpoint: /api/v1/video/${currentVideoId}/frame?timestamp=${currentTime}`)
      console.log(`  Making HTTP GET request...`)
      
      // Call backend to extract frame and analyze code at this exact timestamp
      const result = await api.getFrameAtTimestamp(currentVideoId, currentTime)
      console.log(`[LearningView] Pause-to-Code Step 10: Backend response received:`, result)

      console.log(`[LearningView] Pause-to-Code Step 11: Hiding loading overlay...`)
      setShowLoadingOverlay(false)

      console.log(`[LearningView] Pause-to-Code Step 12: Analyzing response...`)
      if (result.code_content) {
        // Code detected - show in compiler
        console.log(`[LearningView] Pause-to-Code Step 13: CODE DETECTED!`)
        console.log(`  Code length: ${result.code_content.length} characters`)
        console.log(`  Confidence: ${(result.confidence * 100).toFixed(0)}%`)
        console.log(`  First 100 chars: ${result.code_content.substring(0, 100)}...`)
        console.log(`[LearningView] Pause-to-Code Step 14: Setting extracted code in state...`)
        setExtractedCode(result.code_content)
        toast.success(`Code extracted at ${currentTime.toFixed(1)}s!`, {
          description: `Confidence: ${(result.confidence * 100).toFixed(0)}%`
        })
        console.log(`[LearningView] Pause-to-Code Step 15: Opening compiler with extracted code...`)
        setShowCompiler(true)
        console.log(`[LearningView] Pause-to-Code Step 16: Compiler opened successfully`)
      } else if (result.segment_type === "learning") {
        // Learning phase (no code visible)
        console.log(`[LearningView] Pause-to-Code Step 10: Learning phase detected (no code)`)
        console.log(`  Learning topic: ${result.learning_topic || 'N/A'}`)
        setExtractedCode(undefined)
        toast.info("Learning phase detected", {
          description: result.learning_topic || "No code visible at this timestamp"
        })
        console.log(`[LearningView] Pause-to-Code Step 11: Opening compiler with no-code message...`)
        setShowCompiler(true)
      } else if (result.error) {
        // Error from backend
        console.log(`[LearningView] Pause-to-Code Step 10: Backend returned error:`, result.error)
        console.log(`  Error message: ${result.message}`)
        const errorSnippet = result.error === "gemini_quota_exceeded"
          ? `# Pause-to-code unavailable right now\n#\n# Reason: Gemini API quota exceeded for frame analysis.\n#\n# What to do:\n# 1) Enable billing / increase quota for the pause-to-code Gemini key\n# 2) Wait for quota reset\n# 3) Try pausing again when quota is available\n\nprint(\"Pause-to-code is temporarily unavailable due to Gemini quota\")\n`
          : `# Pause-to-code extraction failed\n#\n# ${result.message || "Unknown backend analysis error"}\n\nprint(\"Frame extraction failed. Please try again.\")\n`
        setExtractedCode(errorSnippet)
        toast.error(result.message || "Failed to extract code")
        console.log(`[LearningView] Opening compiler with placeholder due to extraction error`)
        setShowCompiler(true)
        return
      } else {
        // No code found at this timestamp
        console.log(`[LearningView] Pause-to-Code Step 10: No code detected at ${currentTime}s`)
        setExtractedCode(undefined)
        toast.info("No code detected at this timestamp", {
          description: "Try pausing when code is visible on screen"
        })
        console.log(`[LearningView] Pause-to-Code Step 11: Opening compiler with placeholder message...`)
        setShowCompiler(true)
      }
    } catch (error: any) {
      console.error(`[LearningView] EXCEPTION in handlePauseToCoding:`, error)
      console.error(`  Error type: ${error?.name}`)
      console.error(`  Error message: ${error?.message}`)
      console.error(`  Error stack:`, error?.stack)
      console.log(`[LearningView] Pause-to-Code ERROR: Cleaning up...`)
      setShowLoadingOverlay(false)
      setIsExtractingCode(false)
      setExtractedCode(`# Pause-to-code request failed\n#\n# ${error?.message || "Backend connection error"}\n\nprint(\"Pause-to-code request failed. Check backend and try again.\")\n`)
      toast.error("Failed to extract code", {
        description: error?.message || "Backend connection error"
      })
      console.log(`[LearningView] Opening compiler with placeholder after exception`)
      setShowCompiler(true)
      console.log(`[LearningView] Error handled, overlay hidden`)
    } finally {
      setIsExtractingCode(false)
      console.log(`[LearningView] handlePauseToCoding completed (finally block)\n`)
    }
  }

  const handleShowCompiler = async (currentTime?: number) => {
    setIsTransitioning(true)

    if (currentTime !== undefined && currentVideoId) {
      // Check if video is processed
      if (videoStatus !== "completed") {
        toast.info("The video is still processing. Please wait.", {
          description: "You can continue watching while processing completes."
        })
        setIsTransitioning(false)
        return
      }

      try {
        toast.loading("Analyzing frame...")
        
        // Use real-time frame extraction endpoint
        const result = await api.getFrameAtTimestamp(currentVideoId, currentTime)

        toast.dismiss()

        if (result.code_content) {
          setExtractedCode(result.code_content)
          toast.success(`Code extracted! (Confidence: ${(result.confidence * 100).toFixed(0)}%)`)
        } else if (result.segment_type === "learning") {
          setExtractedCode(undefined)
          toast.info(`Learning phase: ${result.learning_topic || "No code at this timestamp"}`)
        } else if (result.error) {
          setExtractedCode(undefined)
          toast.info(result.message || "Video still processing")
        } else {
          setExtractedCode(undefined)
          toast.info("No code found at this timestamp")
        }
      } catch (error) {
        console.error("Error getting code:", error)
        toast.dismiss()
        toast.error("Failed to extract code")
      }
    }

    setTimeout(() => {
      setShowCompiler(true)
      setIsTransitioning(false)
    }, 150)
  }

  const handleHideCompiler = () => {
    setIsTransitioning(true)
    setTimeout(() => {
      setShowCompiler(false)
      setExtractedCode(undefined)
      setIsTransitioning(false)
    }, 150)
  }

  const handleSelectVideo = async (index: number) => {
    if (index === currentVideoIndex) return

    console.log(`[Video Switch] From index ${currentVideoIndex} to ${index}`)
    setIsTransitioning(true)
    
    // Cancel current video processing
    if (currentVideoId) {
      try {
        await api.cancelVideoProcessing(currentVideoId)
      } catch (error) {
        console.error("Error cancelling video:", error)
      }
    }

    // Clear interval
    if (processingIntervalRef.current) {
      clearInterval(processingIntervalRef.current)
    }

    setTimeout(() => {
      const newVideoId = videos[index].video_id
      const savedProgress = videoProgress[newVideoId]
      
      console.log(`[Video Switch] Loading video ${newVideoId}`)
      console.log(`[Video Switch] Saved progress:`, savedProgress || 'None')
      
      setCurrentVideoIndex(index)
      setCurrentVideoId(newVideoId)
      setVideoDuration(videos[index].duration || 0)
      setTranscriptAvailable(true)
      // Load saved watch time if exists, otherwise start from 0
      setWatchTime(savedProgress?.watchedSeconds || 0)
      setShowCompiler(false)
      setVideoStatus("not_found")
      setProcessingProgress(0)
      setIsTransitioning(false)
    }, 150)
  }

  const handleVideoFullscreen = (isFullscreen: boolean) => {
    setIsVideoFullscreen(isFullscreen)
  }

  const handleJumpToTimestamp = (timestamp: number) => {
    // Seek video to the specified timestamp
    // Add a tiny random offset to ensure useEffect triggers even for the same timestamp
    setPausedTime(timestamp + Math.random() * 0.001)
    setShowCompiler(false)
    const mins = Math.floor(timestamp / 60)
    const secs = Math.floor(timestamp % 60)
    toast.info(`Jumping to ${mins}:${secs.toString().padStart(2, '0')}`)
  }

  const handleTimeUpdate = (currentTime: number, isPlaying: boolean) => {
    // Only count watch time when video is actually playing
    if (isPlaying && currentVideoId && videoDuration > 0 && playlistId && userEmail) {
      const watchedSeconds = Math.floor(currentTime)
      setWatchTime(watchedSeconds)
      
      // Calculate completion percentage (90% threshold)
      const completionPercentage = (watchedSeconds / videoDuration) * 100
      const isCompleted = completionPercentage >= 90
      
      // Update progress for current video
      setVideoProgress(prev => {
        const wasCompleted = prev[currentVideoId]?.completed || false
        const newProgress = {
          ...prev,
          [currentVideoId]: {
            watchedSeconds,
            duration: videoDuration,
            completed: isCompleted || wasCompleted
          }
        }
        
        // Save progress to backend (debounced - every 5 seconds or on completion)
        if (watchedSeconds % 5 === 0 || (isCompleted && !wasCompleted)) {
          if (!getAccessToken()) {
            return newProgress
          }

          console.log(`[Progress] Saving to backend: ${userEmail}/${playlistId}/${currentVideoId} - ${watchedSeconds}s`)
          
          // Fire and forget - don't block UI
          api.saveVideoProgress(
            userEmail,
            playlistId,
            currentVideoId,
            watchedSeconds,
            videoDuration,
            isCompleted || wasCompleted
          ).catch(error => {
            console.error(`[Progress] Error saving to backend:`, error)
          })
        }
        
        // Log when video gets marked as completed
        if (isCompleted && !wasCompleted) {
          console.log(`[Progress] Video ${currentVideoId} marked as COMPLETED (${completionPercentage.toFixed(1)}% watched)`)
        }
        
        return newProgress
      })
    }
    setIsVideoPlaying(isPlaying)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-80px)]">
        <div className="text-center max-w-md">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground mb-2">{processingStatus || "Loading..."}</p>
        </div>
      </div>
    )
  }

  if (videos.length === 0) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-80px)]">
        <div className="text-center">
          <p className="text-muted-foreground mb-4">No videos found</p>
          <Button onClick={onBack} variant="outline">
            ← Back to Dashboard
          </Button>
        </div>
      </div>
    )
  }

  if (isVideoFullscreen && showCompiler) {
    return (
      <div className="w-screen h-screen">
        <PythonCompiler
          onClose={() => {
            setShowCompiler(false)
            setIsVideoFullscreen(false)
          }}
          isFullscreen={true}
        />
      </div>
    )
  }

  const currentVideo = videos[currentVideoIndex]

  // Calculate watch statistics
  const watchedMinutes = Math.floor(watchTime / 60)
  const watchedSeconds = watchTime % 60
  const totalMinutes = Math.floor(videoDuration / 60)
  const totalSeconds = videoDuration % 60
  const remainingTime = Math.max(0, videoDuration - watchTime)
  const remainingMinutes = Math.floor(remainingTime / 60)
  const remainingSeconds = remainingTime % 60

  return (
    <div className="flex h-[calc(100vh-80px)] gap-0">
      {/* Main Content - Video and Compiler Container */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Back Button and Dynamic Processing Status */}
        <div className="surface-glass flex items-center justify-between border-b border-border/50 px-6 py-4">
          <Button onClick={onBack} variant="outline" className="border-border/60 bg-transparent text-sm hover:bg-muted/70">
            ← Back to Dashboard
          </Button>
          
          {/* Dynamic Processing Status Indicator */}
          {(videoStatus === "downloading" || videoStatus === "not_found" || videoStatus === "processing") && videoStatus !== "completed" && (
            <div className="flex items-center gap-3 rounded-full border border-amber-500/30 bg-amber-500/10 px-4 py-1.5 text-sm">
              <div className="h-4 w-4 animate-spin rounded-full border-b-2 border-amber-400"></div>
              <div className="flex flex-col items-start">
                <span className="text-xs text-amber-300/70">
                  {videoStatus === "downloading" ? "Downloading video..." : videoStatus === "processing" ? (processingStage || "Processing...") : "Preparing video..."}
                </span>
                {processingProgress > 0 && (
                  <span className="font-semibold text-amber-400">{processingProgress.toFixed(1)}%</span>
                )}
              </div>
            </div>
          )}
          {videoStatus === "completed" && (
            <div className="flex items-center gap-2 rounded-full border border-emerald-500/25 bg-emerald-500/10 px-4 py-1.5 text-sm">
              <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse"></div>
              <span className="text-green-500 font-semibold">Video Ready – Pause to extract code</span>
            </div>
          )}
          {videoStatus === "failed" && (
            <div className="rounded-full border border-red-500/30 bg-red-500/10 px-4 py-1.5 text-sm text-red-600">Processing failed. Retrying or choose another video.</div>
          )}
        </div>

        <div className="flex-1 flex overflow-hidden relative">
          {showLoadingOverlay && (
            <div className="absolute inset-0 bg-black/90 z-50 flex items-center justify-center" style={{ animation: 'fadeIn 0.15s ease-out' }}>
              <div className="text-center" style={{ animation: 'scaleIn 0.2s ease-out' }}>
                <div className="relative mx-auto mb-4 w-16 h-16">
                  <div className="absolute inset-0 rounded-full border-4 border-cyan-400/20"></div>
                  <div className="absolute inset-0 rounded-full border-4 border-transparent border-t-cyan-400" style={{ animation: 'spin 0.4s linear infinite' }}></div>
                  <div className="absolute inset-2 rounded-full border-4 border-transparent border-b-emerald-400" style={{ animation: 'spin 0.6s linear infinite reverse' }}></div>
                  <Code2 className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" style={{ animation: 'pulse 0.5s ease-in-out infinite' }} />
                </div>
                <p className="text-white text-lg font-bold tracking-wide" style={{ animation: 'slideUp 0.2s ease-out' }}>Extracting Code...</p>
                <div className="flex items-center justify-center gap-1 mt-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" style={{ animation: 'bounce 0.4s ease-in-out infinite' }}></div>
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" style={{ animation: 'bounce 0.4s ease-in-out 0.1s infinite' }}></div>
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" style={{ animation: 'bounce 0.4s ease-in-out 0.2s infinite' }}></div>
                </div>
              </div>
              <style>{`
                @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                @keyframes scaleIn { from { transform: scale(0.8); opacity: 0; } to { transform: scale(1); opacity: 1; } }
                @keyframes slideUp { from { transform: translateY(10px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
                @keyframes spin { to { transform: rotate(360deg); } }
                @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
                @keyframes bounce { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-4px); } }
              `}</style>
            </div>
          )}

          <div
            className={`absolute inset-0 transition-all duration-300 ${showCompiler ? "opacity-0 pointer-events-none" : "opacity-100 pointer-events-auto"}`}
          >
            <VideoPlayer
              ref={videoPlayerRef}
              videoId={currentVideoId}
              onPause={() => { /* spacebar/button pause — do nothing, just pause video */ }}
              onPauseToCoding={handlePauseToCoding}
              onFullscreen={handleVideoFullscreen}
              onTimeUpdate={handleTimeUpdate}
              resumeFromTime={pausedTime}
              title={currentVideo?.title || "Loading..."}
              videoReady={videoStatus === "completed"}
              downloadProgress={processingProgress}
              downloadStage={videoStatus === "downloading" ? "Downloading video..." : videoStatus === "processing" ? (processingStage || "Processing...") : videoStatus === "not_found" ? "Preparing video..." : ""}
            />
          </div>

          {/* Compiler Container - Same size as video */}
          <div
            className={`absolute inset-0 transition-all duration-300 ${showCompiler ? "opacity-100 pointer-events-auto" : "opacity-0 pointer-events-none"
              }`}
          >
            {showCompiler && <PythonCompiler onClose={handleHideCompiler} isFullscreen={isVideoFullscreen} initialCode={extractedCode} />}
          </div>
        </div>
      </div>

      {/* Right Sidebar - Progress, Transcript Search, Concepts, and Quiz */}
      {!showCompiler && (
        <div className="surface-glass w-80 border-l border-border/50 flex flex-col">
          <Tabs defaultValue="progress" className="flex flex-col h-full min-h-0">
            <TabsList className="grid w-full grid-cols-4 rounded-none border-b border-border/50 bg-card/50">
              <TabsTrigger value="progress">Progress</TabsTrigger>
              <TabsTrigger value="transcript">Search</TabsTrigger>
              <TabsTrigger value="concepts">Concepts</TabsTrigger>
              <TabsTrigger value="quiz">Quiz</TabsTrigger>
            </TabsList>
            
            <TabsContent value="progress" className="flex-1 m-0 min-h-0 overflow-hidden">
              <ProgressSidebar 
                videos={videos.map((v, idx) => ({
                  id: v.video_id,
                  title: v.title,
                  duration: v.duration,
                  description: idx === currentVideoIndex ? 
                    (videoStatus === "completed" ? "Ready" : videoStatus === "processing" ? "Processing..." : "Not processed") 
                    : "Click to play"
                }))} 
                currentVideoIndex={currentVideoIndex} 
                onSelectVideo={handleSelectVideo}
                watchedTime={watchTime}
                totalTime={videoDuration}
                videoProgress={videoProgress}
              />
            </TabsContent>
            
            <TabsContent value="transcript" className="flex-1 m-0 min-h-0 overflow-hidden">
              {currentVideoId && (
                <TranscriptSearch 
                  videoId={currentVideoId}
                  onJumpToTimestamp={handleJumpToTimestamp}
                />
              )}
            </TabsContent>
            
            <TabsContent value="concepts" className="flex-1 m-0 min-h-0 overflow-hidden">
              {currentVideoId && (
                <ConceptDetector 
                  videoId={currentVideoId}
                  onJumpToTimestamp={handleJumpToTimestamp}
                />
              )}
            </TabsContent>

            <TabsContent value="quiz" className="flex-1 m-0 min-h-0 overflow-hidden">
              {currentVideoId && (
                <QuizPanel
                  userEmail={userEmail}
                  videoId={currentVideoId}
                />
              )}
            </TabsContent>
          </Tabs>
        </div>
      )}
    </div>
  )
}
