"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Sparkles, Loader2, Clock, Play } from "lucide-react"
import { api } from "@/lib/api"
import { toast } from "sonner"

interface ConceptDetectorProps {
  videoId: string
  onJumpToTimestamp?: (timestamp: number) => void
}

interface DetectedConcept {
  concept_name: string
  category: string
  timestamps: number[]
  confidence: number
  description?: string
}

const categoryColors: Record<string, string> = {
  control_flow: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20",
  data_structures: "bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20",
  functions: "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20",
  object_oriented: "bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20",
  algorithms: "bg-pink-500/10 text-pink-600 dark:text-pink-400 border-pink-500/20",
  error_handling: "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20",
  file_operations: "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/20",
  modules: "bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20",
  general: "bg-gray-500/10 text-gray-600 dark:text-gray-400 border-gray-500/20",
}

const categoryLabels: Record<string, string> = {
  control_flow: "Control Flow",
  data_structures: "Data Structures",
  functions: "Functions",
  object_oriented: "OOP",
  algorithms: "Algorithms",
  error_handling: "Error Handling",
  file_operations: "File I/O",
  modules: "Modules",
  general: "General",
}

export default function ConceptDetector({ videoId, onJumpToTimestamp }: ConceptDetectorProps) {
  const [concepts, setConcepts] = useState<DetectedConcept[]>([])
  const [isDetecting, setIsDetecting] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [hasDetected, setHasDetected] = useState(false)

  useEffect(() => {
    loadConcepts()
  }, [videoId])

  const loadConcepts = async () => {
    setIsLoading(true)
    try {
      const response = await api.getDetectedConcepts(videoId)
      if (response.success && response.concepts) {
        setConcepts(response.concepts)
        setHasDetected(response.concepts.length > 0)
      } else {
        setConcepts([])
        setHasDetected(false)
      }
    } catch (error) {
      console.error("Error loading concepts:", error)
      setConcepts([])
      setHasDetected(false)
    } finally {
      setIsLoading(false)
    }
  }

  const handleDetectConcepts = async () => {
    setIsDetecting(true)
    try {
      const response = await api.detectConcepts(videoId)
      if (response.success) {
        setConcepts(response.concepts || [])
        const detectedCount = Number(response.concepts_count || 0)
        setHasDetected(detectedCount > 0)
        if (detectedCount > 0) {
          toast.success(`Detected ${detectedCount} concept${detectedCount !== 1 ? 's' : ''}`)
        } else {
          toast.info("No concepts found", {
            description: "Try running detection again after transcript extraction completes."
          })
        }
      } else {
        toast.error(response.error || "Concept detection failed")
      }
    } catch (error: any) {
      console.error("Concept detection error:", error)
      toast.error(error.message || "Failed to detect concepts")
    } finally {
      setIsDetecting(false)
    }
  }

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const handleJumpToTimestamp = (timestamp: number) => {
    if (onJumpToTimestamp) {
      onJumpToTimestamp(timestamp)
    }
  }

  const getCategoryColor = (category: string) => {
    return categoryColors[category] || categoryColors.general
  }

  const getCategoryLabel = (category: string) => {
    return categoryLabels[category] || category
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-primary" />
            <h3 className="font-semibold">Detected Concepts</h3>
          </div>
          {!hasDetected && (
            <Button
              onClick={handleDetectConcepts}
              disabled={isDetecting}
              size="sm"
              variant="outline"
            >
              {isDetecting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Detecting...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 mr-2" />
                  Detect Concepts
                </>
              )}
            </Button>
          )}
        </div>
        {hasDetected && (
          <p className="text-xs text-muted-foreground">
            {concepts.length} concept{concepts.length !== 1 ? 's' : ''} detected
          </p>
        )}
      </div>

      {/* Concepts List */}
      <div className="flex-1 overflow-y-auto">
        {!hasDetected ? (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground p-6">
            <Sparkles className="w-12 h-12 mb-4 opacity-50" />
            <p className="text-sm text-center mb-2">No concepts detected yet</p>
            <p className="text-xs text-center opacity-70 mb-4">
              Click "Detect Concepts" to analyze the video
            </p>
            <Button
              onClick={handleDetectConcepts}
              disabled={isDetecting}
              size="sm"
              variant="outline"
            >
              {isDetecting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Detecting...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 mr-2" />
                  Detect Concepts
                </>
              )}
            </Button>
          </div>
        ) : concepts.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <p className="text-sm">No concepts found</p>
          </div>
        ) : (
          <div className="p-4 space-y-4">
            {concepts.map((concept, index) => (
              <div
                key={index}
                className="p-4 rounded-lg border border-border bg-card"
              >
                {/* Concept Header */}
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <h4 className="font-semibold text-foreground mb-1 capitalize">
                      {concept.concept_name}
                    </h4>
                    <Badge className={getCategoryColor(concept.category)}>
                      {getCategoryLabel(concept.category)}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {Math.round(concept.confidence * 100)}% confidence
                  </div>
                </div>

                {/* Description */}
                {concept.description && (
                  <p className="text-sm text-muted-foreground mb-3">
                    {concept.description}
                  </p>
                )}

                {/* Timestamps */}
                {concept.timestamps && concept.timestamps.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-xs font-medium text-muted-foreground mb-2">
                      Appears at:
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {concept.timestamps.slice(0, 5).map((timestamp, tsIndex) => (
                        <Button
                          key={tsIndex}
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => handleJumpToTimestamp(timestamp)}
                        >
                          <Clock className="w-3 h-3 mr-1" />
                          {formatTime(timestamp)}
                          <Play className="w-3 h-3 ml-1" />
                        </Button>
                      ))}
                      {concept.timestamps.length > 5 && (
                        <Badge variant="secondary" className="h-7">
                          +{concept.timestamps.length - 5} more
                        </Badge>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

