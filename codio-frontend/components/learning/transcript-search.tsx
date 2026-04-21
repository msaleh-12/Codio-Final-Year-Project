"use client"

import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Search, X, Clock, Play, FileText, Loader2, AlertCircle, Globe, Languages,
  Sparkles, Download, BookOpen, ListChecks, ChevronDown, ChevronUp,
} from "lucide-react"
import { api } from "@/lib/api"
import { toast } from "sonner"

interface TranscriptSearchProps {
  videoId: string
  onJumpToTimestamp?: (timestamp: number) => void
}

interface TranscriptMatch {
  timestamp: number
  text: string
  duration: number
  match_start?: number
  match_length?: number
}

export default function TranscriptSearch({ videoId, onJumpToTimestamp }: TranscriptSearchProps) {
  const [query, setQuery] = useState("")
  const [isSearching, setIsSearching] = useState(false)
  const [matches, setMatches] = useState<TranscriptMatch[]>([])
  const [hasSearched, setHasSearched] = useState(false)
  const [isExtracting, setIsExtracting] = useState(false)
  const [transcriptStatus, setTranscriptStatus] = useState<"unknown" | "checking" | "available" | "extracting" | "unavailable">("unknown")
  const [useEnglish, setUseEnglish] = useState(false)
  const [englishAvailable, setEnglishAvailable] = useState<boolean | null>(null)
  const [isLoadingEnglish, setIsLoadingEnglish] = useState(false)

  // New enhancement states
  const [activeTab, setActiveTab] = useState<"search" | "summary" | "notes">("search")
  const [aiSummary, setAiSummary] = useState("")
  const [keyPoints, setKeyPoints] = useState<string[]>([])
  const [isGeneratingSummary, setIsGeneratingSummary] = useState(false)
  const [showFullTranscript, setShowFullTranscript] = useState(false)
  const [fullTranscript, setFullTranscript] = useState("")
  const [isLoadingTranscript, setIsLoadingTranscript] = useState(false)
  const [userNotes, setUserNotes] = useState("")

  const checkedRef = useRef(false)
  const prevVideoIdRef = useRef("")

  // Auto-check transcript availability
  useEffect(() => {
    if (!videoId || videoId === prevVideoIdRef.current) return
    prevVideoIdRef.current = videoId
    checkedRef.current = false
    setMatches([])
    setHasSearched(false)
    setQuery("")
    setTranscriptStatus("checking")
    setEnglishAvailable(null)
    setUseEnglish(false)
    setAiSummary("")
    setKeyPoints([])
    setFullTranscript("")

    const checkTranscript = async () => {
      try {
        const response = await api.searchTranscript(videoId, "the")
        if (response.success) {
          if (response.matches_count > 0) {
            setTranscriptStatus("available")
            checkedRef.current = true
          } else if (response.message && response.message.includes("transcript")) {
            setTranscriptStatus("extracting")
            await autoExtract()
          } else {
            setTranscriptStatus("available")
            checkedRef.current = true
          }
        }
      } catch {
        setTranscriptStatus("extracting")
        await autoExtract()
      }
      checkEnglishAvailability()
    }

    const autoExtract = async () => {
      try {
        const response = await api.extractTranscript(videoId)
        if (response.success) {
          setTranscriptStatus("available")
          toast.success("Transcript extracted successfully!")
        } else {
          setTranscriptStatus("unavailable")
        }
      } catch {
        setTranscriptStatus("unavailable")
      }
    }

    checkTranscript()
  }, [videoId])

  // Load saved notes from localStorage
  useEffect(() => {
    if (videoId) {
      const saved = localStorage.getItem(`codio-notes-${videoId}`)
      if (saved) setUserNotes(saved)
    }
  }, [videoId])

  const checkEnglishAvailability = async () => {
    try {
      const response = await api.getEnglishTranscript(videoId)
      setEnglishAvailable(response.success)
    } catch {
      setEnglishAvailable(false)
    }
  }

  const handleToggleEnglish = async () => {
    if (!useEnglish) {
      if (englishAvailable === null) {
        setIsLoadingEnglish(true)
        try {
          const response = await api.getEnglishTranscript(videoId)
          if (response.success) {
            setEnglishAvailable(true)
            setUseEnglish(true)
            if (hasSearched && query.trim()) await searchInLanguage(query.trim(), true)
            else { setMatches([]); setHasSearched(false) }
            toast.success("Switched to English transcript")
          } else {
            setEnglishAvailable(false)
            toast.error("English transcript not available")
          }
        } catch {
          setEnglishAvailable(false)
          toast.error("English transcript not available")
        } finally {
          setIsLoadingEnglish(false)
        }
      } else if (englishAvailable) {
        setUseEnglish(true)
        if (hasSearched && query.trim()) await searchInLanguage(query.trim(), true)
        else { setMatches([]); setHasSearched(false) }
        toast.success("Switched to English transcript")
      } else {
        toast.error("English transcript not available")
      }
    } else {
      setUseEnglish(false)
      if (hasSearched && query.trim()) await searchInLanguage(query.trim(), false)
      else { setMatches([]); setHasSearched(false) }
      toast.info("Switched to original transcript")
    }
  }

  const handleExtractTranscript = async () => {
    setIsExtracting(true)
    setTranscriptStatus("extracting")
    try {
      const response = await api.extractTranscript(videoId)
      if (response.success) {
        toast.success("Transcript extracted successfully!")
        setTranscriptStatus("available")
      } else {
        toast.error(response.error || "Failed to extract transcript")
        setTranscriptStatus("unavailable")
      }
    } catch (error: any) {
      toast.error(error.message || "Failed to extract transcript")
      setTranscriptStatus("unavailable")
    } finally {
      setIsExtracting(false)
    }
  }

  const searchInLanguage = async (searchQuery: string, english: boolean) => {
    setIsSearching(true)
    setHasSearched(true)
    try {
      const response = english
        ? await api.searchEnglishTranscript(videoId, searchQuery)
        : await api.searchTranscript(videoId, searchQuery)
      if (response.success) {
        setMatches(response.matches || [])
        if (response.matches_count === 0) {
          if (response.message && response.message.includes("transcript")) {
            if (!english) setTranscriptStatus("unavailable")
          }
        } else {
          if (!english) setTranscriptStatus("available")
        }
      } else {
        setMatches([])
      }
    } catch {
      setMatches([])
    } finally {
      setIsSearching(false)
    }
  }

  const handleSearch = async () => {
    if (!query.trim()) return
    await searchInLanguage(query.trim(), useEnglish)
  }

  const handleGenerateSummary = async () => {
    setIsGeneratingSummary(true)
    try {
      const res = await api.getAiSummary(videoId)
      if (res.success) {
        setAiSummary(res.summary || "")
        setKeyPoints(res.key_points || [])
      } else {
        toast.error("Failed to generate summary")
      }
    } catch {
      toast.error("Failed to generate AI summary")
    } finally {
      setIsGeneratingSummary(false)
    }
  }

  const handleLoadFullTranscript = async () => {
    if (fullTranscript) {
      setShowFullTranscript(!showFullTranscript)
      return
    }
    setIsLoadingTranscript(true)
    try {
      const res = useEnglish
        ? await api.getEnglishTranscript(videoId)
        : await api.getFullTranscript(videoId)
      if (res.success && res.transcript) {
        setFullTranscript(res.transcript)
        setShowFullTranscript(true)
      } else {
        toast.error("Failed to load transcript")
      }
    } catch {
      toast.error("Failed to load full transcript")
    } finally {
      setIsLoadingTranscript(false)
    }
  }

  const handleExportTranscript = () => {
    const content = fullTranscript || "No transcript loaded"
    const blob = new Blob([content], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `transcript-${videoId}.txt`
    a.click()
    URL.revokeObjectURL(url)
    toast.success("Transcript exported")
  }

  const handleSaveNotes = () => {
    localStorage.setItem(`codio-notes-${videoId}`, userNotes)
    toast.success("Notes saved")
  }

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const highlightMatch = (text: string, matchStart?: number, matchLength?: number) => {
    if (matchStart === undefined || matchLength === undefined) return text
    const before = text.substring(0, matchStart)
    const match = text.substring(matchStart, matchStart + matchLength)
    const after = text.substring(matchStart + matchLength)
    return (<>{before}<mark className="bg-yellow-200 dark:bg-yellow-900 px-1 rounded">{match}</mark>{after}</>)
  }

  return (
    <div className="flex flex-col h-full">
      {/* Tab Navigation */}
      <div className="flex border-b border-border">
        {[
          { id: "search" as const, label: "Search", icon: Search },
          { id: "summary" as const, label: "AI Summary", icon: Sparkles },
          { id: "notes" as const, label: "Notes", icon: BookOpen },
        ].map(tab => (
          <button key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? "text-primary border-b-2 border-primary bg-primary/5"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/30"
            }`}
          >
            <tab.icon className="w-3 h-3" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Language Toggle */}
      <div className="p-2.5 border-b border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Languages className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-[10px] font-medium text-muted-foreground">Language</span>
          </div>
          <Button
            variant={useEnglish ? "default" : "outline"}
            size="sm"
            className={`h-6 text-[10px] gap-1 px-2 ${useEnglish ? 'bg-blue-600 hover:bg-blue-700 text-white' : ''}`}
            onClick={handleToggleEnglish}
            disabled={isLoadingEnglish || transcriptStatus === "checking" || transcriptStatus === "extracting"}
          >
            {isLoadingEnglish ? <Loader2 className="w-3 h-3 animate-spin" /> : <Globe className="w-3 h-3" />}
            {useEnglish ? "English" : "Translate"}
          </Button>
        </div>
      </div>

      {/* Status Banner */}
      {(transcriptStatus === "checking" || transcriptStatus === "extracting") && (
        <div className="p-3 border-b border-border">
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-cyan-50 dark:bg-cyan-900/20 border border-cyan-200 dark:border-cyan-800">
            <Loader2 className="w-4 h-4 text-cyan-500 animate-spin flex-shrink-0" />
            <div>
              <p className="text-xs font-medium text-cyan-800 dark:text-cyan-200">
                {transcriptStatus === "checking" ? "Checking transcript..." : "Extracting transcript..."}
              </p>
            </div>
          </div>
        </div>
      )}

      {transcriptStatus === "unavailable" && (
        <div className="p-3 border-b border-border">
          <div className="p-2.5 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
            <div className="flex items-start gap-2 mb-2">
              <AlertCircle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 mt-0.5" />
              <p className="text-xs font-medium text-amber-800 dark:text-amber-200">No transcript available</p>
            </div>
            <Button onClick={handleExtractTranscript} disabled={isExtracting} size="sm" variant="outline" className="w-full text-xs h-7">
              {isExtracting ? <><Loader2 className="w-3 h-3 mr-1 animate-spin" /> Extracting...</> : <><FileText className="w-3 h-3 mr-1" /> Retry Extraction</>}
            </Button>
          </div>
        </div>
      )}

      {/* Search Tab */}
      {activeTab === "search" && (
        <>
          <div className="p-3 border-b border-border">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-1/2 transform -translate-y-1/2 text-muted-foreground w-3.5 h-3.5" />
                <Input type="text"
                  placeholder={useEnglish ? "Search English transcript..." : "Search transcript..."}
                  value={query} onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleSearch() }}
                  className="pl-8 pr-8 h-8 text-xs"
                  disabled={transcriptStatus === "checking" || transcriptStatus === "extracting"}
                />
                {query && (
                  <Button variant="ghost" size="sm" className="absolute right-0.5 top-1/2 transform -translate-y-1/2 h-5 w-5 p-0"
                    onClick={() => { setQuery(""); setMatches([]); setHasSearched(false) }}>
                    <X className="w-3 h-3" />
                  </Button>
                )}
              </div>
              <Button onClick={handleSearch} size="sm" className="h-8 text-xs px-3"
                disabled={isSearching || !query.trim() || transcriptStatus === "checking"}>
                {isSearching ? "..." : "Search"}
              </Button>
            </div>

            {/* Quick actions */}
            <div className="flex gap-1.5 mt-2">
              <Button variant="outline" size="sm" className="h-6 text-[10px] px-2" onClick={handleLoadFullTranscript}
                disabled={isLoadingTranscript || transcriptStatus !== "available"}>
                {isLoadingTranscript ? <Loader2 className="w-3 h-3 animate-spin" /> : showFullTranscript ? <ChevronUp className="w-3 h-3 mr-0.5" /> : <ChevronDown className="w-3 h-3 mr-0.5" />}
                {showFullTranscript ? "Hide" : "Full Transcript"}
              </Button>
              <Button variant="outline" size="sm" className="h-6 text-[10px] px-2" onClick={handleExportTranscript}
                disabled={!fullTranscript && transcriptStatus !== "available"}>
                <Download className="w-3 h-3 mr-0.5" /> Export
              </Button>
            </div>
          </div>

          {/* Full Transcript View */}
          {showFullTranscript && fullTranscript && (
            <div className="p-3 border-b border-border max-h-48 overflow-y-auto bg-muted/20">
              <p className="text-xs text-foreground whitespace-pre-wrap leading-relaxed">{fullTranscript}</p>
            </div>
          )}

          {/* Results */}
          <div className="flex-1 overflow-y-auto">
            {!hasSearched ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                <div className="text-center px-4">
                  <Search className="w-10 h-10 mx-auto mb-3 opacity-40" />
                  <p className="text-xs">Search the video transcript</p>
                  {transcriptStatus === "available" && (
                    <p className="text-[10px] mt-1.5 text-emerald-500">Transcript ready</p>
                  )}
                </div>
              </div>
            ) : matches.length === 0 ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                <div className="text-center px-4">
                  <p className="text-xs">No matches for &ldquo;{query}&rdquo;</p>
                  <p className="text-[10px] mt-1 opacity-70">
                    {useEnglish ? "Try switching to original transcript" : "Try switching to English"}
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-3 space-y-2">
                <p className="text-[10px] text-muted-foreground mb-1">
                  {matches.length} result{matches.length !== 1 ? 's' : ''}
                  {useEnglish && <span className="ml-1 px-1.5 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">EN</span>}
                </p>
                {matches.map((match, index) => (
                  <div key={index}
                    className="p-2.5 rounded-lg border border-border bg-card hover:bg-accent/50 transition-colors cursor-pointer"
                    onClick={() => onJumpToTimestamp?.(match.timestamp)}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        <span className="font-mono font-semibold">{formatTime(match.timestamp)}</span>
                      </div>
                      <Button variant="ghost" size="sm" className="h-5 w-5 p-0"
                        onClick={(e) => { e.stopPropagation(); onJumpToTimestamp?.(match.timestamp) }}>
                        <Play className="w-3 h-3" />
                      </Button>
                    </div>
                    <p className="text-xs text-foreground leading-relaxed">
                      {highlightMatch(match.text, match.match_start, match.match_length)}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {/* AI Summary Tab */}
      {activeTab === "summary" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {!aiSummary && !isGeneratingSummary ? (
            <div className="text-center py-8">
              <Sparkles className="w-10 h-10 mx-auto mb-3 text-muted-foreground opacity-40" />
              <p className="text-xs text-muted-foreground mb-3">Generate an AI-powered summary of this video&apos;s content</p>
              <Button onClick={handleGenerateSummary} size="sm" className="text-xs"
                disabled={transcriptStatus !== "available"}>
                <Sparkles className="w-3 h-3 mr-1" /> Generate Summary
              </Button>
            </div>
          ) : isGeneratingSummary ? (
            <div className="text-center py-8">
              <Loader2 className="w-8 h-8 mx-auto mb-3 text-primary animate-spin" />
              <p className="text-xs text-muted-foreground">Analyzing transcript with AI...</p>
            </div>
          ) : (
            <>
              {/* Summary */}
              <div className="rounded-xl border border-border/60 bg-card/65 p-3">
                <div className="flex items-center gap-2 mb-2">
                  <Sparkles className="w-3.5 h-3.5 text-primary" />
                  <h4 className="text-xs font-semibold text-foreground">Summary</h4>
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed">{aiSummary}</p>
              </div>

              {/* Key Points */}
              {keyPoints.length > 0 && (
                <div className="rounded-xl border border-border/60 bg-card/65 p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <ListChecks className="w-3.5 h-3.5 text-emerald-500" />
                    <h4 className="text-xs font-semibold text-foreground">Key Points</h4>
                  </div>
                  <ul className="space-y-1.5">
                    {keyPoints.map((point, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                        <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-primary/10 text-primary text-[9px] font-bold flex-shrink-0 mt-0.5">{i + 1}</span>
                        <span className="leading-relaxed">{point}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <Button variant="outline" size="sm" className="w-full text-xs" onClick={handleGenerateSummary}>
                <Sparkles className="w-3 h-3 mr-1" /> Regenerate
              </Button>
            </>
          )}
        </div>
      )}

      {/* Notes Tab */}
      {activeTab === "notes" && (
        <div className="flex-1 flex flex-col p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <BookOpen className="w-3.5 h-3.5 text-muted-foreground" />
              <h4 className="text-xs font-semibold text-foreground">Video Notes</h4>
            </div>
            <Button variant="outline" size="sm" className="h-6 text-[10px] px-2" onClick={handleSaveNotes}>
              Save
            </Button>
          </div>
          <textarea
            value={userNotes}
            onChange={(e) => setUserNotes(e.target.value)}
            placeholder="Take notes while watching the video. Your notes are saved locally per video."
            className="flex-1 w-full p-3 rounded-lg border border-border bg-background text-xs resize-none focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <p className="text-[10px] text-muted-foreground text-center">Notes are saved locally in your browser</p>
        </div>
      )}
    </div>
  )
}
