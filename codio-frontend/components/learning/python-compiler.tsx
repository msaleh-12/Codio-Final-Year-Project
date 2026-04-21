"use client"

import { useState, useEffect, useRef, type KeyboardEvent } from "react"
import { Button } from "@/components/ui/button"
import { Play, X, ChevronDown, History, Lightbulb, Copy, RotateCcw, Download, Keyboard } from "lucide-react"
import { api } from "@/lib/api"

interface PythonCompilerProps {
  onClose: () => void
  isFullscreen?: boolean
  initialCode?: string
  videoId?: string
}

interface SuggestionItem {
  label: string
  insertText: string
  source: "local" | "ai"
  replaceWord: boolean
}

interface CodeHistoryEntry {
  id: string
  code: string
  output: string
  error: string
  timestamp: string
}

const PYTHON_AUTOCOMPLETE_SUGGESTIONS = [
  "print()", "input()", "len()", "range()", "int()", "str()", "float()",
  "list()", "dict()", "set()", "tuple()", "if", "elif", "else:", "for",
  "while", "break", "continue", "def", "return", "class", "import",
  "from", "try:", "except Exception as e:", "finally:", "with", "open()",
  "append()", "enumerate()", "zip()", "map()", "filter()",
]

const PLACEHOLDER_CODE = `# No code detected at this timestamp
# 
# This could mean:
# - The instructor is explaining concepts without showing code
# - The video is in a learning/theory phase
# - No code is visible on screen at this moment
#
# Try pausing when you see code on the video screen.
# You can also write your own code here!

print("Write your Python code here...")
`

export default function PythonCompiler({ onClose, isFullscreen = false, initialCode, videoId }: PythonCompilerProps) {
  const [code, setCode] = useState(initialCode || PLACEHOLDER_CODE)
  const [output, setOutput] = useState("")
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState("")
  const [executionTime, setExecutionTime] = useState(0)
  const [lineCount, setLineCount] = useState(1)
  const [terminalHeight, setTerminalHeight] = useState(40)
  const [isDragging, setIsDragging] = useState(false)
  const [autocompleteEnabled, setAutocompleteEnabled] = useState(true)
  const [suggestions, setSuggestions] = useState<SuggestionItem[]>([])
  const [showSuggestions, setShowSuggestions] = useState(false)
  const [activeSuggestionIndex, setActiveSuggestionIndex] = useState(0)
  const [aiSuggestion, setAiSuggestion] = useState("")
  const [isFetchingAiSuggestion, setIsFetchingAiSuggestion] = useState(false)

  // New enhancement states
  const [showHistory, setShowHistory] = useState(false)
  const [codeHistory, setCodeHistory] = useState<CodeHistoryEntry[]>([])
  const [isExplaining, setIsExplaining] = useState(false)
  const [errorExplanation, setErrorExplanation] = useState("")
  const [showShortcuts, setShowShortcuts] = useState(false)
  const [fontSize, setFontSize] = useState(14)

  const outputRef = useRef<HTMLDivElement>(null)
  const dividerRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  
  const hasExtractedCode = !!initialCode && !initialCode.includes("Welcome to Codio")

  useEffect(() => {
    if (initialCode) {
      setCode(initialCode)
      setOutput("")
      setError("")
      setErrorExplanation("")
    } else {
      setCode(PLACEHOLDER_CODE)
      setOutput("")
      setError("")
      setErrorExplanation("")
    }
  }, [initialCode])

  useEffect(() => {
    setLineCount(code.split("\n").length)
  }, [code])

  useEffect(() => {
    if (!autocompleteEnabled) {
      setShowSuggestions(false)
      setSuggestions([])
      setAiSuggestion("")
    }
  }, [autocompleteEnabled])

  useEffect(() => {
    if (!autocompleteEnabled) return
    const el = textareaRef.current
    if (!el) return
    const cursor = el.selectionStart ?? code.length
    if (code.trim().length < 2) { setAiSuggestion(""); return }

    const timer = setTimeout(async () => {
      try {
        setIsFetchingAiSuggestion(true)
        const response = await api.completePythonCode(code, cursor)
        setAiSuggestion((response.completion || "").trim())
      } catch { setAiSuggestion("") }
      finally { setIsFetchingAiSuggestion(false) }
    }, 550)
    return () => clearTimeout(timer)
  }, [code, autocompleteEnabled])

  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight
  }, [output, error])

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging) return
      const container = dividerRef.current?.parentElement
      if (!container) return
      const containerHeight = container.clientHeight
      const newHeight = ((e.clientY - container.getBoundingClientRect().top) / containerHeight) * 100
      if (newHeight > 20 && newHeight < 80) setTerminalHeight(100 - newHeight)
    }
    const handleMouseUp = () => setIsDragging(false)
    if (isDragging) {
      document.addEventListener("mousemove", handleMouseMove)
      document.addEventListener("mouseup", handleMouseUp)
    }
    return () => {
      document.removeEventListener("mousemove", handleMouseMove)
      document.removeEventListener("mouseup", handleMouseUp)
    }
  }, [isDragging])

  // Global keyboard shortcuts
  useEffect(() => {
    const handleGlobalKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.ctrlKey && e.key === "Enter") {
        e.preventDefault()
        runCode()
      }
      if (e.ctrlKey && e.key === "s") {
        e.preventDefault()
        handleDownloadCode()
      }
      if (e.ctrlKey && e.key === "+") {
        e.preventDefault()
        setFontSize(prev => Math.min(prev + 1, 24))
      }
      if (e.ctrlKey && e.key === "-") {
        e.preventDefault()
        setFontSize(prev => Math.max(prev - 1, 10))
      }
    }
    window.addEventListener("keydown", handleGlobalKeyDown)
    return () => window.removeEventListener("keydown", handleGlobalKeyDown)
  }, [code])

  const runCode = async () => {
    setIsRunning(true)
    setError("")
    setOutput("")
    setErrorExplanation("")
    const startTime = performance.now()

    try {
      let runResult: any
      try {
        const proxyResponse = await api.executePythonCode(code)
        runResult = proxyResponse.run
      } catch {
        const response = await fetch("https://emkc.org/api/v2/piston/execute", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ language: "python", version: "3.10.0", files: [{ content: code }] }),
        })
        const data = await response.json().catch(() => ({}))
        if (!response.ok) throw new Error(data?.error || data?.message || `Execution API error (${response.status})`)
        runResult = data.run
      }

      const endTime = performance.now()
      setExecutionTime(endTime - startTime)

      if (!runResult || typeof runResult.code !== "number") {
        throw new Error("Execution service returned an invalid response")
      }

      const stdout = runResult?.stdout || runResult?.output || ""
      const stderr = runResult?.stderr || ""

      if (runResult?.code === 0) {
        setOutput(stdout || "Code executed successfully!")
        setError("")
      } else {
        setError(stderr || `Execution failed (exit code ${runResult.code})`)
        setOutput("")
      }

      // Save to code history
      const historyEntry: CodeHistoryEntry = {
        id: Date.now().toString(),
        code,
        output: stdout,
        error: stderr,
        timestamp: new Date().toISOString(),
      }
      setCodeHistory(prev => [historyEntry, ...prev].slice(0, 50))

      // Save to backend if videoId available
      if (videoId) {
        api.saveCodeRun(videoId, code, stdout, stderr).catch(() => {})
      }
    } catch (err: any) {
      setError(err.message || "Unable to execute code right now")
      setOutput("")
    } finally {
      setIsRunning(false)
    }
  }

  const handleExplainError = async () => {
    if (!error || isExplaining) return
    setIsExplaining(true)
    try {
      const res = await api.explainError(code, error)
      if (res.success && res.explanation) {
        setErrorExplanation(res.explanation)
      } else {
        setErrorExplanation("Could not generate explanation. The error might be too complex or the AI service is unavailable.")
      }
    } catch {
      setErrorExplanation("Failed to connect to AI service. Please try again.")
    } finally {
      setIsExplaining(false)
    }
  }

  const handleCopyCode = () => {
    navigator.clipboard.writeText(code).catch(() => {})
  }

  const handleDownloadCode = () => {
    const blob = new Blob([code], { type: "text/x-python" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = "code.py"
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleResetCode = () => {
    if (initialCode) {
      setCode(initialCode)
    } else {
      setCode(PLACEHOLDER_CODE)
    }
    setOutput("")
    setError("")
    setErrorExplanation("")
  }

  const loadFromHistory = (entry: CodeHistoryEntry) => {
    setCode(entry.code)
    setOutput(entry.output)
    setError(entry.error)
    setShowHistory(false)
    setErrorExplanation("")
  }

  const getWordAtCursor = (value: string, cursor: number) => {
    let start = cursor
    let end = cursor
    while (start > 0 && /[A-Za-z0-9_]/.test(value[start - 1])) start -= 1
    while (end < value.length && /[A-Za-z0-9_]/.test(value[end])) end += 1
    return { word: value.slice(start, cursor), start, end }
  }

  const buildSuggestions = (prefix: string): SuggestionItem[] => {
    const localWords = Array.from(new Set((code.match(/[A-Za-z_][A-Za-z0-9_]*/g) || [])))
    const aiItems: SuggestionItem[] = aiSuggestion
      ? [{ label: `AI: ${aiSuggestion.split("\n")[0].slice(0, 80)}`, insertText: aiSuggestion, source: "ai", replaceWord: false }]
      : []
    if (!prefix) return aiItems
    const loweredPrefix = prefix.toLowerCase()
    const localItems = Array.from(new Set([...PYTHON_AUTOCOMPLETE_SUGGESTIONS, ...localWords]))
      .filter((item) => item.toLowerCase().startsWith(loweredPrefix))
      .map((item) => ({ label: item, insertText: item, source: "local" as const, replaceWord: true }))
      .slice(0, 8)
    return [...aiItems, ...localItems].slice(0, 8)
  }

  const refreshSuggestions = () => {
    if (!autocompleteEnabled) return
    const el = textareaRef.current
    if (!el) return
    const cursor = el.selectionStart ?? 0
    const { word } = getWordAtCursor(code, cursor)
    const next = buildSuggestions(word)
    setSuggestions(next)
    setActiveSuggestionIndex(0)
    setShowSuggestions(next.length > 0)
  }

  const applySuggestion = (suggestion: SuggestionItem) => {
    const el = textareaRef.current
    if (!el) return
    const cursorStart = el.selectionStart ?? 0
    const cursorEnd = el.selectionEnd ?? cursorStart
    let nextCode = code
    let nextCursor = cursorStart

    if (suggestion.replaceWord) {
      const { start, end } = getWordAtCursor(code, cursorStart)
      const replaceEnd = Math.max(end, cursorEnd)
      nextCode = `${code.slice(0, start)}${suggestion.insertText}${code.slice(replaceEnd)}`
      nextCursor = start + suggestion.insertText.length
    } else {
      nextCode = `${code.slice(0, cursorStart)}${suggestion.insertText}${code.slice(cursorEnd)}`
      nextCursor = cursorStart + suggestion.insertText.length
    }

    setCode(nextCode)
    setShowSuggestions(false)
    setSuggestions([])
    if (suggestion.source === "ai") setAiSuggestion("")
    requestAnimationFrame(() => { el.focus(); el.setSelectionRange(nextCursor, nextCursor) })
  }

  const handleEditorChange = (value: string) => {
    setCode(value)
    requestAnimationFrame(() => refreshSuggestions())
  }

  const handleEditorKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (autocompleteEnabled && e.ctrlKey && e.code === "Space") {
      e.preventDefault(); refreshSuggestions(); return
    }
    if (!autocompleteEnabled || !showSuggestions || suggestions.length === 0) return
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveSuggestionIndex((prev) => (prev + 1) % suggestions.length); return }
    if (e.key === "ArrowUp") { e.preventDefault(); setActiveSuggestionIndex((prev) => (prev - 1 + suggestions.length) % suggestions.length); return }
    if (e.key === "Tab" || e.key === "Enter") { e.preventDefault(); applySuggestion(suggestions[activeSuggestionIndex]); return }
    if (e.key === "Escape") { setShowSuggestions(false); return }
  }

  /* ==================== Shared Editor + Terminal ==================== */

  const renderToolbar = () => (
    <div className="px-4 py-2.5 border-b border-[#3e3e42] bg-[#252526] flex items-center justify-between flex-shrink-0">
      <div className="flex items-center gap-2">
        <p className="text-xs font-mono text-[#cccccc]">Python Compiler</p>
        {hasExtractedCode && (
          <span className="px-2 py-0.5 bg-blue-600/20 text-blue-400 text-[10px] rounded border border-blue-600/30">
            Code extracted from video
          </span>
        )}
        <Button onClick={() => setAutocompleteEnabled((prev) => !prev)} variant="ghost" size="sm"
          className="text-[#cccccc] hover:bg-[#3e3e42] h-6 text-[10px] px-2">
          Auto Complete: {autocompleteEnabled ? "On" : "Off"}
        </Button>
      </div>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="sm" className="text-[#858585] hover:bg-[#3e3e42] h-6 w-6 p-0"
          onClick={handleCopyCode} title="Copy Code">
          <Copy className="w-3 h-3" />
        </Button>
        <Button variant="ghost" size="sm" className="text-[#858585] hover:bg-[#3e3e42] h-6 w-6 p-0"
          onClick={handleDownloadCode} title="Download (Ctrl+S)">
          <Download className="w-3 h-3" />
        </Button>
        <Button variant="ghost" size="sm" className="text-[#858585] hover:bg-[#3e3e42] h-6 w-6 p-0"
          onClick={handleResetCode} title="Reset Code">
          <RotateCcw className="w-3 h-3" />
        </Button>
        <Button variant="ghost" size="sm" className={`h-6 w-6 p-0 ${showHistory ? "text-[#007acc]" : "text-[#858585]"} hover:bg-[#3e3e42]`}
          onClick={() => { setShowHistory(!showHistory); setShowShortcuts(false) }} title="Code History">
          <History className="w-3 h-3" />
        </Button>
        <Button variant="ghost" size="sm" className={`h-6 w-6 p-0 ${showShortcuts ? "text-[#007acc]" : "text-[#858585]"} hover:bg-[#3e3e42]`}
          onClick={() => { setShowShortcuts(!showShortcuts); setShowHistory(false) }} title="Keyboard Shortcuts">
          <Keyboard className="w-3 h-3" />
        </Button>
        <div className="mx-1 h-4 w-px bg-[#3e3e42]" />
        <Button onClick={onClose} variant="ghost" size="sm" className="text-[#cccccc] hover:bg-[#3e3e42] h-6 text-[10px] px-2">
          {hasExtractedCode ? "Back to Video" : <X className="w-3 h-3" />}
        </Button>
      </div>
    </div>
  )

  const renderEditor = () => (
    <div className="flex-1 flex flex-col overflow-hidden" style={{ height: `${100 - terminalHeight}%` }}>
      <div className="flex-1 flex overflow-hidden relative">
        {/* Line Numbers */}
        <div className="bg-[#1e1e1e] border-r border-[#3e3e42] px-3 py-4 text-right font-mono select-none overflow-hidden"
          style={{ fontSize: `${fontSize - 2}px` }}>
          {Array.from({ length: lineCount }, (_, i) => (
            <div key={i + 1} className="leading-6 text-[#858585]">{i + 1}</div>
          ))}
        </div>

        {/* Code Input */}
        <textarea
          ref={textareaRef}
          value={code}
          onChange={(e) => handleEditorChange(e.target.value)}
          onKeyDown={handleEditorKeyDown}
          onKeyUp={refreshSuggestions}
          onClick={refreshSuggestions}
          onBlur={() => setTimeout(() => setShowSuggestions(false), 120)}
          className="flex-1 p-4 bg-[#1e1e1e] text-[#d4d4d4] font-mono resize-none focus:outline-none"
          style={{ fontSize: `${fontSize}px` }}
          spellCheck="false"
          placeholder="Write your Python code here..."
        />

        {/* Autocomplete Suggestions */}
        {autocompleteEnabled && showSuggestions && suggestions.length > 0 && (
          <div className="absolute right-4 bottom-4 w-72 max-h-52 overflow-auto rounded border border-[#3e3e42] bg-[#252526] shadow-lg z-20">
            <div className="px-3 py-2 text-[10px] font-mono text-[#858585] border-b border-[#3e3e42]">
              Suggestions (Tab/Enter to apply){isFetchingAiSuggestion ? " - AI thinking..." : ""}
            </div>
            {suggestions.map((item, index) => (
              <button key={`${item.source}-${item.label}-${index}`} type="button"
                onMouseDown={(e) => { e.preventDefault(); applySuggestion(item) }}
                className={`w-full text-left px-3 py-2 text-xs font-mono ${index === activeSuggestionIndex ? "bg-[#094771] text-white" : "text-[#d4d4d4] hover:bg-[#2a2d2e]"}`}>
                <span className="opacity-70 mr-2">[{item.source.toUpperCase()}]</span>{item.label}
              </button>
            ))}
          </div>
        )}

        {/* History Panel */}
        {showHistory && (
          <div className="absolute right-0 top-0 bottom-0 w-72 bg-[#252526] border-l border-[#3e3e42] z-30 flex flex-col">
            <div className="px-3 py-2 border-b border-[#3e3e42] flex items-center justify-between">
              <span className="text-xs font-mono text-[#cccccc]">Code History</span>
              <Button variant="ghost" size="sm" className="h-5 w-5 p-0 text-[#858585] hover:bg-[#3e3e42]"
                onClick={() => setShowHistory(false)}>
                <X className="w-3 h-3" />
              </Button>
            </div>
            <div className="flex-1 overflow-y-auto">
              {codeHistory.length === 0 ? (
                <p className="p-4 text-xs text-[#858585] text-center">No history yet. Run some code!</p>
              ) : (
                codeHistory.map((entry) => (
                  <button key={entry.id} onClick={() => loadFromHistory(entry)}
                    className="w-full text-left px-3 py-2 border-b border-[#3e3e42] hover:bg-[#2a2d2e] transition-colors">
                    <p className="text-[10px] text-[#858585]">{new Date(entry.timestamp).toLocaleTimeString()}</p>
                    <pre className="text-xs text-[#d4d4d4] font-mono truncate mt-1">{entry.code.split("\n")[0]}</pre>
                    {entry.error ? (
                      <span className="text-[10px] text-[#f48771]">Error</span>
                    ) : (
                      <span className="text-[10px] text-[#4ec9b0]">Success</span>
                    )}
                  </button>
                ))
              )}
            </div>
          </div>
        )}

        {/* Shortcuts Panel */}
        {showShortcuts && (
          <div className="absolute right-0 top-0 bottom-0 w-72 bg-[#252526] border-l border-[#3e3e42] z-30 flex flex-col">
            <div className="px-3 py-2 border-b border-[#3e3e42] flex items-center justify-between">
              <span className="text-xs font-mono text-[#cccccc]">Keyboard Shortcuts</span>
              <Button variant="ghost" size="sm" className="h-5 w-5 p-0 text-[#858585] hover:bg-[#3e3e42]"
                onClick={() => setShowShortcuts(false)}>
                <X className="w-3 h-3" />
              </Button>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-2">
              {[
                ["Ctrl + Enter", "Run Code"],
                ["Ctrl + S", "Download Code"],
                ["Ctrl + Space", "Open Suggestions"],
                ["Ctrl + +", "Increase Font Size"],
                ["Ctrl + -", "Decrease Font Size"],
                ["Tab / Enter", "Apply Suggestion"],
                ["Escape", "Close Suggestions"],
              ].map(([key, desc]) => (
                <div key={key} className="flex items-center justify-between">
                  <span className="text-xs text-[#d4d4d4]">{desc}</span>
                  <kbd className="px-1.5 py-0.5 bg-[#3e3e42] text-[10px] text-[#cccccc] rounded font-mono">{key}</kbd>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )

  const renderTerminal = () => (
    <div className="border-t border-[#3e3e42] bg-[#1e1e1e] flex flex-col overflow-hidden flex-shrink-0"
      style={{ height: `${terminalHeight}%` }}>
      {/* Terminal Header */}
      <div className="px-4 py-2.5 border-b border-[#3e3e42] bg-[#252526] flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2">
          <ChevronDown className="w-4 h-4 text-[#cccccc]" />
          <p className="text-xs font-mono text-[#cccccc]">OUTPUT</p>
          {error && !isExplaining && (
            <Button onClick={handleExplainError} variant="ghost" size="sm"
              className="text-amber-400 hover:bg-[#3e3e42] h-6 text-[10px] px-2 gap-1">
              <Lightbulb className="w-3 h-3" />
              Explain Error
            </Button>
          )}
          {isExplaining && (
            <span className="text-[10px] text-amber-400 animate-pulse">AI analyzing error...</span>
          )}
        </div>
        <div className="flex gap-2 items-center">
          <span className="text-[10px] text-[#858585] font-mono">Font: {fontSize}px</span>
          {executionTime > 0 && <span className="text-xs text-[#858585]">{executionTime.toFixed(0)}ms</span>}
          <Button onClick={runCode} disabled={isRunning}
            className="text-xs h-7 bg-[#007acc] hover:bg-[#005a9e] text-white flex items-center gap-1">
            <Play className="w-3 h-3" />
            {isRunning ? "Running..." : "Run (Ctrl+Enter)"}
          </Button>
        </div>
      </div>

      {/* Terminal Content */}
      <div ref={outputRef} className="flex-1 overflow-auto p-4 font-mono text-[#d4d4d4] space-y-2 bg-[#1e1e1e]"
        style={{ fontSize: `${fontSize - 2}px` }}>
        {error ? (
          <div>
            <div className="text-[#f48771]">
              <p className="font-semibold mb-2">Error:</p>
              <pre className="whitespace-pre-wrap break-words">{error}</pre>
            </div>
            {errorExplanation && (
              <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
                <div className="flex items-center gap-2 mb-2">
                  <Lightbulb className="w-3.5 h-3.5 text-amber-400" />
                  <span className="text-xs font-semibold text-amber-400">AI Error Explanation</span>
                </div>
                <pre className="whitespace-pre-wrap break-words text-[#d4d4d4] text-xs">{errorExplanation}</pre>
              </div>
            )}
          </div>
        ) : output ? (
          <div>
            <pre className="whitespace-pre-wrap break-words text-[#ce9178]">{output}</pre>
          </div>
        ) : (
          <p className="text-[#858585]">Output will appear here... Press Ctrl+Enter to run</p>
        )}
      </div>
    </div>
  )

  return (
    <div className={`${isFullscreen ? "fixed inset-0 z-50" : "w-full h-full"} flex flex-col bg-[#1e1e1e]`}>
      {renderToolbar()}
      <div className="flex-1 flex flex-col overflow-hidden">
        {renderEditor()}
        <div ref={dividerRef} onMouseDown={() => setIsDragging(true)}
          className="h-1 bg-[#3e3e42] hover:bg-[#007acc] cursor-row-resize transition-colors flex-shrink-0" />
        {renderTerminal()}
      </div>
    </div>
  )
}
