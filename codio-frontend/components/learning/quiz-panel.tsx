"use client"

import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import {
  Sparkles, Trophy, Gauge, CircleCheckBig, Code, CheckCircle2, XCircle,
  HelpCircle, History, Timer, RotateCcw, ChevronRight, Clock, Star,
} from "lucide-react"
import { api, getAccessToken, QuizQuestion } from "@/lib/api"
import { toast } from "sonner"

interface QuizPanelProps {
  userEmail: string
  videoId: string
}

interface QuizHistoryEntry {
  session_id: string
  score: number
  questions_answered: number
  correct_answers: number
  date: string
  video_id?: string
}

interface ReviewQuestion {
  question: string
  type: string
  user_answer: string
  correct_answer: string
  is_correct: boolean
  explanation: string
}

const QUESTION_TYPE_INFO: Record<string, { label: string; color: string }> = {
  multiple_choice: { label: "Multiple Choice", color: "bg-blue-500/10 text-blue-600 border-blue-500/30" },
  true_false: { label: "True / False", color: "bg-purple-500/10 text-purple-600 border-purple-500/30" },
  fill_in_blank: { label: "Fill in the Blank", color: "bg-amber-500/10 text-amber-600 border-amber-500/30" },
  output_prediction: { label: "Output Prediction", color: "bg-emerald-500/10 text-emerald-600 border-emerald-500/30" },
}

export default function QuizPanel({ userEmail, videoId }: QuizPanelProps) {
  const [transcript, setTranscript] = useState("")
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [currentQuestion, setCurrentQuestion] = useState<QuizQuestion | null>(null)
  const [selectedAnswer, setSelectedAnswer] = useState<number | string | null>(null)
  const [fillInAnswer, setFillInAnswer] = useState("")
  const [questionStartTime, setQuestionStartTime] = useState<number | null>(null)
  const [learningRate, setLearningRate] = useState(0)
  const [currentLevel, setCurrentLevel] = useState(1)
  const [questionsAnswered, setQuestionsAnswered] = useState(0)
  const [correctAnswers, setCorrectAnswers] = useState(0)
  const [feedback, setFeedback] = useState<{ text: string; isCorrect: boolean } | null>(null)
  const [quizEnded, setQuizEnded] = useState(false)
  const [finalScore, setFinalScore] = useState<number | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [startError, setStartError] = useState<string | null>(null)

  // New enhancement states
  const [showHistory, setShowHistory] = useState(false)
  const [quizHistory, setQuizHistory] = useState<QuizHistoryEntry[]>([])
  const [showReview, setShowReview] = useState(false)
  const [reviewQuestions, setReviewQuestions] = useState<ReviewQuestion[]>([])
  const [timedMode, setTimedMode] = useState(false)
  const [timeRemaining, setTimeRemaining] = useState(30)
  const [answeredQuestions, setAnsweredQuestions] = useState<ReviewQuestion[]>([])
  const timerRef = useRef<NodeJS.Timeout | null>(null)

  const canStartQuiz = !!videoId || transcript.trim().length > 0

  // Timer effect for timed mode
  useEffect(() => {
    if (timedMode && currentQuestion && !feedback && timeRemaining > 0) {
      timerRef.current = setInterval(() => {
        setTimeRemaining(prev => {
          if (prev <= 1) {
            // Auto-submit when time runs out
            clearInterval(timerRef.current!)
            submitAnswer()
            return 0
          }
          return prev - 1
        })
      }, 1000)
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [timedMode, currentQuestion, feedback])

  // Load quiz history on mount
  useEffect(() => {
    api.getQuizHistory(10).then(res => {
      if (res.success) setQuizHistory(res.history || [])
    }).catch(() => {})
  }, [])

  const loadTranscriptFromVideo = async () => {
    setIsLoading(true)
    try {
      try {
        const existing = await api.getFullTranscript(videoId)
        if (existing.success && existing.transcript) {
          setTranscript(existing.transcript)
          toast.success("Transcript loaded from current video")
          return
        }
      } catch {}
      const extracted = await api.extractTranscript(videoId)
      if (!extracted.success) { toast.error(extracted.error || "Unable to extract transcript"); return }
      const loaded = await api.getFullTranscript(videoId)
      if (loaded.success && loaded.transcript) {
        setTranscript(loaded.transcript)
        toast.success("Transcript extracted and loaded")
      } else {
        toast.error("Transcript extraction completed but text could not be loaded")
      }
    } catch (error: any) {
      toast.error(error.message || "Failed to load transcript")
    } finally {
      setIsLoading(false)
    }
  }

  const startQuiz = async () => {
    if (!canStartQuiz) { setStartError("Load a video transcript or paste transcript text first"); return }
    if (!getAccessToken()) { setStartError("Please log in again before starting a quiz"); return }

    setIsLoading(true)
    setFeedback(null)
    setStartError(null)
    setAnsweredQuestions([])

    try {
      const transcriptPayload = videoId ? "" : transcript.trim()
      const response = await Promise.race([
        api.startQuiz(userEmail, transcriptPayload, videoId),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Quiz start timed out.")), 12000))
      ])

      if (!response.success) { setStartError("Quiz failed to start. Please try again."); return }

      setSessionId(response.session_id)
      setCurrentQuestion(response.first_question)
      setCurrentLevel(response.current_level)
      setLearningRate(response.learning_rate)
      setQuestionStartTime(Date.now())
      setQuestionsAnswered(0)
      setCorrectAnswers(0)
      setQuizEnded(false)
      setFinalScore(null)
      setSelectedAnswer(null)
      setFillInAnswer("")
      setShowHistory(false)
      setShowReview(false)
      if (timedMode) setTimeRemaining(30)
      toast.success("Quiz started")
    } catch (error: any) {
      setStartError(error?.message || "Failed to start quiz")
    } finally {
      setIsLoading(false)
    }
  }

  const getAnswerToSubmit = (): number | string | null => {
    if (!currentQuestion) return null
    switch (currentQuestion.type) {
      case "fill_in_blank": return fillInAnswer.trim() || null
      case "true_false": return selectedAnswer !== null ? (selectedAnswer === 0 ? "true" : "false") : null
      default: return selectedAnswer
    }
  }

  const submitAnswer = async () => {
    if (!sessionId || !currentQuestion) return
    const answerToSubmit = getAnswerToSubmit()
    if (answerToSubmit === null && timeRemaining > 0) return

    setIsLoading(true)
    if (timerRef.current) clearInterval(timerRef.current)

    try {
      const elapsed = questionStartTime ? Math.max(1, Math.floor((Date.now() - questionStartTime) / 1000)) : 1
      const response = await api.submitQuizAnswer(sessionId, currentQuestion.id, answerToSubmit ?? -1, elapsed)

      setLearningRate(response.learning_rate)
      setCurrentLevel(response.new_level)
      if (response.progress) {
        setQuestionsAnswered(response.progress.questionsAnswered)
        setCorrectAnswers(response.progress.correctAnswers)
      }

      setFeedback({
        text: response.explanation || (response.is_correct ? "Correct!" : "Incorrect."),
        isCorrect: response.is_correct,
      })

      // Save for review
      setAnsweredQuestions(prev => [...prev, {
        question: currentQuestion.content.question,
        type: currentQuestion.type,
        user_answer: String(answerToSubmit ?? "No answer"),
        correct_answer: response.explanation || "",
        is_correct: response.is_correct,
        explanation: response.explanation || "",
      }])

      if (response.next_question) {
        setTimeout(() => {
          setCurrentQuestion(response.next_question!)
          setSelectedAnswer(null)
          setFillInAnswer("")
          setQuestionStartTime(Date.now())
          setFeedback(null)
          if (timedMode) setTimeRemaining(30)
        }, 2000)
      } else if (!response.should_continue) {
        setTimeout(() => finishQuiz(sessionId), 2000)
      }
    } catch (error: any) {
      toast.error(error.message || "Failed to submit answer")
    } finally {
      setIsLoading(false)
    }
  }

  const finishQuiz = async (activeSessionId: string) => {
    try {
      const result = await api.endQuizSession(activeSessionId)
      setQuizEnded(true)
      setCurrentQuestion(null)
      setFinalScore(result.final_score ?? null)
      setFeedback(null)
      if (timerRef.current) clearInterval(timerRef.current)
      // Refresh history
      api.getQuizHistory(10).then(res => {
        if (res.success) setQuizHistory(res.history || [])
      }).catch(() => {})
      toast.success("Quiz completed")
    } catch (error: any) {
      toast.error(error.message || "Failed to end quiz session")
    }
  }

  const loadReview = async (sid: string) => {
    try {
      const res = await api.getQuizReview(sid)
      if (res.success && res.questions) {
        setReviewQuestions(res.questions)
        setShowReview(true)
        setShowHistory(false)
      } else {
        toast.error("Could not load review for this session")
      }
    } catch {
      toast.error("Failed to load quiz review")
    }
  }

  const resetQuiz = () => {
    setSessionId(null)
    setCurrentQuestion(null)
    setSelectedAnswer(null)
    setFillInAnswer("")
    setQuestionStartTime(null)
    setLearningRate(0)
    setCurrentLevel(1)
    setQuestionsAnswered(0)
    setCorrectAnswers(0)
    setFeedback(null)
    setQuizEnded(false)
    setFinalScore(null)
    setShowReview(false)
    setAnsweredQuestions([])
    if (timerRef.current) clearInterval(timerRef.current)
  }

  const isAnswerSelected = (): boolean => {
    if (!currentQuestion) return false
    switch (currentQuestion.type) {
      case "fill_in_blank": return fillInAnswer.trim().length > 0
      default: return selectedAnswer !== null
    }
  }

  // ---- Review Mode ----
  if (showReview) {
    return (
      <div className="h-full space-y-3 overflow-y-auto p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-foreground">Quiz Review</h3>
          <Button variant="ghost" size="sm" className="text-xs" onClick={() => setShowReview(false)}>
            Back
          </Button>
        </div>
        {reviewQuestions.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-4">No review data available for this session.</p>
        ) : (
          reviewQuestions.map((q, i) => (
            <div key={i} className={`rounded-xl border p-3 ${q.is_correct ? "border-emerald-500/30 bg-emerald-50/50 dark:bg-emerald-900/10" : "border-red-500/30 bg-red-50/50 dark:bg-red-900/10"}`}>
              <div className="flex items-start gap-2 mb-2">
                {q.is_correct ? <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5" /> : <XCircle className="h-4 w-4 text-red-500 mt-0.5" />}
                <p className="text-xs font-medium text-foreground">{q.question}</p>
              </div>
              <div className="ml-6 space-y-1 text-xs text-muted-foreground">
                <p>Your answer: <span className="font-mono">{q.user_answer}</span></p>
                {q.explanation && <p className="italic">{q.explanation}</p>}
              </div>
            </div>
          ))
        )}
      </div>
    )
  }

  // ---- History View ----
  if (showHistory) {
    return (
      <div className="h-full space-y-3 overflow-y-auto p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-muted-foreground" />
            <h3 className="text-sm font-semibold text-foreground">Quiz History</h3>
          </div>
          <Button variant="ghost" size="sm" className="text-xs" onClick={() => setShowHistory(false)}>
            Back
          </Button>
        </div>
        {quizHistory.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-8">No quiz history yet. Take a quiz to see your results here!</p>
        ) : (
          quizHistory.map((entry, i) => {
            const scoreColor = entry.score >= 80 ? "text-emerald-500" : entry.score >= 50 ? "text-amber-500" : "text-red-500"
            return (
              <div key={i} className="rounded-xl border border-border/60 bg-card/65 p-3 hover:bg-card/80 transition-colors">
                <div className="flex items-center justify-between mb-1">
                  <span className={`text-lg font-bold ${scoreColor}`}>{entry.score}%</span>
                  <span className="text-[10px] text-muted-foreground">{new Date(entry.date).toLocaleDateString()}</span>
                </div>
                <p className="text-xs text-muted-foreground">{entry.correct_answers}/{entry.questions_answered} correct</p>
                <Button variant="ghost" size="sm" className="mt-1 text-xs text-primary h-6 px-2"
                  onClick={() => loadReview(entry.session_id)}>
                  Review Answers <ChevronRight className="h-3 w-3 ml-1" />
                </Button>
              </div>
            )
          })
        )}
      </div>
    )
  }

  // ---- Start screen ----
  if (!sessionId && !currentQuestion) {
    return (
      <div className="h-full space-y-4 overflow-y-auto p-4">
        <div className="space-y-2 rounded-xl border border-border/60 bg-card/65 p-4">
          <div className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-wide text-primary">
            <Sparkles className="h-3.5 w-3.5" />
            Adaptive Quiz Engine
          </div>
          <h3 className="text-sm font-semibold text-foreground">Quiz From Current Video</h3>
          <p className="text-xs text-muted-foreground">
            Generate quiz questions from this video&apos;s transcript. Questions adapt to your level with 4 types: multiple choice, true/false, fill-in-the-blank, and output prediction.
          </p>
        </div>

        {/* Mode Selection */}
        <div className="flex gap-2">
          <Button
            variant={timedMode ? "outline" : "default"}
            size="sm"
            className="flex-1 text-xs"
            onClick={() => setTimedMode(false)}
          >
            <Star className="h-3 w-3 mr-1" />
            Normal Mode
          </Button>
          <Button
            variant={timedMode ? "default" : "outline"}
            size="sm"
            className="flex-1 text-xs"
            onClick={() => setTimedMode(true)}
          >
            <Timer className="h-3 w-3 mr-1" />
            Timed Mode (30s)
          </Button>
        </div>

        <Button variant="outline" className="w-full border-border/60 bg-background/50" onClick={loadTranscriptFromVideo} disabled={isLoading || !videoId}>
          {isLoading ? "Loading transcript..." : "Use Current Video Transcript"}
        </Button>

        <Textarea
          value={transcript}
          onChange={(e) => setTranscript(e.target.value)}
          rows={8}
          placeholder="Transcript text will appear here. You can also paste custom transcript."
          className="min-h-36 border-border/60 bg-background/60"
        />

        {startError && <p className="text-xs text-red-500">{startError}</p>}

        <Button className="w-full bg-primary font-semibold text-primary-foreground hover:bg-primary/90" onClick={startQuiz} disabled={isLoading || !canStartQuiz}>
          {isLoading ? "Starting quiz..." : "Start Quiz"}
        </Button>

        {/* History Button */}
        <Button variant="outline" className="w-full border-border/60 bg-background/50 text-xs" onClick={() => setShowHistory(true)}>
          <History className="h-3 w-3 mr-1" />
          View Quiz History ({quizHistory.length})
        </Button>
      </div>
    )
  }

  // ---- Results screen ----
  if (quizEnded) {
    const scoreColor = (finalScore ?? 0) >= 80 ? "text-emerald-500" : (finalScore ?? 0) >= 50 ? "text-amber-500" : "text-red-500"
    return (
      <div className="h-full space-y-4 overflow-y-auto p-4">
        <div className="rounded-2xl border border-border/60 bg-card/70 p-4">
          <div className="mb-3 flex items-center gap-2 text-foreground">
            <Trophy className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">Quiz Results</h3>
          </div>
          <div className="flex items-center justify-center py-4">
            <div className="relative h-24 w-24">
              <svg className="h-24 w-24 -rotate-90" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="52" fill="none" stroke="hsl(var(--muted))" strokeWidth="8" opacity="0.3" />
                <circle cx="60" cy="60" r="52" fill="none"
                  stroke={(finalScore ?? 0) >= 80 ? "#10b981" : (finalScore ?? 0) >= 50 ? "#f59e0b" : "#ef4444"}
                  strokeWidth="8"
                  strokeDasharray={`${2 * Math.PI * 52}`}
                  strokeDashoffset={`${2 * Math.PI * 52 * (1 - (finalScore ?? 0) / 100)}`}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-2xl font-bold ${scoreColor}`}>{finalScore ?? 0}%</span>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-2 text-center text-xs">
            <div className="rounded-lg bg-muted/30 p-2">
              <p className="font-semibold text-foreground">{correctAnswers}/{questionsAnswered}</p>
              <p className="text-muted-foreground">Correct</p>
            </div>
            <div className="rounded-lg bg-muted/30 p-2">
              <p className="font-semibold text-foreground">Level {currentLevel}</p>
              <p className="text-muted-foreground">Final</p>
            </div>
            <div className="rounded-lg bg-muted/30 p-2">
              <p className="font-semibold text-foreground">{Math.round(learningRate * 100)}%</p>
              <p className="text-muted-foreground">Learning</p>
            </div>
          </div>
          {(finalScore ?? 0) >= 80 && (
            <div className="mt-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 p-2 text-center text-xs text-emerald-700 dark:text-emerald-300">
              Excellent work! You have a strong understanding of this topic.
            </div>
          )}
          {(finalScore ?? 0) >= 50 && (finalScore ?? 0) < 80 && (
            <div className="mt-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 p-2 text-center text-xs text-amber-700 dark:text-amber-300">
              Good effort! Review the topics you missed and try again.
            </div>
          )}
          {(finalScore ?? 0) < 50 && (
            <div className="mt-3 rounded-lg bg-red-50 dark:bg-red-900/20 p-2 text-center text-xs text-red-700 dark:text-red-300">
              Keep practicing! Re-watch the video and try the quiz again.
            </div>
          )}
        </div>

        {/* Review answered questions */}
        {answeredQuestions.length > 0 && (
          <Button variant="outline" className="w-full border-border/60 text-xs" onClick={() => { setReviewQuestions(answeredQuestions); setShowReview(true) }}>
            <History className="h-3 w-3 mr-1" />
            Review Your Answers
          </Button>
        )}

        <Button className="w-full bg-primary font-semibold text-primary-foreground hover:bg-primary/90" onClick={resetQuiz}>
          <RotateCcw className="h-3 w-3 mr-1" />
          Start New Quiz
        </Button>
        <Button variant="outline" className="w-full border-border/60 bg-background/50 text-xs" onClick={() => setShowHistory(true)}>
          <History className="h-3 w-3 mr-1" />
          View All History
        </Button>
      </div>
    )
  }

  // ---- Active quiz screen ----
  const accuracy = questionsAnswered > 0 ? Math.round((correctAnswers / questionsAnswered) * 100) : 0
  const learningPercent = Math.max(0, Math.min(100, Math.round(learningRate * 100)))
  const typeInfo = currentQuestion ? QUESTION_TYPE_INFO[currentQuestion.type] || QUESTION_TYPE_INFO.multiple_choice : null

  const renderQuestionContent = () => {
    if (!currentQuestion) return null

    switch (currentQuestion.type) {
      case "true_false":
        return (
          <div className="space-y-2">
            {["True", "False"].map((option, index) => (
              <Button key={index}
                variant={selectedAnswer === index ? "default" : "outline"}
                className={`h-auto w-full justify-start whitespace-normal rounded-xl border text-left transition-all duration-200 ${
                  selectedAnswer === index
                    ? "border-primary/80 bg-primary text-primary-foreground shadow-[0_10px_24px_-16px_var(--color-primary)]"
                    : "border-border/60 bg-background/55 hover:-translate-y-0.5 hover:border-primary/45"
                }`}
                onClick={() => setSelectedAnswer(index)}
                disabled={isLoading || feedback !== null}
              >
                <span className="mr-2 inline-flex h-6 w-6 items-center justify-center rounded-md border border-current/35 text-xs font-semibold">
                  {option === "True" ? "T" : "F"}
                </span>
                <span>{option}</span>
              </Button>
            ))}
          </div>
        )

      case "fill_in_blank":
        return (
          <div className="space-y-3">
            {currentQuestion.content.codeTemplate && (
              <div className="rounded-lg bg-zinc-900 p-3 font-mono text-sm text-zinc-100 overflow-x-auto">
                <div className="flex items-center gap-2 mb-2 text-xs text-zinc-400">
                  <Code className="h-3 w-3" /> Complete the code
                </div>
                <pre className="whitespace-pre-wrap">{currentQuestion.content.codeTemplate}</pre>
              </div>
            )}
            <Input type="text" placeholder="Type your answer..." value={fillInAnswer}
              onChange={(e) => setFillInAnswer(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && fillInAnswer.trim()) submitAnswer() }}
              disabled={isLoading || feedback !== null}
              className="font-mono border-border/60 bg-background/60" autoFocus
            />
          </div>
        )

      case "output_prediction":
        return (
          <div className="space-y-3">
            {currentQuestion.content.codeSnippet && (
              <div className="rounded-lg bg-zinc-900 p-3 font-mono text-sm text-zinc-100 overflow-x-auto">
                <div className="flex items-center gap-2 mb-2 text-xs text-zinc-400">
                  <Code className="h-3 w-3" /> Predict the output
                </div>
                <pre className="whitespace-pre-wrap">{currentQuestion.content.codeSnippet}</pre>
              </div>
            )}
            <div className="space-y-2">
              {currentQuestion.content.options.map((option, index) => (
                <Button key={index}
                  variant={selectedAnswer === index ? "default" : "outline"}
                  className={`h-auto w-full justify-start whitespace-normal rounded-xl border text-left transition-all duration-200 ${
                    selectedAnswer === index
                      ? "border-primary/80 bg-primary text-primary-foreground"
                      : "border-border/60 bg-background/55 hover:-translate-y-0.5 hover:border-primary/45"
                  }`}
                  onClick={() => setSelectedAnswer(index)}
                  disabled={isLoading || feedback !== null}
                >
                  <span className="mr-2 inline-flex h-6 w-6 items-center justify-center rounded-md border border-current/35 text-xs font-semibold">
                    {String.fromCharCode(65 + index)}
                  </span>
                  <span className="font-mono">{option}</span>
                </Button>
              ))}
            </div>
          </div>
        )

      case "multiple_choice":
      default:
        return (
          <div className="space-y-2">
            {currentQuestion.content.options.map((option, index) => (
              <Button key={index}
                variant={selectedAnswer === index ? "default" : "outline"}
                className={`h-auto w-full justify-start whitespace-normal rounded-xl border text-left transition-all duration-200 ${
                  selectedAnswer === index
                    ? "border-primary/80 bg-primary text-primary-foreground"
                    : "border-border/60 bg-background/55 hover:-translate-y-0.5 hover:border-primary/45"
                }`}
                onClick={() => setSelectedAnswer(index)}
                disabled={isLoading || feedback !== null}
              >
                <span className="mr-2 inline-flex h-6 w-6 items-center justify-center rounded-md border border-current/35 text-xs font-semibold">
                  {String.fromCharCode(65 + index)}
                </span>
                <span>{option}</span>
              </Button>
            ))}
          </div>
        )
    }
  }

  return (
    <div className="h-full space-y-3 overflow-y-auto p-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Adaptive Quiz</h3>
        <div className="flex items-center gap-2">
          {timedMode && !feedback && (
            <Badge variant="outline" className={`text-[10px] ${timeRemaining <= 10 ? "border-red-500/50 text-red-500 animate-pulse" : "border-amber-500/50 text-amber-500"}`}>
              <Timer className="h-3 w-3 mr-1" />
              {timeRemaining}s
            </Badge>
          )}
          {typeInfo && (
            <Badge variant="outline" className={`text-[10px] ${typeInfo.color}`}>
              {typeInfo.label}
            </Badge>
          )}
          <Badge variant="secondary" className="border border-primary/25 bg-primary/10 text-primary">Level {currentLevel}</Badge>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="rounded-xl border border-border/60 bg-card/60 p-2.5">
          <div className="mb-1 flex items-center gap-1.5 text-muted-foreground">
            <CircleCheckBig className="h-3 w-3" /> Accuracy
          </div>
          <p className="text-base font-semibold text-foreground">{accuracy}%</p>
          <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-muted/70">
            <div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${accuracy}%` }} />
          </div>
        </div>
        <div className="rounded-xl border border-border/60 bg-card/60 p-2.5">
          <div className="mb-1 flex items-center gap-1.5 text-muted-foreground">
            <Gauge className="h-3 w-3" /> Learning Rate
          </div>
          <p className="text-base font-semibold text-foreground">{learningPercent}%</p>
          <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-muted/70">
            <div className="h-full rounded-full bg-accent transition-all duration-500" style={{ width: `${learningPercent}%` }} />
          </div>
        </div>
      </div>

      {/* Question */}
      {currentQuestion && (
        <div className="space-y-3 rounded-xl border border-border/60 bg-card/65 p-4">
          <div className="flex items-start gap-2">
            <HelpCircle className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
            <p className="text-sm font-medium leading-relaxed text-foreground">{currentQuestion.content.question}</p>
          </div>
          {renderQuestionContent()}
        </div>
      )}

      {/* Feedback */}
      {feedback && (
        <div className={`rounded-xl border p-3 ${
          feedback.isCorrect ? "border-emerald-500/30 bg-emerald-50 dark:bg-emerald-900/20" : "border-red-500/30 bg-red-50 dark:bg-red-900/20"
        }`}>
          <div className="flex items-center gap-2 mb-1">
            {feedback.isCorrect ? <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" /> : <XCircle className="h-4 w-4 text-red-600 dark:text-red-400" />}
            <p className={`text-xs font-semibold ${feedback.isCorrect ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}`}>
              {feedback.isCorrect ? "Correct!" : "Incorrect"}
            </p>
          </div>
          <p className="text-xs text-muted-foreground">{feedback.text}</p>
        </div>
      )}

      {/* Actions */}
      <div className="space-y-2">
        <Button className="w-full bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
          onClick={submitAnswer} disabled={!isAnswerSelected() || isLoading || feedback !== null}>
          {isLoading ? "Submitting..." : feedback !== null ? "Loading next question..." : "Submit Answer"}
        </Button>
        <Button variant="outline" className="w-full border-border/60 bg-background/50" onClick={() => finishQuiz(sessionId!)} disabled={isLoading}>
          End Quiz
        </Button>
      </div>

      <div className="text-center text-xs text-muted-foreground">
        Question {questionsAnswered + 1} of 5
      </div>
    </div>
  )
}
