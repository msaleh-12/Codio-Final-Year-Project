"use client"

import { useEffect, useState } from "react"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { api, getAccessToken } from "@/lib/api"
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip,
} from "recharts"
import {
  Play, BookOpen, CheckCircle2, Clock, TrendingUp, Search, Sparkles,
  ArrowRight, BarChart3, Flame, Target, Zap, Brain, Trophy, Rocket,
  Compass, Award, Bell, Settings, Users, Lightbulb, ChevronRight,
  Calendar, Medal, Star, X,
} from "lucide-react"
import type { PreloadedVideoMeta } from "./dashboard"

interface DashboardHomeProps {
  user: { email: string; name: string }
  onStartLearning: (url: string, title: string, videoMeta?: PreloadedVideoMeta) => void
  onNavigate: (section: "home" | "discover" | "my-learning" | "completed" | "admin") => void
}

interface RecentPlaylist {
  playlist_id: string
  playlist_url: string
  playlist_title: string
  total_videos: number
  completed_videos: number
  progress_percentage: number
  last_accessed: string
}

const ACHIEVEMENT_ICONS: Record<string, React.ReactNode> = {
  rocket: <Rocket className="h-5 w-5" />,
  play: <Play className="h-5 w-5" />,
  brain: <Brain className="h-5 w-5" />,
  trophy: <Trophy className="h-5 w-5" />,
  flame: <Flame className="h-5 w-5" />,
  compass: <Compass className="h-5 w-5" />,
  clock: <Clock className="h-5 w-5" />,
}

export default function DashboardHome({ user, onStartLearning, onNavigate }: DashboardHomeProps) {
  const [enhanced, setEnhanced] = useState<any>({})
  const [recentPlaylists, setRecentPlaylists] = useState<RecentPlaylist[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [heatmapData, setHeatmapData] = useState<any[]>([])
  const [leaderboard, setLeaderboard] = useState<any[]>([])
  const [recommendations, setRecommendations] = useState<any[]>([])
  const [notifications, setNotifications] = useState<any[]>([])
  const [showNotifications, setShowNotifications] = useState(false)
  const [showGoalEditor, setShowGoalEditor] = useState(false)
  const [goalMinutes, setGoalMinutes] = useState(120)
  const [goalVideos, setGoalVideos] = useState(5)
  const [goalQuizzes, setGoalQuizzes] = useState(3)

  useEffect(() => {
    const fetchDashboardData = async () => {
      if (!getAccessToken()) {
        setIsLoading(false)
        return
      }

      try {
        const [enhancedRes, playlistsRes] = await Promise.all([
          api.getEnhancedUserDashboard(user.email),
          api.getUserPlaylists(user.email),
        ])

        if (enhancedRes.success && enhancedRes.stats) {
          setEnhanced(enhancedRes.stats)
        }

        if (playlistsRes.success && playlistsRes.playlists) {
          const sorted = [...playlistsRes.playlists].sort((a: any, b: any) =>
            new Date(b.last_accessed).getTime() - new Date(a.last_accessed).getTime()
          )
          setRecentPlaylists(sorted.slice(0, 5))
        }

        // Fetch enhancement data in parallel (non-blocking)
        Promise.all([
          api.getActivityHeatmap(90).catch(() => ({ success: false })),
          api.getLeaderboard(5).catch(() => ({ success: false })),
          api.getRecommendations().catch(() => ({ success: false })),
          api.getNotifications(true).catch(() => ({ success: false })),
          api.getUserGoals().catch(() => ({ success: false })),
        ]).then(([heatmap, lb, recs, notifs, goals]) => {
          if (heatmap.success) setHeatmapData(heatmap.heatmap || [])
          if (lb.success) setLeaderboard(lb.leaderboard || [])
          if (recs.success) setRecommendations(recs.recommendations || [])
          if (notifs.success) setNotifications(notifs.notifications || [])
          if (goals.success && goals.goals) {
            setGoalMinutes(goals.goals.weekly_minutes_target || 120)
            setGoalVideos(goals.goals.weekly_videos_target || 5)
            setGoalQuizzes(goals.goals.weekly_quizzes_target || 3)
          }
        })
      } catch (error) {
        console.error("[DashboardHome] Error fetching data:", error)
      } finally {
        setIsLoading(false)
      }
    }

    fetchDashboardData()
  }, [user.email])

  const getGreeting = () => {
    const hour = new Date().getHours()
    if (hour < 12) return "Good Morning"
    if (hour < 17) return "Good Afternoon"
    return "Good Evening"
  }

  const fmt = (seconds: number): string => {
    if (!seconds) return "0m"
    if (seconds < 60) return `${Math.round(seconds)}s`
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`
    return `${(seconds / 3600).toFixed(1)}h`
  }

  const handleSaveGoals = async () => {
    try {
      await api.updateUserGoals({
        weekly_minutes_target: goalMinutes,
        weekly_videos_target: goalVideos,
        weekly_quizzes_target: goalQuizzes,
      })
      setShowGoalEditor(false)
    } catch (e) {
      console.error("Failed to save goals:", e)
    }
  }

  const handleMarkAllRead = async () => {
    try {
      await api.markAllNotificationsRead()
      setNotifications([])
    } catch (e) {
      console.error("Failed to mark notifications read:", e)
    }
  }

  const totalPlaylists = enhanced.total_playlists || 0
  const completedVideos = enhanced.completed_videos || 0
  const videosInProgress = enhanced.videos_in_progress || 0
  const watchTimeSec = enhanced.total_watch_time_seconds || 0
  const streak = enhanced.learning_streak || 0
  const quizSessions = enhanced.quiz_sessions || 0
  const quizAccuracy = enhanced.quiz_accuracy || 0
  const conceptsLearned = enhanced.concepts_learned || 0
  const weeklyActivity = enhanced.weekly_activity || []
  const weeklyGoal = enhanced.weekly_goal || { target_minutes: 120, current_minutes: 0, progress_pct: 0 }
  const achievements = enhanced.achievements || []
  const achievementsEarned = enhanced.achievements_earned || 0
  const achievementsTotal = enhanced.achievements_total || 0
  const skillProgress = enhanced.skill_progress || []

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-b-2 border-primary" />
          <p className="mt-4 text-sm text-muted-foreground">Loading your dashboard...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      {/* Welcome Banner with Notification Bell */}
      <section className="relative overflow-hidden rounded-2xl border border-border/50 bg-gradient-to-br from-primary/10 via-background to-accent/10 px-6 py-8 sm:px-10">
        <div className="absolute -left-16 -top-16 h-40 w-40 rounded-full bg-primary/20 blur-3xl" />
        <div className="absolute -right-24 bottom-0 h-48 w-48 rounded-full bg-accent/20 blur-3xl" />

        <div className="relative flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-primary" />
              <span className="text-xs font-semibold uppercase tracking-wider text-primary">
                {getGreeting()}
              </span>
            </div>
            <h2 className="text-3xl font-bold text-foreground sm:text-4xl">
              Welcome back, {user.name.split(" ")[0]}!
            </h2>
            <p className="mt-2 max-w-lg text-muted-foreground">
              {videosInProgress > 0
                ? `You have ${videosInProgress} video${videosInProgress > 1 ? "s" : ""} in progress. Keep up the momentum!`
                : totalPlaylists > 0
                ? `You've completed ${completedVideos} videos. Keep learning!`
                : "Ready to start learning? Search for a coding tutorial to begin."}
            </p>
          </div>

          <div className="flex items-center gap-3">
            {/* Notification Bell */}
            <div className="relative">
              <Button
                variant="outline"
                size="icon"
                className="relative border-border/60"
                onClick={() => setShowNotifications(!showNotifications)}
              >
                <Bell className="h-4 w-4" />
                {notifications.length > 0 && (
                  <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
                    {notifications.length > 9 ? "9+" : notifications.length}
                  </span>
                )}
              </Button>

              {/* Notification Dropdown */}
              {showNotifications && (
                <div className="absolute right-0 top-12 z-50 w-80 rounded-xl border border-border bg-card p-4 shadow-2xl">
                  <div className="mb-3 flex items-center justify-between">
                    <h4 className="text-sm font-semibold text-foreground">Notifications</h4>
                    {notifications.length > 0 && (
                      <Button variant="ghost" size="sm" className="text-xs text-muted-foreground" onClick={handleMarkAllRead}>
                        Mark all read
                      </Button>
                    )}
                  </div>
                  {notifications.length === 0 ? (
                    <p className="py-4 text-center text-xs text-muted-foreground">No new notifications</p>
                  ) : (
                    <div className="max-h-60 space-y-2 overflow-y-auto">
                      {notifications.slice(0, 5).map((n: any) => (
                        <div key={n.id} className="rounded-lg bg-muted/30 p-3">
                          <p className="text-xs font-semibold text-foreground">{n.title}</p>
                          <p className="mt-0.5 text-xs text-muted-foreground">{n.message}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <Button
              onClick={() => onNavigate("discover")}
              className="bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
            >
              <Search className="mr-2 h-4 w-4" />
              Discover Videos
            </Button>
            {videosInProgress > 0 && (
              <Button
                onClick={() => onNavigate("my-learning")}
                variant="outline"
                className="border-border/60"
              >
                <BookOpen className="mr-2 h-4 w-4" />
                Continue Learning
              </Button>
            )}
          </div>
        </div>
      </section>

      {/* AI Recommendations */}
      {recommendations.length > 0 && (
        <section>
          <div className="mb-4 flex items-center gap-2">
            <Lightbulb className="h-5 w-5 text-amber-400" />
            <h3 className="text-xl font-semibold text-foreground">Recommended for You</h3>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {recommendations.slice(0, 3).map((rec: any, i: number) => {
              const priorityColors: Record<string, string> = {
                high: "border-red-400/30 bg-red-400/5",
                medium: "border-amber-400/30 bg-amber-400/5",
                low: "border-blue-400/30 bg-blue-400/5",
              }
              const iconMap: Record<string, React.ReactNode> = {
                streak: <Flame className="h-5 w-5 text-orange-400" />,
                quiz: <Brain className="h-5 w-5 text-purple-400" />,
                review: <BookOpen className="h-5 w-5 text-blue-400" />,
                continue: <Play className="h-5 w-5 text-emerald-400" />,
                goal: <Target className="h-5 w-5 text-amber-400" />,
                tip: <Lightbulb className="h-5 w-5 text-yellow-400" />,
              }
              return (
                <Card key={i} className={`border p-4 ${priorityColors[rec.priority] || priorityColors.low}`}>
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5">{iconMap[rec.type] || <Star className="h-5 w-5 text-primary" />}</div>
                    <div>
                      <p className="text-sm font-semibold text-foreground">{rec.title}</p>
                      <p className="mt-1 text-xs text-muted-foreground">{rec.description}</p>
                    </div>
                  </div>
                </Card>
              )
            })}
          </div>
        </section>
      )}

      {/* KPI Stats Grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KPICard label="Videos Watched" value={completedVideos} icon={<Play className="h-5 w-5" />} color="blue" subtext={`${videosInProgress} in progress`} />
        <KPICard label="Watch Time" value={fmt(watchTimeSec)} icon={<Clock className="h-5 w-5" />} color="purple" subtext={`${weeklyGoal.current_minutes}m this week`} />
        <KPICard label="Learning Streak" value={`${streak} day${streak !== 1 ? "s" : ""}`} icon={<Flame className="h-5 w-5" />} color="orange" subtext={streak > 0 ? "Keep it going!" : "Start today!"} />
        <KPICard label="Quiz Accuracy" value={`${quizAccuracy}%`} icon={<Brain className="h-5 w-5" />} color="emerald" subtext={`${quizSessions} quiz${quizSessions !== 1 ? "zes" : ""} taken`} />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KPICard label="Courses Enrolled" value={totalPlaylists} icon={<BookOpen className="h-5 w-5" />} color="amber" subtext={`${completedVideos} videos done`} />
        <KPICard label="Concepts Learned" value={conceptsLearned} icon={<Compass className="h-5 w-5" />} color="cyan" subtext="From quizzes" />
        <KPICard label="Achievements" value={`${achievementsEarned}/${achievementsTotal}`} icon={<Award className="h-5 w-5" />} color="pink" subtext={achievementsEarned === achievementsTotal ? "All unlocked!" : `${achievementsTotal - achievementsEarned} remaining`} />
        <KPICard label="Weekly Goal" value={`${weeklyGoal.progress_pct}%`} icon={<Target className="h-5 w-5" />} color="green" subtext={`${weeklyGoal.current_minutes}m / ${weeklyGoal.target_minutes}m`} />
      </div>

      {/* Activity Heatmap + Weekly Chart + Goal */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* Activity Heatmap */}
        <Card className="border-border/60 bg-card/75 p-5 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Calendar className="h-4 w-4 text-muted-foreground" />
              <h3 className="font-semibold text-foreground">Activity Heatmap</h3>
            </div>
            <span className="text-xs text-muted-foreground">Last 90 days</span>
          </div>
          <ActivityHeatmap data={heatmapData} />
          <div className="mt-3 flex items-center justify-end gap-2 text-xs text-muted-foreground">
            <span>Less</span>
            {[0, 1, 2, 3, 4].map((level) => (
              <div
                key={level}
                className="h-3 w-3 rounded-sm"
                style={{
                  backgroundColor:
                    level === 0 ? "hsl(var(--muted)/0.3)" :
                    level === 1 ? "#166534" :
                    level === 2 ? "#16a34a" :
                    level === 3 ? "#22c55e" : "#4ade80",
                }}
              />
            ))}
            <span>More</span>
          </div>
        </Card>

        {/* Weekly Goal with Editor */}
        <Card className="border-border/60 bg-card/75 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="font-semibold text-foreground">Weekly Goal</h3>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setShowGoalEditor(!showGoalEditor)}>
              <Settings className="h-3.5 w-3.5 text-muted-foreground" />
            </Button>
          </div>

          {showGoalEditor ? (
            <div className="space-y-3">
              <div>
                <label className="text-xs text-muted-foreground">Minutes / week</label>
                <input
                  type="number"
                  value={goalMinutes}
                  onChange={(e) => setGoalMinutes(Number(e.target.value))}
                  className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-1.5 text-sm text-foreground"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Videos / week</label>
                <input
                  type="number"
                  value={goalVideos}
                  onChange={(e) => setGoalVideos(Number(e.target.value))}
                  className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-1.5 text-sm text-foreground"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Quizzes / week</label>
                <input
                  type="number"
                  value={goalQuizzes}
                  onChange={(e) => setGoalQuizzes(Number(e.target.value))}
                  className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-1.5 text-sm text-foreground"
                />
              </div>
              <div className="flex gap-2">
                <Button size="sm" className="flex-1" onClick={handleSaveGoals}>Save</Button>
                <Button size="sm" variant="outline" className="flex-1" onClick={() => setShowGoalEditor(false)}>Cancel</Button>
              </div>
            </div>
          ) : (
            <>
              <div className="flex flex-col items-center justify-center py-2">
                <div className="relative h-28 w-28">
                  <svg className="h-28 w-28 -rotate-90" viewBox="0 0 120 120">
                    <circle cx="60" cy="60" r="52" fill="none" stroke="hsl(var(--muted))" strokeWidth="10" opacity="0.3" />
                    <circle cx="60" cy="60" r="52" fill="none" stroke="#10b981" strokeWidth="10"
                      strokeDasharray={`${2 * Math.PI * 52}`}
                      strokeDashoffset={`${2 * Math.PI * 52 * (1 - weeklyGoal.progress_pct / 100)}`}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-2xl font-bold text-foreground">{weeklyGoal.progress_pct}%</span>
                    <span className="text-xs text-muted-foreground">of goal</span>
                  </div>
                </div>
                <p className="mt-3 text-sm text-muted-foreground">
                  {weeklyGoal.current_minutes}m of {weeklyGoal.target_minutes}m target
                </p>
              </div>

              <div className="mt-3 rounded-lg bg-orange-400/10 border border-orange-400/20 p-3">
                <div className="flex items-center gap-3">
                  <Flame className="h-6 w-6 text-orange-400" />
                  <div>
                    <p className="text-sm font-semibold text-foreground">{streak}-Day Streak</p>
                    <p className="text-xs text-muted-foreground">{streak > 0 ? "Keep learning daily!" : "Learn today to start a streak!"}</p>
                  </div>
                </div>
              </div>
            </>
          )}
        </Card>
      </div>

      {/* Weekly Activity Chart */}
      <Card className="border-border/60 bg-card/75 p-5">
        <h3 className="mb-4 font-semibold text-foreground">Weekly Activity</h3>
        <div className="h-[200px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={weeklyActivity}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
              <XAxis dataKey="day" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} />
              <YAxis tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} tickFormatter={(v) => `${v}m`} />
              <Tooltip
                contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, color: "hsl(var(--foreground))" }}
                formatter={(v: any) => [`${v} min`, "Learning"]}
              />
              <Bar dataKey="minutes" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      {/* Leaderboard + Achievements side by side */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Leaderboard */}
        <Card className="border-border/60 bg-card/75 p-5">
          <div className="mb-4 flex items-center gap-2">
            <Trophy className="h-5 w-5 text-amber-400" />
            <h3 className="font-semibold text-foreground">Leaderboard</h3>
          </div>
          {leaderboard.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">No leaderboard data yet</p>
          ) : (
            <div className="space-y-2">
              {leaderboard.map((entry: any, i: number) => {
                const medals = ["text-amber-400", "text-gray-400", "text-orange-600"]
                const isCurrentUser = entry.email === user.email
                return (
                  <div
                    key={entry.email}
                    className={`flex items-center gap-3 rounded-lg p-3 ${
                      isCurrentUser ? "bg-primary/10 border border-primary/20" : "bg-muted/20"
                    }`}
                  >
                    <div className={`flex h-8 w-8 items-center justify-center rounded-full ${
                      i < 3 ? "bg-amber-400/15" : "bg-muted/40"
                    }`}>
                      {i < 3 ? (
                        <Medal className={`h-4 w-4 ${medals[i]}`} />
                      ) : (
                        <span className="text-xs font-bold text-muted-foreground">#{entry.rank}</span>
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-sm font-semibold truncate ${isCurrentUser ? "text-primary" : "text-foreground"}`}>
                        {entry.name} {isCurrentUser && "(You)"}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {fmt(entry.total_watch_seconds)} watched | {entry.quiz_accuracy}% quiz accuracy
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs font-semibold text-foreground">{entry.completions}</p>
                      <p className="text-[10px] text-muted-foreground">completed</p>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </Card>

        {/* Achievements */}
        <Card className="border-border/60 bg-card/75 p-5">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Award className="h-5 w-5 text-pink-400" />
              <h3 className="font-semibold text-foreground">Achievements</h3>
            </div>
            <span className="text-xs text-muted-foreground">{achievementsEarned}/{achievementsTotal}</span>
          </div>
          <div className="space-y-2">
            {achievements.map((a: any) => (
              <div
                key={a.id}
                className={`flex items-center gap-3 rounded-lg p-3 transition-all ${
                  a.earned ? "bg-primary/5" : "bg-muted/20 opacity-60"
                }`}
              >
                <div className={`rounded-lg p-2 ${a.earned ? "bg-primary/15 text-primary" : "bg-muted/40 text-muted-foreground"}`}>
                  {ACHIEVEMENT_ICONS[a.icon] || <Award className="h-5 w-5" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-semibold ${a.earned ? "text-foreground" : "text-muted-foreground"}`}>{a.title}</p>
                  <p className="text-xs text-muted-foreground truncate">{a.description}</p>
                </div>
                {a.earned && <CheckCircle2 className="h-4 w-4 flex-shrink-0 text-primary" />}
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Skill Progress */}
      {skillProgress.length > 0 && (
        <section>
          <h3 className="mb-4 text-xl font-semibold text-foreground">Skill Progress</h3>
          <Card className="border-border/60 bg-card/75 p-5">
            <div className="space-y-4">
              {skillProgress.map((skill: any, i: number) => (
                <div key={i} className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-foreground line-clamp-1">{skill.name}</p>
                    <span className="text-xs font-semibold text-primary">{skill.progress}%</span>
                  </div>
                  <div className="h-2.5 overflow-hidden rounded-full bg-muted/40">
                    <div
                      className={`h-full rounded-full transition-all ${
                        skill.progress >= 100
                          ? "bg-gradient-to-r from-emerald-400 to-emerald-500"
                          : "bg-gradient-to-r from-primary to-primary/70"
                      }`}
                      style={{ width: `${Math.min(skill.progress, 100)}%` }}
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">{skill.completed} / {skill.total} videos completed</p>
                </div>
              ))}
            </div>
          </Card>
        </section>
      )}

      {/* Quick Actions */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card
          className="group cursor-pointer border-border/60 bg-card/75 p-5 transition-all hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5"
          onClick={() => onNavigate("discover")}
        >
          <div className="flex items-center gap-4">
            <div className="rounded-xl bg-primary/15 p-3">
              <Zap className="h-6 w-6 text-primary" />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold text-foreground group-hover:text-primary">Start New Course</h3>
              <p className="text-xs text-muted-foreground">Search YouTube for tutorials</p>
            </div>
            <ArrowRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-1 group-hover:text-primary" />
          </div>
        </Card>

        <Card
          className="group cursor-pointer border-border/60 bg-card/75 p-5 transition-all hover:border-amber-400/40 hover:shadow-lg hover:shadow-amber-400/5"
          onClick={() => onNavigate("my-learning")}
        >
          <div className="flex items-center gap-4">
            <div className="rounded-xl bg-amber-400/15 p-3">
              <Target className="h-6 w-6 text-amber-400" />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold text-foreground group-hover:text-amber-400">Resume Learning</h3>
              <p className="text-xs text-muted-foreground">{videosInProgress} videos in progress</p>
            </div>
            <ArrowRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-1 group-hover:text-amber-400" />
          </div>
        </Card>

        <Card
          className="group cursor-pointer border-border/60 bg-card/75 p-5 transition-all hover:border-emerald-400/40 hover:shadow-lg hover:shadow-emerald-400/5"
          onClick={() => onNavigate("completed")}
        >
          <div className="flex items-center gap-4">
            <div className="rounded-xl bg-emerald-400/15 p-3">
              <BarChart3 className="h-6 w-6 text-emerald-400" />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold text-foreground group-hover:text-emerald-400">View Progress</h3>
              <p className="text-xs text-muted-foreground">{completedVideos} videos completed</p>
            </div>
            <ArrowRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-1 group-hover:text-emerald-400" />
          </div>
        </Card>
      </div>

      {/* Continue Learning */}
      {recentPlaylists.length > 0 ? (
        <section>
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-xl font-semibold text-foreground">Continue Learning</h3>
            <Button
              variant="ghost"
              size="sm"
              className="text-muted-foreground hover:text-foreground"
              onClick={() => onNavigate("my-learning")}
            >
              View All
              <ArrowRight className="ml-1 h-4 w-4" />
            </Button>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {recentPlaylists.slice(0, 3).map((playlist) => (
              <Card
                key={playlist.playlist_id}
                className="group cursor-pointer border-border/60 bg-card/75 p-5 transition-all hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5"
                onClick={() => onStartLearning(playlist.playlist_url, playlist.playlist_title)}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between">
                    <h4 className="line-clamp-2 flex-1 text-sm font-semibold text-foreground transition-colors group-hover:text-primary">
                      {playlist.playlist_title}
                    </h4>
                    <Play className="ml-2 h-4 w-4 flex-shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">
                        {playlist.completed_videos} / {playlist.total_videos} videos
                      </span>
                      <span className="font-medium text-primary">
                        {playlist.progress_percentage.toFixed(0)}%
                      </span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-muted/60">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-primary to-primary/70 transition-all"
                        style={{ width: `${Math.min(playlist.progress_percentage, 100)}%` }}
                      />
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground">
                    Last accessed: {new Date(playlist.last_accessed).toLocaleDateString()}
                  </p>
                </div>
              </Card>
            ))}
          </div>
        </section>
      ) : (
        <section className="rounded-2xl border border-dashed border-border/60 px-6 py-12 text-center">
          <Search className="mx-auto h-12 w-12 text-muted-foreground/40" />
          <h3 className="mt-4 text-lg font-semibold text-foreground">No courses yet</h3>
          <p className="mt-2 text-sm text-muted-foreground">
            Search for a coding tutorial to start your learning journey
          </p>
          <Button
            onClick={() => onNavigate("discover")}
            className="mt-6 bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
          >
            <Search className="mr-2 h-4 w-4" />
            Discover Videos
          </Button>
        </section>
      )}

      {/* Learning Tips */}
      <section>
        <h3 className="mb-4 text-xl font-semibold text-foreground">Learning Tips</h3>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Card className="border-border/60 bg-card/75 p-5">
            <div className="flex items-start gap-3">
              <div className="rounded-lg bg-blue-400/15 p-2">
                <Flame className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-foreground">Pause & Practice</h4>
                <p className="mt-1 text-xs text-muted-foreground">
                  Pause the video when you see code. The editor will extract it for you to practice.
                </p>
              </div>
            </div>
          </Card>

          <Card className="border-border/60 bg-card/75 p-5">
            <div className="flex items-start gap-3">
              <div className="rounded-lg bg-emerald-400/15 p-2">
                <TrendingUp className="h-5 w-5 text-emerald-400" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-foreground">Search Transcripts</h4>
                <p className="mt-1 text-xs text-muted-foreground">
                  Use the Search tab to find specific topics in the video and jump to exact timestamps.
                </p>
              </div>
            </div>
          </Card>

          <Card className="border-border/60 bg-card/75 p-5">
            <div className="flex items-start gap-3">
              <div className="rounded-lg bg-purple-400/15 p-2">
                <Target className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-foreground">Take Quizzes</h4>
                <p className="mt-1 text-xs text-muted-foreground">
                  Test your understanding with AI-generated quizzes based on the video content.
                </p>
              </div>
            </div>
          </Card>
        </div>
      </section>
    </div>
  )
}

/* ==================== Activity Heatmap Component ==================== */

function ActivityHeatmap({ data }: { data: any[] }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex h-[120px] items-center justify-center text-sm text-muted-foreground">
        No activity data yet. Start watching videos to build your heatmap!
      </div>
    )
  }

  // Group by week (7 columns per row)
  const weeks: any[][] = []
  let currentWeek: any[] = []
  
  // Pad the start to align with day of week
  const firstDate = new Date(data[0]?.date || new Date())
  const startPad = firstDate.getDay() // 0=Sun
  for (let i = 0; i < startPad; i++) {
    currentWeek.push(null)
  }

  data.forEach((d) => {
    currentWeek.push(d)
    if (currentWeek.length === 7) {
      weeks.push(currentWeek)
      currentWeek = []
    }
  })
  if (currentWeek.length > 0) {
    weeks.push(currentWeek)
  }

  const getColor = (minutes: number) => {
    if (minutes === 0) return "hsl(var(--muted)/0.3)"
    if (minutes < 5) return "#166534"
    if (minutes < 15) return "#16a34a"
    if (minutes < 30) return "#22c55e"
    return "#4ade80"
  }

  return (
    <div className="flex gap-[3px] overflow-x-auto pb-1">
      {weeks.map((week, wi) => (
        <div key={wi} className="flex flex-col gap-[3px]">
          {week.map((day, di) => (
            <div
              key={di}
              className="h-3 w-3 rounded-sm transition-colors"
              style={{ backgroundColor: day ? getColor(day.minutes) : "transparent" }}
              title={day ? `${day.date}: ${day.minutes}m watched` : ""}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

/* ==================== KPI Card Component ==================== */

function KPICard({ label, value, icon, color, subtext }: { label: string; value: string | number; icon: React.ReactNode; color: string; subtext?: string }) {
  const colorMap: Record<string, { text: string; bg: string }> = {
    blue: { text: "text-blue-400", bg: "bg-blue-400/10 border-blue-400/20" },
    emerald: { text: "text-emerald-400", bg: "bg-emerald-400/10 border-emerald-400/20" },
    amber: { text: "text-amber-400", bg: "bg-amber-400/10 border-amber-400/20" },
    purple: { text: "text-purple-400", bg: "bg-purple-400/10 border-purple-400/20" },
    cyan: { text: "text-cyan-400", bg: "bg-cyan-400/10 border-cyan-400/20" },
    pink: { text: "text-pink-400", bg: "bg-pink-400/10 border-pink-400/20" },
    green: { text: "text-green-400", bg: "bg-green-400/10 border-green-400/20" },
    orange: { text: "text-orange-400", bg: "bg-orange-400/10 border-orange-400/20" },
    red: { text: "text-red-400", bg: "bg-red-400/10 border-red-400/20" },
  }
  const c = colorMap[color] || colorMap.blue
  return (
    <Card className={`border ${c.bg} p-5`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
          <p className={`mt-1 text-2xl font-bold ${c.text}`}>{value}</p>
          {subtext && <p className="mt-1 text-xs text-muted-foreground">{subtext}</p>}
        </div>
        <div className={`rounded-xl p-3 ${c.bg}`}>
          <span className={c.text}>{icon}</span>
        </div>
      </div>
    </Card>
  )
}
