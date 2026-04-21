"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import {
  User, Mail, Calendar, Trophy, BookOpen, Clock, Target, Save,
  Shield, Palette, Bell, Keyboard, ChevronRight, Award,
} from "lucide-react"
import { api } from "@/lib/api"
import { toast } from "sonner"

interface ProfilePageProps {
  user: { email: string; name: string }
}

export default function ProfilePage({ user }: ProfilePageProps) {
  const [stats, setStats] = useState<any>(null)
  const [preferences, setPreferences] = useState<any>({})
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [activeTab, setActiveTab] = useState<"overview" | "preferences" | "shortcuts">("overview")

  useEffect(() => {
    loadProfile()
  }, [])

  const loadProfile = async () => {
    setIsLoading(true)
    try {
      const [statsRes, prefsRes] = await Promise.allSettled([
        api.getEnhancedUserDashboard(user.email),
        api.getUserPreferences(),
      ])
      if (statsRes.status === "fulfilled" && statsRes.value.success) setStats(statsRes.value)
      if (prefsRes.status === "fulfilled" && prefsRes.value.success) setPreferences(prefsRes.value.preferences || {})
    } catch { /* ignore */ }
    setIsLoading(false)
  }

  const handleSavePreferences = async () => {
    setIsSaving(true)
    try {
      await api.updateUserPreferences(preferences)
      toast.success("Preferences saved!")
    } catch {
      toast.error("Failed to save preferences")
    }
    setIsSaving(false)
  }

  const getInitials = (name: string) => {
    return name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2)
  }

  const shortcuts = [
    { key: "Space", action: "Play / Pause video" },
    { key: "Arrow Left", action: "Seek back 10 seconds" },
    { key: "Arrow Right", action: "Seek forward 10 seconds" },
    { key: "Arrow Up/Down", action: "Volume up/down" },
    { key: "M", action: "Mute / Unmute" },
    { key: "F", action: "Toggle fullscreen" },
    { key: "B", action: "Add bookmark at current time" },
    { key: "Shift + >", action: "Increase playback speed" },
    { key: "Shift + <", action: "Decrease playback speed" },
    { key: "Ctrl + Enter", action: "Run code in compiler" },
    { key: "Ctrl + Space", action: "Trigger code autocomplete" },
    { key: "Ctrl + S", action: "Save code" },
    { key: "Ctrl + Z", action: "Undo in code editor" },
  ]

  if (isLoading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-32 rounded-2xl bg-muted/30" />
        <div className="grid grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 rounded-xl bg-muted/30" />)}
        </div>
        <div className="h-64 rounded-2xl bg-muted/30" />
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Profile Header */}
      <Card className="border-border/40 bg-gradient-to-r from-primary/5 via-card to-card overflow-hidden">
        <div className="p-6 flex items-center gap-5">
          <div className="h-20 w-20 rounded-2xl bg-primary/15 border border-primary/30 flex items-center justify-center flex-shrink-0">
            <span className="text-2xl font-bold text-primary">{getInitials(user.name)}</span>
          </div>
          <div className="flex-1 min-w-0">
            <h1 className="text-2xl font-bold text-foreground">{user.name}</h1>
            <div className="flex items-center gap-2 mt-1 text-sm text-muted-foreground">
              <Mail className="w-3.5 h-3.5" /> {user.email}
            </div>
            <div className="flex items-center gap-4 mt-3">
              {stats?.learning_streak > 0 && (
                <div className="flex items-center gap-1.5 text-xs">
                  <Trophy className="w-3.5 h-3.5 text-amber-500" />
                  <span className="text-foreground font-medium">{stats.learning_streak} day streak</span>
                </div>
              )}
              {stats?.total_watch_time && (
                <div className="flex items-center gap-1.5 text-xs">
                  <Clock className="w-3.5 h-3.5 text-cyan-500" />
                  <span className="text-foreground font-medium">{stats.total_watch_time}</span>
                </div>
              )}
              <div className="flex items-center gap-1.5 text-xs">
                <Shield className="w-3.5 h-3.5 text-emerald-500" />
                <span className="text-foreground font-medium">
                  {user.email === "admin@gmail.com" ? "Admin" : "Learner"}
                </span>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Courses", value: stats?.total_playlists || 0, icon: BookOpen, color: "text-blue-500" },
          { label: "Completed", value: stats?.completed_videos || 0, icon: Award, color: "text-emerald-500" },
          { label: "Quizzes", value: stats?.quiz_sessions || 0, icon: Target, color: "text-purple-500" },
          { label: "Streak", value: `${stats?.learning_streak || 0}d`, icon: Trophy, color: "text-amber-500" },
        ].map((stat, i) => (
          <Card key={i} className="border-border/40 p-4">
            <div className="flex items-center gap-2 mb-2">
              <stat.icon className={`w-4 h-4 ${stat.color}`} />
              <span className="text-xs text-muted-foreground">{stat.label}</span>
            </div>
            <p className="text-2xl font-bold text-foreground">{stat.value}</p>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border/40">
        {[
          { id: "overview" as const, label: "Overview", icon: User },
          { id: "preferences" as const, label: "Preferences", icon: Palette },
          { id: "shortcuts" as const, label: "Keyboard Shortcuts", icon: Keyboard },
        ].map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}>
            <tab.icon className="w-4 h-4" /> {tab.label}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === "overview" && (
        <div className="space-y-4">
          <Card className="border-border/40 p-5">
            <h3 className="text-sm font-semibold text-foreground mb-4">Account Information</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b border-border/20">
                <span className="text-sm text-muted-foreground">Full Name</span>
                <span className="text-sm font-medium text-foreground">{user.name}</span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-border/20">
                <span className="text-sm text-muted-foreground">Email</span>
                <span className="text-sm font-medium text-foreground">{user.email}</span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-border/20">
                <span className="text-sm text-muted-foreground">Role</span>
                <span className="text-sm font-medium text-foreground">{user.email === "admin@gmail.com" ? "Administrator" : "Learner"}</span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-sm text-muted-foreground">Member Since</span>
                <span className="text-sm font-medium text-foreground">{stats?.joined || "Recently"}</span>
              </div>
            </div>
          </Card>

          {/* Achievements */}
          {stats?.achievements && stats.achievements.length > 0 && (
            <Card className="border-border/40 p-5">
              <h3 className="text-sm font-semibold text-foreground mb-4">Achievements</h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {stats.achievements.map((ach: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 p-3 rounded-xl bg-muted/20 border border-border/20">
                    <span className="text-lg">{ach.icon || "🏆"}</span>
                    <div>
                      <p className="text-xs font-medium text-foreground">{ach.title}</p>
                      <p className="text-[10px] text-muted-foreground">{ach.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Skill Progress */}
          {stats?.skill_progress && stats.skill_progress.length > 0 && (
            <Card className="border-border/40 p-5">
              <h3 className="text-sm font-semibold text-foreground mb-4">Skill Progress</h3>
              <div className="space-y-3">
                {stats.skill_progress.map((skill: any, i: number) => (
                  <div key={i}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-foreground">{skill.name}</span>
                      <span className="text-xs text-muted-foreground">{skill.level}</span>
                    </div>
                    <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                      <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${skill.progress || 0}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      )}

      {/* Preferences Tab */}
      {activeTab === "preferences" && (
        <div className="space-y-4">
          <Card className="border-border/40 p-5">
            <h3 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
              <Bell className="w-4 h-4" /> Notification Settings
            </h3>
            <div className="space-y-3">
              {[
                { key: "notify_achievements", label: "Achievement notifications" },
                { key: "notify_streak", label: "Streak reminders" },
                { key: "notify_recommendations", label: "Study recommendations" },
              ].map(item => (
                <label key={item.key} className="flex items-center justify-between py-2 cursor-pointer">
                  <span className="text-sm text-foreground">{item.label}</span>
                  <button
                    onClick={() => setPreferences({ ...preferences, [item.key]: !preferences[item.key] })}
                    className={`relative w-10 h-5 rounded-full transition-colors ${preferences[item.key] !== false ? 'bg-primary' : 'bg-muted'}`}
                  >
                    <span className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${preferences[item.key] !== false ? 'translate-x-5' : ''}`} />
                  </button>
                </label>
              ))}
            </div>
          </Card>

          <Card className="border-border/40 p-5">
            <h3 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
              <Palette className="w-4 h-4" /> Learning Preferences
            </h3>
            <div className="space-y-3">
              <div>
                <label className="text-sm text-muted-foreground mb-1 block">Default Playback Speed</label>
                <select value={preferences.default_speed || "1"}
                  onChange={(e) => setPreferences({ ...preferences, default_speed: e.target.value })}
                  className="w-full h-9 rounded-lg border border-border bg-background px-3 text-sm">
                  <option value="0.75">0.75x</option>
                  <option value="1">1x (Normal)</option>
                  <option value="1.25">1.25x</option>
                  <option value="1.5">1.5x</option>
                  <option value="2">2x</option>
                </select>
              </div>
              <div>
                <label className="text-sm text-muted-foreground mb-1 block">Compiler Font Size</label>
                <select value={preferences.font_size || "14"}
                  onChange={(e) => setPreferences({ ...preferences, font_size: e.target.value })}
                  className="w-full h-9 rounded-lg border border-border bg-background px-3 text-sm">
                  <option value="12">12px</option>
                  <option value="14">14px (Default)</option>
                  <option value="16">16px</option>
                  <option value="18">18px</option>
                  <option value="20">20px</option>
                </select>
              </div>
              <div>
                <label className="text-sm text-muted-foreground mb-1 block">Default Transcript Language</label>
                <select value={preferences.transcript_lang || "original"}
                  onChange={(e) => setPreferences({ ...preferences, transcript_lang: e.target.value })}
                  className="w-full h-9 rounded-lg border border-border bg-background px-3 text-sm">
                  <option value="original">Original Language</option>
                  <option value="en">English (Auto-translated)</option>
                </select>
              </div>
            </div>
          </Card>

          <Button onClick={handleSavePreferences} disabled={isSaving} className="w-full">
            <Save className="w-4 h-4 mr-2" /> {isSaving ? "Saving..." : "Save Preferences"}
          </Button>
        </div>
      )}

      {/* Keyboard Shortcuts Tab */}
      {activeTab === "shortcuts" && (
        <Card className="border-border/40 p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Keyboard Shortcuts</h3>
          <div className="space-y-1">
            {shortcuts.map((s, i) => (
              <div key={i} className="flex items-center justify-between py-2 border-b border-border/10 last:border-0">
                <span className="text-sm text-foreground">{s.action}</span>
                <kbd className="px-2 py-1 rounded bg-muted/40 border border-border/40 text-xs font-mono text-muted-foreground">{s.key}</kbd>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
