"use client"

import { useEffect, useState, useCallback, useMemo } from "react"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { api, getAccessToken } from "@/lib/api"
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip, AreaChart, Area,
} from "recharts"
import {
  Users, BookOpen, Play, Server, RefreshCw, ShieldCheck, Activity,
  Database, Clock, TrendingUp, UserCheck, BarChart3, Trophy, Brain,
  DollarSign, CreditCard, Zap, Target, ArrowUpRight, ArrowDownRight,
  Layers, Eye, Award, ChevronDown, ChevronUp, Search,
  Trash2, CheckCircle, XCircle, Download, LayoutDashboard,
  GraduationCap, UserPlus, FileText, AlertTriangle, Edit,
  X, ChevronLeft, ChevronRight, Filter, SortAsc, SortDesc,
  Plus, Mail, Shield, UserCog, CalendarDays, Hash,
  ArrowUp, ArrowDown, Minus, Copy, ExternalLink,
} from "lucide-react"

interface AdminPanelProps {
  userEmail: string
  activeTab?: string
}

type TabId = "overview" | "users" | "billing" | "certificates" | "courses" | "analytics"
type SortField = "name" | "total_playlists" | "completed_videos" | "total_watch_time" | "quiz_sessions" | "created_at" | "last_login"
type SortDir = "asc" | "desc"

export default function AdminPanel({ userEmail, activeTab: externalTab }: AdminPanelProps) {
  // ── Core State ──
  const [stats, setStats] = useState<any>({})
  const [users, setUsers] = useState<any[]>([])
  const [subscriptions, setSubscriptions] = useState<any[]>([])
  const [billing, setBilling] = useState<any>(null)
  const [certificates, setCertificates] = useState<any[]>([])
  const [courses, setCourses] = useState<any[]>([])
  const [analytics, setAnalytics] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [internalTab, setInternalTab] = useState<TabId>("overview")
  const activeTab: TabId = (externalTab as TabId) || internalTab
  const setActiveTab = (tab: TabId) => setInternalTab(tab)
  const [actionMsg, setActionMsg] = useState("")

  // ── Enhanced State ──
  const [searchQuery, setSearchQuery] = useState("")
  const [sortField, setSortField] = useState<SortField>("created_at")
  const [sortDir, setSortDir] = useState<SortDir>("desc")
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [roleFilter, setRoleFilter] = useState<string>("all")
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [showFilters, setShowFilters] = useState(false)

  // ── User Detail Drawer ──
  const [selectedUser, setSelectedUser] = useState<any>(null)
  const [selectedUserStats, setSelectedUserStats] = useState<any>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [drawerLoading, setDrawerLoading] = useState(false)

  // ── Issue Certificate Dialog ──
  const [showIssueCertDialog, setShowIssueCertDialog] = useState(false)
  const [certUserEmail, setCertUserEmail] = useState("")
  const [certCourseTitle, setCertCourseTitle] = useState("")
  const [certPlaylistId, setCertPlaylistId] = useState("")
  const [issuingCert, setIssuingCert] = useState(false)

  // ── Period Selector ──
  const [period, setPeriod] = useState<"7d" | "30d" | "90d" | "all">("all")

  const showAction = (msg: string) => {
    setActionMsg(msg)
    setTimeout(() => setActionMsg(""), 4000)
  }

  // ── Data Fetching ──
  const fetchAdminData = async () => {
    if (!getAccessToken()) {
      setIsLoading(false)
      setError("No authentication token. Please log out and log back in.")
      return
    }
    setIsLoading(true)
    setError(null)
    try {
      const [enhancedRes, usersRes] = await Promise.all([
        api.getEnhancedAdminStats(),
        api.getAdminUsers(),
      ])
      if (enhancedRes.success && enhancedRes.stats) setStats(enhancedRes.stats)
      if (usersRes.success && usersRes.users) setUsers(usersRes.users)
    } catch (err: any) {
      console.error("[AdminPanel] Error:", err)
      setError(err?.message || "Failed to load admin data")
    } finally {
      setIsLoading(false)
    }
  }

  const loadTabData = useCallback(async (tab: TabId) => {
    try {
      if (tab === "billing" && !billing) {
        const [subsRes, billRes] = await Promise.all([
          api.getSubscriptions(),
          api.getBillingOverview(),
        ])
        if (subsRes?.success) setSubscriptions(subsRes.subscriptions || [])
        if (billRes?.success) setBilling(billRes.billing)
      }
      if (tab === "certificates" && certificates.length === 0) {
        const res = await api.getCertificates()
        if (res?.success) setCertificates(res.certificates || [])
      }
      if (tab === "courses" && courses.length === 0) {
        const res = await api.getAdminCourses()
        if (res?.success) setCourses(res.courses || [])
      }
      if (tab === "analytics" && !analytics) {
        const res = await api.getEngagementAnalytics()
        if (res?.success) setAnalytics(res.analytics)
      }
    } catch (e: any) {
      console.error("Tab data load error:", e)
    }
  }, [billing, certificates.length, courses.length, analytics])

  useEffect(() => { fetchAdminData() }, [userEmail])
  useEffect(() => { loadTabData(activeTab) }, [activeTab, loadTabData, externalTab])

  // ── Action Handlers ──
  const handleToggleUserStatus = async (email: string, currentStatus: string) => {
    const newStatus = currentStatus === "active" ? "suspended" : "active"
    try {
      await api.toggleUserStatus(email, newStatus)
      setUsers(prev => prev.map(u => u.email === email ? { ...u, status: newStatus } : u))
      showAction(`User ${email} ${newStatus === "active" ? "activated" : "suspended"}`)
    } catch (e: any) { showAction(`Error: ${e.message}`) }
  }

  const handleDeleteUser = async (email: string) => {
    if (!confirm(`Are you sure you want to delete ${email}? This cannot be undone.`)) return
    try {
      await api.deleteUser(email)
      setUsers(prev => prev.filter(u => u.email !== email))
      showAction(`User ${email} deleted`)
    } catch (e: any) { showAction(`Error: ${e.message}`) }
  }

  const handleUpdateRole = async (email: string, role: string) => {
    try {
      await api.updateUserRole(email, role)
      setUsers(prev => prev.map(u => u.email === email ? { ...u, role } : u))
      showAction(`Role updated to ${role} for ${email}`)
    } catch (e: any) { showAction(`Error: ${e.message}`) }
  }

  const handleUpdateSubscription = async (email: string, plan: string) => {
    try {
      await api.updateSubscription(email, plan)
      const [subsRes, billRes] = await Promise.all([api.getSubscriptions(), api.getBillingOverview()])
      if (subsRes?.success) setSubscriptions(subsRes.subscriptions || [])
      if (billRes?.success) setBilling(billRes.billing)
      showAction(`Subscription updated for ${email}`)
    } catch (e: any) { showAction(`Error: ${e.message}`) }
  }

  const handleRevokeCertificate = async (certId: string) => {
    try {
      await api.revokeCertificate(certId)
      setCertificates(prev => prev.map(c => c.cert_id === certId ? { ...c, status: "revoked" } : c))
      showAction(`Certificate ${certId} revoked`)
    } catch (e: any) { showAction(`Error: ${e.message}`) }
  }

  const handleIssueCertificate = async () => {
    if (!certUserEmail || !certCourseTitle) return
    setIssuingCert(true)
    try {
      const res = await api.issueCertificate(certUserEmail, certCourseTitle, certPlaylistId || undefined)
      if (res?.success) {
        setCertificates(prev => [...prev, res.certificate])
        showAction(`Certificate issued to ${certUserEmail}`)
        setShowIssueCertDialog(false)
        setCertUserEmail("")
        setCertCourseTitle("")
        setCertPlaylistId("")
      }
    } catch (e: any) { showAction(`Error: ${e.message}`) }
    finally { setIssuingCert(false) }
  }

  const handleToggleCourse = async (playlistId: string, currentStatus: string) => {
    const newStatus = currentStatus === "active" ? "archived" : "active"
    try {
      await api.toggleCourseStatus(playlistId, newStatus)
      setCourses(prev => prev.map(c => c.playlist_id === playlistId ? { ...c, status: newStatus } : c))
      showAction(`Course ${newStatus === "active" ? "activated" : "archived"}`)
    } catch (e: any) { showAction(`Error: ${e.message}`) }
  }

  const handleViewUser = async (user: any) => {
    setSelectedUser(user)
    setDrawerOpen(true)
    setDrawerLoading(true)
    try {
      const res = await api.getAdminUserStats(user.email)
      if (res?.success) setSelectedUserStats(res.stats)
    } catch (e: any) {
      console.error("Error loading user stats:", e)
    } finally {
      setDrawerLoading(false)
    }
  }

  const handleExport = async () => {
    try {
      const res = await api.exportAnalytics()
      if (res?.success) {
        const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" })
        const url = URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = `codio_analytics_${new Date().toISOString().split("T")[0]}.json`
        a.click()
        showAction("Analytics exported successfully")
      }
    } catch (e: any) { showAction(`Export failed: ${e.message}`) }
  }

  const handleExportCSV = (data: any[], filename: string) => {
    if (!data || data.length === 0) return
    const headers = Object.keys(data[0])
    const csv = [
      headers.join(","),
      ...data.map(row => headers.map(h => {
        const val = row[h]
        return typeof val === "string" && val.includes(",") ? `"${val}"` : val ?? ""
      }).join(","))
    ].join("\n")
    const blob = new Blob([csv], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `${filename}_${new Date().toISOString().split("T")[0]}.csv`
    a.click()
    showAction(`${filename} exported as CSV`)
  }

  // ── Utilities ──
  const fmt = (seconds: number): string => {
    if (!seconds) return "0s"
    if (seconds < 60) return `${Math.round(seconds)}s`
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`
    return `${(seconds / 3600).toFixed(1)}h`
  }
  const fmtDate = (d: string) => d ? new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }) : "N/A"
  const fmtCurrency = (n: number) => `$${(n || 0).toFixed(2)}`
  const COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#8b5cf6", "#ef4444", "#06b6d4"]

  // ── Sorting & Filtering ──
  const filteredAndSortedUsers = useMemo(() => {
    let result = [...users]

    // Search filter
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      result = result.filter(u =>
        u.name?.toLowerCase().includes(q) ||
        u.email?.toLowerCase().includes(q)
      )
    }

    // Status filter
    if (statusFilter !== "all") {
      result = result.filter(u => (u.status || "active") === statusFilter)
    }

    // Role filter
    if (roleFilter !== "all") {
      result = result.filter(u => (u.role || "learner") === roleFilter)
    }

    // Sort
    result.sort((a, b) => {
      let aVal = a[sortField] ?? ""
      let bVal = b[sortField] ?? ""
      if (typeof aVal === "string") aVal = aVal.toLowerCase()
      if (typeof bVal === "string") bVal = bVal.toLowerCase()
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1
      return 0
    })

    return result
  }, [users, searchQuery, statusFilter, roleFilter, sortField, sortDir])

  // Pagination
  const totalPages = Math.ceil(filteredAndSortedUsers.length / pageSize)
  const paginatedUsers = filteredAndSortedUsers.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  useEffect(() => { setCurrentPage(1) }, [searchQuery, statusFilter, roleFilter, pageSize])

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(prev => prev === "asc" ? "desc" : "asc")
    } else {
      setSortField(field)
      setSortDir("asc")
    }
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <SortAsc className="h-3 w-3 opacity-30" />
    return sortDir === "asc" ? <SortAsc className="h-3 w-3 text-primary" /> : <SortDesc className="h-3 w-3 text-primary" />
  }

  // ── Trend Calculation ──
  const getTrend = (current: number, previous: number) => {
    if (!previous || previous === 0) return { pct: 0, dir: "flat" as const }
    const pct = Math.round(((current - previous) / previous) * 100)
    return { pct: Math.abs(pct), dir: pct > 0 ? "up" as const : pct < 0 ? "down" as const : "flat" as const }
  }

  // ── Activity Feed (simulated from user data) ──
  const activityFeed = useMemo(() => {
    const activities: { type: string; message: string; time: string; icon: React.ReactNode; color: string }[] = []
    users.forEach(u => {
      if (u.last_login) {
        activities.push({
          type: "login",
          message: `${u.name || u.email} logged in`,
          time: u.last_login,
          icon: <UserCheck className="h-3.5 w-3.5" />,
          color: "text-blue-400"
        })
      }
      if (u.created_at) {
        activities.push({
          type: "signup",
          message: `${u.name || u.email} signed up`,
          time: u.created_at,
          icon: <UserPlus className="h-3.5 w-3.5" />,
          color: "text-emerald-400"
        })
      }
    })
    return activities
      .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime())
      .slice(0, 8)
  }, [users])

  const tabs: { id: TabId; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: "overview", label: "Overview", icon: <LayoutDashboard className="h-4 w-4" /> },
    { id: "users", label: "User Management", icon: <Users className="h-4 w-4" />, count: users.length },
    { id: "billing", label: "Billing", icon: <CreditCard className="h-4 w-4" /> },
    { id: "certificates", label: "Certificates", icon: <Award className="h-4 w-4" /> },
    { id: "courses", label: "Courses", icon: <BookOpen className="h-4 w-4" /> },
    { id: "analytics", label: "Analytics", icon: <BarChart3 className="h-4 w-4" /> },
  ]

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-b-2 border-primary" />
          <p className="mt-4 text-sm text-muted-foreground">Loading admin console...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* ── Admin Header ── */}
      <div className="rounded-xl border border-border/60 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 p-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-primary/20 p-2.5">
              <ShieldCheck className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">Admin Console</h1>
              <p className="text-sm text-muted-foreground">Platform management, billing, certificates, and analytics</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {actionMsg && (
              <span className="animate-pulse rounded-full bg-primary/10 px-3 py-1 text-sm text-primary">
                {actionMsg}
              </span>
            )}
            {/* Period Selector */}
            <div className="hidden items-center gap-1 rounded-lg border border-border/60 bg-muted/30 p-0.5 sm:flex">
              {(["7d", "30d", "90d", "all"] as const).map(p => (
                <button
                  key={p}
                  onClick={() => setPeriod(p)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition-all ${
                    period === p ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {p === "all" ? "All Time" : p.toUpperCase()}
                </button>
              ))}
            </div>
            <Button variant="outline" size="sm" onClick={handleExport} className="border-border/60">
              <Download className="mr-2 h-4 w-4" /> Export
            </Button>
            <Button variant="default" size="sm" onClick={fetchAdminData}>
              <RefreshCw className="mr-2 h-4 w-4" /> Refresh
            </Button>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/25 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
      )}

      {/* ── Tab Navigation ── */}
      {!externalTab && <div className="flex gap-1 overflow-x-auto rounded-xl bg-muted/30 p-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 whitespace-nowrap rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${
              activeTab === tab.id
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
            }`}
          >
            {tab.icon}
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className={`rounded-full px-1.5 py-0.5 text-xs ${
                activeTab === tab.id
                  ? "bg-primary-foreground/20 text-primary-foreground"
                  : "bg-muted/60 text-muted-foreground"
              }`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>}

      {/* ══════════════════════ OVERVIEW TAB ══════════════════════ */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* KPI Cards with Trend Indicators */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <KPICardEnhanced label="Total Users" value={stats.total_users || 0} icon={<Users className="h-5 w-5" />} color="blue" subtext={`+${stats.new_users_week || 0} this week`} trend={getTrend(stats.total_users || 0, (stats.total_users || 0) - (stats.new_users_week || 0))} />
            <KPICardEnhanced label="Active Users (7d)" value={stats.active_users_7d || 0} icon={<Activity className="h-5 w-5" />} color="emerald" subtext={`${stats.active_users_30d || 0} in 30d`} trend={getTrend(stats.active_users_7d || 0, stats.active_users_30d ? Math.round(stats.active_users_30d / 4) : 0)} />
            <KPICardEnhanced label="Total Revenue" value={fmtCurrency(stats.billing?.total_revenue || 0)} icon={<DollarSign className="h-5 w-5" />} color="green" subtext={`ARPU ${fmtCurrency(stats.billing?.arpu || 0)}`} trend={{ pct: 12, dir: "up" }} />
            <KPICardEnhanced label="Completion Rate" value={`${stats.completion_rate || 0}%`} icon={<Target className="h-5 w-5" />} color="purple" subtext={`${stats.total_completions || 0} completions`} trend={{ pct: stats.completion_rate || 0 > 50 ? 5 : 0, dir: stats.completion_rate > 50 ? "up" : "flat" }} />
            <KPICardEnhanced label="Total Courses" value={stats.total_playlists || 0} icon={<BookOpen className="h-5 w-5" />} color="amber" subtext={`${stats.total_videos_watched || 0} videos watched`} trend={{ pct: 0, dir: "flat" }} />
            <KPICardEnhanced label="Quiz Sessions" value={stats.total_quiz_sessions || 0} icon={<Brain className="h-5 w-5" />} color="pink" subtext={`${stats.quiz_accuracy || 0}% accuracy`} trend={{ pct: 8, dir: "up" }} />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            {/* System Health */}
            <Card className="border-border/60 bg-card/75 p-5">
              <div className="mb-4 flex items-center gap-3">
                <div className="rounded-lg bg-blue-400/15 p-2"><Server className="h-5 w-5 text-blue-400" /></div>
                <h3 className="font-semibold text-foreground">Platform Health</h3>
              </div>
              <div className="space-y-3">
                <StatusRow label="Backend API" value="Online" status="ok" />
                <StatusRow label="Database" value="Connected" status="ok" />
                <StatusRow label="Video Processing" value="Operational" status="ok" />
                <StatusRow label="AI Services (Gemini)" value="Active" status="ok" />
                <StatusRow label="Total Watch Time" value={fmt(stats.total_watch_time_seconds || 0)} />
                <StatusRow label="Quiz Attempts" value={String(stats.total_quiz_attempts || 0)} />
              </div>
            </Card>

            {/* User Adoption Funnel */}
            <Card className="border-border/60 bg-card/75 p-5">
              <div className="mb-4 flex items-center gap-3">
                <div className="rounded-lg bg-purple-400/15 p-2"><TrendingUp className="h-5 w-5 text-purple-400" /></div>
                <h3 className="font-semibold text-foreground">User Adoption Funnel</h3>
              </div>
              <div className="space-y-3">
                <FunnelRow label="Signed Up" value={stats.funnel_signed_up || 0} max={stats.funnel_signed_up || 1} color="bg-blue-400" />
                <FunnelRow label="Started Course" value={stats.funnel_started_course || 0} max={stats.funnel_signed_up || 1} color="bg-emerald-400" />
                <FunnelRow label="Completed Video" value={stats.funnel_completed_video || 0} max={stats.funnel_signed_up || 1} color="bg-amber-400" />
                <FunnelRow label="Took Quiz" value={stats.funnel_took_quiz || 0} max={stats.funnel_signed_up || 1} color="bg-purple-400" />
              </div>
            </Card>

            {/* Recent Activity Feed */}
            <Card className="border-border/60 bg-card/75 p-5">
              <div className="mb-4 flex items-center gap-3">
                <div className="rounded-lg bg-cyan-400/15 p-2"><Activity className="h-5 w-5 text-cyan-400" /></div>
                <h3 className="font-semibold text-foreground">Recent Activity</h3>
              </div>
              <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
                {activityFeed.length > 0 ? activityFeed.map((act, i) => (
                  <div key={i} className="flex items-start gap-3 rounded-lg bg-muted/20 px-3 py-2">
                    <span className={`mt-0.5 ${act.color}`}>{act.icon}</span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-foreground">{act.message}</p>
                      <p className="text-xs text-muted-foreground">{fmtDate(act.time)}</p>
                    </div>
                  </div>
                )) : (
                  <p className="py-8 text-center text-sm text-muted-foreground">No recent activity</p>
                )}
              </div>
            </Card>
          </div>

          {/* Top Learners + Top Courses */}
          <div className="grid gap-4 lg:grid-cols-2">
            <Card className="border-border/60 bg-card/75 p-5">
              <div className="mb-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="rounded-lg bg-amber-400/15 p-2"><GraduationCap className="h-5 w-5 text-amber-400" /></div>
                  <h3 className="font-semibold text-foreground">Top Learners</h3>
                </div>
                <Button variant="ghost" size="sm" onClick={() => handleExportCSV(stats.top_learners || [], "top_learners")} className="text-xs text-muted-foreground">
                  <Download className="mr-1 h-3 w-3" /> CSV
                </Button>
              </div>
              <div className="space-y-2">
                {(stats.top_learners || []).map((l: any, i: number) => (
                  <div key={l.email} className="flex items-center justify-between rounded-lg bg-muted/30 px-4 py-3 transition-colors hover:bg-muted/50 cursor-pointer" onClick={() => handleViewUser(l)}>
                    <div className="flex items-center gap-3">
                      <span className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-bold ${i === 0 ? "bg-amber-400/20 text-amber-400" : i === 1 ? "bg-gray-400/20 text-gray-400" : "bg-orange-400/20 text-orange-400"}`}>
                        #{i + 1}
                      </span>
                      <div>
                        <p className="text-sm font-medium text-foreground">{l.name || l.email}</p>
                        <p className="text-xs text-muted-foreground">{l.email}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-semibold text-foreground">{fmt(l.total_watch || 0)}</p>
                      <p className="text-xs text-muted-foreground">{l.completions || 0} completed</p>
                    </div>
                  </div>
                ))}
                {(stats.top_learners || []).length === 0 && <p className="py-6 text-center text-sm text-muted-foreground">No learner data yet</p>}
              </div>
            </Card>

            <Card className="border-border/60 bg-card/75 p-5">
              <div className="mb-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="rounded-lg bg-blue-400/15 p-2"><BookOpen className="h-5 w-5 text-blue-400" /></div>
                  <h3 className="font-semibold text-foreground">Top Courses</h3>
                </div>
                <Button variant="ghost" size="sm" onClick={() => handleExportCSV(stats.top_courses || [], "top_courses")} className="text-xs text-muted-foreground">
                  <Download className="mr-1 h-3 w-3" /> CSV
                </Button>
              </div>
              <div className="space-y-2">
                {(stats.top_courses || []).map((c: any, i: number) => (
                  <div key={c.playlist_id || i} className="flex items-center justify-between rounded-lg bg-muted/30 px-4 py-3">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-foreground">{c.playlist_title}</p>
                      <p className="text-xs text-muted-foreground">{c.total_videos} videos</p>
                    </div>
                    <div className="ml-3 text-right">
                      <p className="text-sm font-semibold text-foreground">{c.enrollments} enrolled</p>
                      <p className="text-xs text-muted-foreground">{c.completions} completions</p>
                    </div>
                  </div>
                ))}
                {(stats.top_courses || []).length === 0 && <p className="py-6 text-center text-sm text-muted-foreground">No course data yet</p>}
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* ══════════════════════ USER MANAGEMENT TAB ══════════════════════ */}
      {activeTab === "users" && (
        <div className="space-y-4">
          {/* Search & Filter Bar */}
          <div className="rounded-xl border border-border/60 bg-card/75 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search users by name or email..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="w-full rounded-lg border border-border/60 bg-muted/30 py-2 pl-10 pr-4 text-sm text-foreground placeholder-muted-foreground focus:border-primary focus:outline-none"
                />
              </div>
              <Button variant="outline" size="sm" onClick={() => setShowFilters(!showFilters)} className="border-border/60">
                <Filter className="mr-2 h-4 w-4" /> Filters {showFilters ? <ChevronUp className="ml-1 h-3 w-3" /> : <ChevronDown className="ml-1 h-3 w-3" />}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => handleExportCSV(filteredAndSortedUsers, "users")} className="text-muted-foreground">
                <Download className="mr-2 h-4 w-4" /> Export CSV
              </Button>
              <span className="text-sm text-muted-foreground">{filteredAndSortedUsers.length} users</span>
            </div>

            {/* Advanced Filters */}
            {showFilters && (
              <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-border/30 pt-3">
                <div className="flex items-center gap-2">
                  <label className="text-xs font-medium text-muted-foreground">Status:</label>
                  <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="rounded-lg border border-border/60 bg-muted/30 px-2 py-1 text-xs text-foreground focus:border-primary focus:outline-none">
                    <option value="all">All</option>
                    <option value="active">Active</option>
                    <option value="suspended">Suspended</option>
                  </select>
                </div>
                <div className="flex items-center gap-2">
                  <label className="text-xs font-medium text-muted-foreground">Role:</label>
                  <select value={roleFilter} onChange={e => setRoleFilter(e.target.value)} className="rounded-lg border border-border/60 bg-muted/30 px-2 py-1 text-xs text-foreground focus:border-primary focus:outline-none">
                    <option value="all">All</option>
                    <option value="admin">Admin</option>
                    <option value="moderator">Moderator</option>
                    <option value="learner">Learner</option>
                  </select>
                </div>
                <div className="flex items-center gap-2">
                  <label className="text-xs font-medium text-muted-foreground">Per page:</label>
                  <select value={pageSize} onChange={e => setPageSize(Number(e.target.value))} className="rounded-lg border border-border/60 bg-muted/30 px-2 py-1 text-xs text-foreground focus:border-primary focus:outline-none">
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                  </select>
                </div>
                <Button variant="ghost" size="sm" onClick={() => { setStatusFilter("all"); setRoleFilter("all"); setSearchQuery("") }} className="text-xs text-muted-foreground">
                  Clear Filters
                </Button>
              </div>
            )}
          </div>

          {/* Users Table */}
          <Card className="border-border/60 bg-card/75 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border/40 bg-muted/30">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">User</th>
                    <th className="cursor-pointer px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground" onClick={() => handleSort("total_playlists")}>
                      <span className="flex items-center gap-1">Courses <SortIcon field="total_playlists" /></span>
                    </th>
                    <th className="cursor-pointer px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground" onClick={() => handleSort("completed_videos")}>
                      <span className="flex items-center gap-1">Completed <SortIcon field="completed_videos" /></span>
                    </th>
                    <th className="cursor-pointer px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground" onClick={() => handleSort("total_watch_time")}>
                      <span className="flex items-center gap-1">Watch Time <SortIcon field="total_watch_time" /></span>
                    </th>
                    <th className="cursor-pointer px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground" onClick={() => handleSort("quiz_sessions")}>
                      <span className="flex items-center gap-1">Quizzes <SortIcon field="quiz_sessions" /></span>
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Role</th>
                    <th className="cursor-pointer px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground" onClick={() => handleSort("created_at")}>
                      <span className="flex items-center gap-1">Joined <SortIcon field="created_at" /></span>
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30">
                  {paginatedUsers.length > 0 ? paginatedUsers.map((u) => {
                    const isAdmin = u.email === "admin@gmail.com"
                    const status = u.status || "active"
                    const role = u.role || "learner"
                    return (
                      <tr key={u.email} className="transition-colors hover:bg-muted/20">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-3">
                            <div className={`flex h-9 w-9 items-center justify-center rounded-full text-sm font-bold text-white ${isAdmin ? "bg-gradient-to-br from-amber-500 to-orange-500" : "bg-gradient-to-br from-primary to-blue-500"}`}>
                              {u.name?.charAt(0)?.toUpperCase() || "?"}
                            </div>
                            <div>
                              <p className="flex items-center gap-2 text-sm font-medium text-foreground">
                                {u.name || "N/A"}
                                {isAdmin && <span className="rounded-full bg-amber-400/20 px-1.5 py-0.5 text-[10px] font-semibold text-amber-400">ADMIN</span>}
                              </p>
                              <p className="text-xs text-muted-foreground">{u.email}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-foreground">{u.total_playlists || 0}</td>
                        <td className="px-4 py-3 text-sm text-foreground">{u.completed_videos || 0}</td>
                        <td className="px-4 py-3 text-sm text-foreground">{fmt(u.total_watch_time || 0)}</td>
                        <td className="px-4 py-3 text-sm text-foreground">{u.quiz_sessions || 0}</td>
                        <td className="px-4 py-3">
                          {!isAdmin ? (
                            <select
                              value={role}
                              onChange={e => handleUpdateRole(u.email, e.target.value)}
                              className="rounded-lg border border-border/60 bg-muted/30 px-2 py-1 text-xs text-foreground focus:border-primary focus:outline-none"
                            >
                              <option value="learner">Learner</option>
                              <option value="moderator">Moderator</option>
                              <option value="admin">Admin</option>
                            </select>
                          ) : (
                            <span className="rounded-full bg-amber-400/15 px-2 py-1 text-xs font-medium text-amber-400">Admin</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">{fmtDate(u.created_at)}</td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => !isAdmin && handleToggleUserStatus(u.email, status)}
                            disabled={isAdmin}
                            className={`inline-flex cursor-pointer items-center gap-1 rounded-full px-2 py-1 text-xs font-medium transition-colors ${
                              status === "active"
                                ? "bg-emerald-400/15 text-emerald-400 hover:bg-emerald-400/25"
                                : "bg-red-400/15 text-red-400 hover:bg-red-400/25"
                            } ${isAdmin ? "cursor-not-allowed opacity-50" : ""}`}
                          >
                            <span className={`h-1.5 w-1.5 rounded-full ${status === "active" ? "bg-emerald-400" : "bg-red-400"}`} />
                            {status === "active" ? "Active" : "Suspended"}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            <button onClick={() => handleViewUser(u)} className="rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary" title="View Details">
                              <Eye className="h-4 w-4" />
                            </button>
                            {!isAdmin && (
                              <button
                                onClick={() => handleDeleteUser(u.email)}
                                className="rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-red-400/10 hover:text-red-400"
                                title="Delete User"
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  }) : (
                    <tr><td colSpan={9} className="px-4 py-12 text-center text-sm text-muted-foreground">No users found</td></tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between border-t border-border/40 px-4 py-3">
                <p className="text-xs text-muted-foreground">
                  Showing {(currentPage - 1) * pageSize + 1} to {Math.min(currentPage * pageSize, filteredAndSortedUsers.length)} of {filteredAndSortedUsers.length} users
                </p>
                <div className="flex items-center gap-1">
                  <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-muted/40 disabled:opacity-30">
                    <ChevronLeft className="h-4 w-4" />
                  </button>
                  {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                    let page: number
                    if (totalPages <= 5) page = i + 1
                    else if (currentPage <= 3) page = i + 1
                    else if (currentPage >= totalPages - 2) page = totalPages - 4 + i
                    else page = currentPage - 2 + i
                    return (
                      <button
                        key={page}
                        onClick={() => setCurrentPage(page)}
                        className={`h-8 w-8 rounded-lg text-xs font-medium transition-colors ${
                          currentPage === page ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted/40"
                        }`}
                      >
                        {page}
                      </button>
                    )
                  })}
                  <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-muted/40 disabled:opacity-30">
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            )}
          </Card>
        </div>
      )}

      {/* ══════════════════════ BILLING TAB ══════════════════════ */}
      {activeTab === "billing" && (
        <div className="space-y-6">
          {billing ? (
            <>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <KPICardEnhanced label="Total Revenue" value={fmtCurrency(billing.total_revenue)} icon={<DollarSign className="h-5 w-5" />} color="green" subtext="All time" trend={{ pct: 12, dir: "up" }} />
                <KPICardEnhanced label="Monthly Revenue" value={fmtCurrency(billing.monthly_revenue)} icon={<TrendingUp className="h-5 w-5" />} color="emerald" subtext={`+${billing.mrr_growth}% growth`} trend={{ pct: billing.mrr_growth || 0, dir: "up" }} />
                <KPICardEnhanced label="Active Subscriptions" value={billing.active_subscriptions} icon={<CreditCard className="h-5 w-5" />} color="blue" subtext={`${billing.expired_subscriptions} expired`} trend={{ pct: 0, dir: "flat" }} />
                <KPICardEnhanced label="ARPU" value={fmtCurrency(billing.arpu)} icon={<Target className="h-5 w-5" />} color="purple" subtext="Avg revenue per user" trend={{ pct: 5, dir: "up" }} />
                <KPICardEnhanced label="Churn Rate" value={`${billing.churn_rate}%`} icon={<ArrowDownRight className="h-5 w-5" />} color="red" subtext="Monthly churn" trend={{ pct: billing.churn_rate || 0, dir: "down" }} />
                <KPICardEnhanced label="MRR Growth" value={`+${billing.mrr_growth}%`} icon={<ArrowUpRight className="h-5 w-5" />} color="cyan" subtext="Month over month" trend={{ pct: billing.mrr_growth || 0, dir: "up" }} />
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <Card className="border-border/60 bg-card/75 p-5">
                  <div className="mb-4 flex items-center justify-between">
                    <h3 className="font-semibold text-foreground">Revenue Trend</h3>
                    <Button variant="ghost" size="sm" onClick={() => handleExportCSV(billing.revenue_trend || [], "revenue_trend")} className="text-xs text-muted-foreground">
                      <Download className="mr-1 h-3 w-3" /> CSV
                    </Button>
                  </div>
                  <div className="h-[250px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={billing.revenue_trend || []}>
                        <defs>
                          <linearGradient id="revenueGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                        <XAxis dataKey="month" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} />
                        <YAxis tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} tickFormatter={(v) => `$${v}`} />
                        <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, color: "hsl(var(--foreground))" }} formatter={(v: any) => [`$${v}`, "Revenue"]} />
                        <Area type="monotone" dataKey="revenue" stroke="#10b981" strokeWidth={3} fill="url(#revenueGrad)" dot={{ fill: "#10b981", r: 4 }} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </Card>

                <Card className="border-border/60 bg-card/75 p-5">
                  <h3 className="mb-4 font-semibold text-foreground">Subscription Plans</h3>
                  <div className="h-[200px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={billing.plan_breakdown || []} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="users" nameKey="plan" label={({ plan, users }: any) => `${plan}: ${users}`}>
                          {(billing.plan_breakdown || []).map((_: any, i: number) => (
                            <Cell key={i} fill={COLORS[i % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, color: "hsl(var(--foreground))" }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-2 flex flex-wrap justify-center gap-4">
                    {(billing.plan_breakdown || []).map((p: any, i: number) => (
                      <div key={p.plan} className="flex items-center gap-2 text-xs">
                        <span className="h-3 w-3 rounded-full" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                        <span className="text-muted-foreground capitalize">{p.plan.replace("_", " ")}</span>
                      </div>
                    ))}
                  </div>
                  <div className="mt-3 grid grid-cols-3 gap-3 border-t border-border/30 pt-3 text-center">
                    <div><p className="text-lg font-bold text-foreground">{billing.paid_users}</p><p className="text-xs text-muted-foreground">Paid</p></div>
                    <div><p className="text-lg font-bold text-foreground">{billing.free_users}</p><p className="text-xs text-muted-foreground">Free</p></div>
                    <div><p className="text-lg font-bold text-foreground">{billing.total_users}</p><p className="text-xs text-muted-foreground">Total</p></div>
                  </div>
                </Card>
              </div>

              {/* Subscription Management Table */}
              <Card className="border-border/60 bg-card/75 overflow-hidden">
                <div className="flex items-center justify-between border-b border-border/40 px-5 py-3">
                  <h3 className="font-semibold text-foreground">Subscription Management</h3>
                  <Button variant="ghost" size="sm" onClick={() => handleExportCSV(subscriptions, "subscriptions")} className="text-xs text-muted-foreground">
                    <Download className="mr-1 h-3 w-3" /> CSV
                  </Button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border/40 bg-muted/30">
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">User</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Plan</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Amount</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Started</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Expires</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Status</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Change Plan</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/30">
                      {subscriptions.map((sub, i) => (
                        <tr key={i} className="transition-colors hover:bg-muted/20">
                          <td className="px-4 py-3">
                            <p className="text-sm font-medium text-foreground">{sub.user_name}</p>
                            <p className="text-xs text-muted-foreground">{sub.user_email}</p>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`rounded-full px-2 py-1 text-xs font-medium ${
                              sub.plan === "free" ? "bg-muted/40 text-muted-foreground" :
                              sub.plan === "enterprise" ? "bg-purple-400/15 text-purple-400" :
                              "bg-primary/15 text-primary"
                            }`}>
                              {sub.plan.replace("_", " ").toUpperCase()}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm text-foreground">${sub.amount.toFixed(2)}</td>
                          <td className="px-4 py-3 text-sm text-muted-foreground">{fmtDate(sub.started_at)}</td>
                          <td className="px-4 py-3 text-sm text-muted-foreground">{fmtDate(sub.expires_at)}</td>
                          <td className="px-4 py-3">
                            <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-medium ${
                              sub.status === "active" ? "bg-emerald-400/15 text-emerald-400" : "bg-red-400/15 text-red-400"
                            }`}>
                              <span className={`h-1.5 w-1.5 rounded-full ${sub.status === "active" ? "bg-emerald-400" : "bg-red-400"}`} />
                              {sub.status}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <select
                              onChange={e => { if (e.target.value) handleUpdateSubscription(sub.user_email, e.target.value) }}
                              defaultValue=""
                              className="rounded-lg border border-border/60 bg-muted/30 px-2 py-1 text-xs text-foreground focus:border-primary focus:outline-none"
                            >
                              <option value="" disabled>Change Plan</option>
                              <option value="free">Free</option>
                              <option value="pro_monthly">Pro Monthly ($29.99)</option>
                              <option value="pro_annual">Pro Annual ($199.99)</option>
                              <option value="enterprise">Enterprise ($99.99)</option>
                            </select>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </>
          ) : (
            <div className="flex items-center justify-center py-20">
              <div className="mx-auto h-8 w-8 animate-spin rounded-full border-b-2 border-primary" />
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════ CERTIFICATES TAB ══════════════════════ */}
      {activeTab === "certificates" && (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-4">
            <KPICardEnhanced label="Total Issued" value={certificates.length} icon={<Award className="h-5 w-5" />} color="amber" subtext="All time" trend={{ pct: 0, dir: "flat" }} />
            <KPICardEnhanced label="Active" value={certificates.filter(c => c.status === "active").length} icon={<CheckCircle className="h-5 w-5" />} color="emerald" subtext="Valid certificates" trend={{ pct: 0, dir: "flat" }} />
            <KPICardEnhanced label="Revoked" value={certificates.filter(c => c.status === "revoked").length} icon={<XCircle className="h-5 w-5" />} color="red" subtext="Invalidated" trend={{ pct: 0, dir: "flat" }} />
            {/* Issue Certificate Button Card */}
            <Card className="border border-dashed border-primary/40 bg-primary/5 p-5 flex flex-col items-center justify-center cursor-pointer hover:bg-primary/10 transition-colors" onClick={() => setShowIssueCertDialog(true)}>
              <div className="rounded-full bg-primary/20 p-3 mb-2">
                <Plus className="h-6 w-6 text-primary" />
              </div>
              <p className="text-sm font-semibold text-primary">Issue Certificate</p>
              <p className="text-xs text-muted-foreground mt-1">Award new certificate</p>
            </Card>
          </div>

          {/* Certificates Table */}
          <Card className="border-border/60 bg-card/75 overflow-hidden">
            <div className="flex items-center justify-between border-b border-border/40 px-5 py-3">
              <h3 className="font-semibold text-foreground">Issued Certificates</h3>
              <Button variant="ghost" size="sm" onClick={() => handleExportCSV(certificates, "certificates")} className="text-xs text-muted-foreground">
                <Download className="mr-1 h-3 w-3" /> CSV
              </Button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border/40 bg-muted/30">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Certificate ID</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Recipient</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Course</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Grade</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Issued</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30">
                  {certificates.map((cert, i) => (
                    <tr key={i} className="transition-colors hover:bg-muted/20">
                      <td className="px-4 py-3">
                        <span className="font-mono text-sm text-primary">{cert.cert_id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-sm font-medium text-foreground">{cert.user_name || cert.user_email}</p>
                        <p className="text-xs text-muted-foreground">{cert.user_email}</p>
                      </td>
                      <td className="px-4 py-3 max-w-[200px]">
                        <p className="truncate text-sm text-foreground">{cert.course_title}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded-full bg-emerald-400/15 px-2 py-1 text-xs font-medium text-emerald-400">{cert.grade}</span>
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">{fmtDate(cert.issued_at)}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-medium ${
                          cert.status === "active" ? "bg-emerald-400/15 text-emerald-400" : "bg-red-400/15 text-red-400"
                        }`}>
                          {cert.status === "active" ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                          {cert.status}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button className="rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-muted/40 hover:text-foreground" title="Copy Certificate ID" onClick={() => { navigator.clipboard.writeText(cert.cert_id); showAction("Certificate ID copied") }}>
                            <Copy className="h-3.5 w-3.5" />
                          </button>
                          {cert.status === "active" && (
                            <button
                              onClick={() => handleRevokeCertificate(cert.cert_id)}
                              className="flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-red-400 transition-colors hover:bg-red-400/10"
                            >
                              <XCircle className="h-3 w-3" /> Revoke
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {certificates.length === 0 && (
                    <tr><td colSpan={7} className="px-4 py-8 text-center text-sm text-muted-foreground">No certificates issued yet</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* ══════════════════════ COURSES TAB ══════════════════════ */}
      {activeTab === "courses" && (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KPICardEnhanced label="Total Courses" value={courses.length} icon={<BookOpen className="h-5 w-5" />} color="blue" subtext="All courses" trend={{ pct: 0, dir: "flat" }} />
            <KPICardEnhanced label="Total Enrollments" value={courses.reduce((s, c) => s + c.enrolled_users, 0)} icon={<Users className="h-5 w-5" />} color="emerald" subtext="Across all courses" trend={{ pct: 0, dir: "flat" }} />
            <KPICardEnhanced label="Total Completions" value={courses.reduce((s, c) => s + c.completions, 0)} icon={<CheckCircle className="h-5 w-5" />} color="amber" subtext="Videos completed" trend={{ pct: 0, dir: "flat" }} />
            <KPICardEnhanced label="Avg Completion Rate" value={`${courses.length > 0 ? (courses.reduce((s, c) => s + c.completion_rate, 0) / courses.length).toFixed(1) : 0}%`} icon={<Target className="h-5 w-5" />} color="purple" subtext="Platform average" trend={{ pct: 0, dir: "flat" }} />
          </div>

          <Card className="border-border/60 bg-card/75 overflow-hidden">
            <div className="flex items-center justify-between border-b border-border/40 px-5 py-3">
              <h3 className="font-semibold text-foreground">Course Management</h3>
              <Button variant="ghost" size="sm" onClick={() => handleExportCSV(courses, "courses")} className="text-xs text-muted-foreground">
                <Download className="mr-1 h-3 w-3" /> CSV
              </Button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border/40 bg-muted/30">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Course</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Videos</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Enrolled</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Completions</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Rate</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Watch Time</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Created</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30">
                  {courses.map((course, i) => (
                    <tr key={i} className="transition-colors hover:bg-muted/20">
                      <td className="px-4 py-3">
                        <p className="max-w-[220px] truncate text-sm font-medium text-foreground">{course.playlist_title}</p>
                        <p className="font-mono text-xs text-muted-foreground">{course.playlist_id?.substring(0, 12)}...</p>
                      </td>
                      <td className="px-4 py-3 text-sm text-foreground">{course.total_videos}</td>
                      <td className="px-4 py-3 text-sm text-foreground">{course.enrolled_users}</td>
                      <td className="px-4 py-3 text-sm text-foreground">{course.completions}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-16 overflow-hidden rounded-full bg-muted/60">
                            <div className={`h-full rounded-full ${course.completion_rate >= 50 ? "bg-emerald-400" : course.completion_rate > 0 ? "bg-amber-400" : "bg-muted-foreground"}`} style={{ width: `${Math.min(course.completion_rate, 100)}%` }} />
                          </div>
                          <span className="text-xs text-muted-foreground">{course.completion_rate}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-foreground">{fmt(course.total_watch_time || 0)}</td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">{fmtDate(course.created_at)}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-medium ${
                          (course.status || "active") === "active" ? "bg-emerald-400/15 text-emerald-400" : "bg-muted/40 text-muted-foreground"
                        }`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${(course.status || "active") === "active" ? "bg-emerald-400" : "bg-muted-foreground"}`} />
                          {course.status || "active"}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleToggleCourse(course.playlist_id, course.status || "active")}
                          className={`rounded-lg px-2 py-1 text-xs transition-colors ${
                            (course.status || "active") === "active"
                              ? "text-amber-400 hover:bg-amber-400/10"
                              : "text-emerald-400 hover:bg-emerald-400/10"
                          }`}
                        >
                          {(course.status || "active") === "active" ? "Archive" : "Activate"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* ══════════════════════ ANALYTICS TAB ══════════════════════ */}
      {activeTab === "analytics" && (
        <div className="space-y-6">
          {analytics ? (
            <>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <KPICardEnhanced label="Quiz Sessions" value={analytics.quiz_overview?.total_sessions || 0} icon={<Brain className="h-5 w-5" />} color="blue" subtext="Total sessions" trend={{ pct: 8, dir: "up" }} />
                <KPICardEnhanced label="Total Attempts" value={analytics.quiz_overview?.total_attempts || 0} icon={<Zap className="h-5 w-5" />} color="emerald" subtext={`${analytics.quiz_overview?.correct_answers || 0} correct`} trend={{ pct: 0, dir: "flat" }} />
                <KPICardEnhanced label="Quiz Accuracy" value={`${analytics.quiz_overview?.accuracy || 0}%`} icon={<Target className="h-5 w-5" />} color="amber" subtext="Platform average" trend={{ pct: 3, dir: "up" }} />
                <KPICardEnhanced label="Avg Time/Question" value={`${analytics.quiz_overview?.avg_time_per_question || 0}s`} icon={<Clock className="h-5 w-5" />} color="purple" subtext="Response time" trend={{ pct: 0, dir: "flat" }} />
              </div>

              {/* Weekly Learning Hours Chart */}
              <Card className="border-border/60 bg-card/75 p-5">
                <div className="mb-4 flex items-center justify-between">
                  <h3 className="font-semibold text-foreground">Weekly Learning Hours (Last 8 Weeks)</h3>
                  <Button variant="ghost" size="sm" onClick={() => handleExportCSV(analytics.weekly_learning_hours || [], "weekly_hours")} className="text-xs text-muted-foreground">
                    <Download className="mr-1 h-3 w-3" /> CSV
                  </Button>
                </div>
                <div className="h-[250px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={analytics.weekly_learning_hours || []}>
                      <defs>
                        <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.9} />
                          <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.4} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                      <XAxis dataKey="week" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} />
                      <YAxis tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} />
                      <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, color: "hsl(var(--foreground))" }} />
                      <Bar dataKey="hours" fill="url(#barGrad)" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </Card>

              {/* Engagement Distribution + Top Performers */}
              <div className="grid gap-4 lg:grid-cols-2">
                <Card className="border-border/60 bg-card/75 p-5">
                  <h3 className="mb-4 font-semibold text-foreground">User Engagement Distribution</h3>
                  <div className="space-y-3">
                    {(analytics.engagement_distribution || []).map((seg: any, i: number) => {
                      const total = (analytics.engagement_distribution || []).reduce((s: number, d: any) => s + d.users, 0)
                      const pct = total > 0 ? Math.round(seg.users / total * 100) : 0
                      const colors = ["bg-red-400", "bg-amber-400", "bg-blue-400", "bg-emerald-400"]
                      return (
                        <div key={i}>
                          <div className="mb-1 flex justify-between text-sm">
                            <span className="text-muted-foreground">{seg.segment}</span>
                            <span className="font-medium text-foreground">{seg.users} users ({pct}%)</span>
                          </div>
                          <div className="h-2.5 w-full overflow-hidden rounded-full bg-muted/40">
                            <div className={`h-full rounded-full ${colors[i % colors.length]} transition-all`} style={{ width: `${pct}%` }} />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </Card>

                <Card className="border-border/60 bg-card/75 p-5">
                  <div className="mb-4 flex items-center justify-between">
                    <h3 className="font-semibold text-foreground">Top Performers</h3>
                    <Button variant="ghost" size="sm" onClick={() => handleExportCSV(analytics.top_performers || [], "top_performers")} className="text-xs text-muted-foreground">
                      <Download className="mr-1 h-3 w-3" /> CSV
                    </Button>
                  </div>
                  <div className="space-y-2">
                    {(analytics.top_performers || []).map((p: any, i: number) => (
                      <div key={i} className="flex items-center justify-between rounded-lg bg-muted/30 px-4 py-3">
                        <div className="flex items-center gap-3">
                          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-amber-500 to-orange-500 text-xs font-bold text-white">
                            {i + 1}
                          </span>
                          <div>
                            <p className="text-sm font-medium text-foreground">{p.name}</p>
                            <p className="text-xs text-muted-foreground">{p.email}</p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-semibold text-foreground">{fmt(p.total_watch)}</p>
                          <p className="text-xs text-muted-foreground">{p.completions} done, {p.quiz_accuracy}% quiz</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>

              {/* Course Completion Rates */}
              <Card className="border-border/60 bg-card/75 p-5">
                <div className="mb-4 flex items-center justify-between">
                  <h3 className="font-semibold text-foreground">Course Enrollment vs Completion</h3>
                  <Button variant="ghost" size="sm" onClick={() => handleExportCSV(analytics.course_completion_rates || [], "completion_rates")} className="text-xs text-muted-foreground">
                    <Download className="mr-1 h-3 w-3" /> CSV
                  </Button>
                </div>
                <div className="space-y-3">
                  {(analytics.course_completion_rates || []).map((c: any, i: number) => {
                    const rate = c.enrolled > 0 ? Math.round(c.completed / c.enrolled * 100) : 0
                    return (
                      <div key={i} className="flex items-center gap-4">
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm text-foreground">{c.playlist_title}</p>
                        </div>
                        <div className="flex items-center gap-3 text-sm">
                          <span className="w-20 text-right text-muted-foreground">{c.enrolled} enrolled</span>
                          <div className="h-2 w-32 overflow-hidden rounded-full bg-muted/60">
                            <div className={`h-full rounded-full ${rate >= 50 ? "bg-emerald-400" : rate > 0 ? "bg-amber-400" : "bg-muted-foreground"}`} style={{ width: `${rate}%` }} />
                          </div>
                          <span className="w-16 font-medium text-foreground">{c.completed} done</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </Card>
            </>
          ) : (
            <div className="flex items-center justify-center py-20">
              <div className="mx-auto h-8 w-8 animate-spin rounded-full border-b-2 border-primary" />
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════ USER DETAIL DRAWER ══════════════════════ */}
      {drawerOpen && (
        <>
          <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" onClick={() => setDrawerOpen(false)} />
          <div className="fixed inset-y-0 right-0 z-50 w-full max-w-lg overflow-y-auto border-l border-border/40 bg-card shadow-2xl transition-transform sm:max-w-xl">
            <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border/40 bg-card/95 px-6 py-4 backdrop-blur-xl">
              <div className="flex items-center gap-3">
                <div className={`flex h-10 w-10 items-center justify-center rounded-full text-sm font-bold text-white ${selectedUser?.email === "admin@gmail.com" ? "bg-gradient-to-br from-amber-500 to-orange-500" : "bg-gradient-to-br from-primary to-blue-500"}`}>
                  {selectedUser?.name?.charAt(0)?.toUpperCase() || "?"}
                </div>
                <div>
                  <h2 className="text-lg font-bold text-foreground">{selectedUser?.name || "N/A"}</h2>
                  <p className="text-sm text-muted-foreground">{selectedUser?.email}</p>
                </div>
              </div>
              <button onClick={() => setDrawerOpen(false)} className="rounded-lg p-2 text-muted-foreground hover:bg-muted/40 hover:text-foreground">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              {drawerLoading ? (
                <div className="flex items-center justify-center py-20">
                  <div className="mx-auto h-8 w-8 animate-spin rounded-full border-b-2 border-primary" />
                </div>
              ) : (
                <>
                  {/* User Info Cards */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-xl border border-border/40 bg-muted/20 p-4">
                      <p className="text-xs font-medium text-muted-foreground">Status</p>
                      <span className={`mt-1 inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-medium ${
                        (selectedUser?.status || "active") === "active" ? "bg-emerald-400/15 text-emerald-400" : "bg-red-400/15 text-red-400"
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${(selectedUser?.status || "active") === "active" ? "bg-emerald-400" : "bg-red-400"}`} />
                        {selectedUser?.status || "active"}
                      </span>
                    </div>
                    <div className="rounded-xl border border-border/40 bg-muted/20 p-4">
                      <p className="text-xs font-medium text-muted-foreground">Role</p>
                      <p className="mt-1 text-sm font-semibold text-foreground capitalize">{selectedUser?.role || "learner"}</p>
                    </div>
                    <div className="rounded-xl border border-border/40 bg-muted/20 p-4">
                      <p className="text-xs font-medium text-muted-foreground">Joined</p>
                      <p className="mt-1 text-sm font-semibold text-foreground">{fmtDate(selectedUser?.created_at)}</p>
                    </div>
                    <div className="rounded-xl border border-border/40 bg-muted/20 p-4">
                      <p className="text-xs font-medium text-muted-foreground">Last Active</p>
                      <p className="mt-1 text-sm font-semibold text-foreground">{fmtDate(selectedUser?.last_login)}</p>
                    </div>
                  </div>

                  {/* Learning Stats */}
                  <div>
                    <h3 className="mb-3 text-sm font-semibold text-foreground">Learning Statistics</h3>
                    <div className="grid grid-cols-2 gap-3">
                      <StatCard label="Courses Enrolled" value={selectedUserStats?.total_playlists || selectedUser?.total_playlists || 0} icon={<BookOpen className="h-4 w-4 text-blue-400" />} />
                      <StatCard label="Videos Completed" value={selectedUserStats?.completed_videos || selectedUser?.completed_videos || 0} icon={<CheckCircle className="h-4 w-4 text-emerald-400" />} />
                      <StatCard label="Total Watch Time" value={fmt(selectedUserStats?.total_watch_time || selectedUser?.total_watch_time || 0)} icon={<Clock className="h-4 w-4 text-amber-400" />} />
                      <StatCard label="Quiz Sessions" value={selectedUserStats?.quiz_sessions || selectedUser?.quiz_sessions || 0} icon={<Brain className="h-4 w-4 text-purple-400" />} />
                    </div>
                  </div>

                  {/* Courses List */}
                  {selectedUserStats?.playlists && selectedUserStats.playlists.length > 0 && (
                    <div>
                      <h3 className="mb-3 text-sm font-semibold text-foreground">Enrolled Courses</h3>
                      <div className="space-y-2">
                        {selectedUserStats.playlists.map((pl: any, i: number) => (
                          <div key={i} className="flex items-center justify-between rounded-lg border border-border/30 bg-muted/20 px-4 py-3">
                            <div className="min-w-0 flex-1">
                              <p className="truncate text-sm font-medium text-foreground">{pl.playlist_title}</p>
                              <p className="text-xs text-muted-foreground">{pl.total_videos} videos</p>
                            </div>
                            <div className="ml-3 text-right">
                              <div className="flex items-center gap-2">
                                <div className="h-2 w-16 overflow-hidden rounded-full bg-muted/60">
                                  <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(pl.progress || 0, 100)}%` }} />
                                </div>
                                <span className="text-xs font-medium text-foreground">{pl.progress || 0}%</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Quick Actions */}
                  <div>
                    <h3 className="mb-3 text-sm font-semibold text-foreground">Quick Actions</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedUser?.email !== "admin@gmail.com" && (
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => { handleToggleUserStatus(selectedUser?.email, selectedUser?.status || "active"); setSelectedUser((prev: any) => ({ ...prev, status: (prev?.status || "active") === "active" ? "suspended" : "active" })) }}
                            className="border-border/60"
                          >
                            {(selectedUser?.status || "active") === "active" ? <XCircle className="mr-2 h-4 w-4 text-red-400" /> : <CheckCircle className="mr-2 h-4 w-4 text-emerald-400" />}
                            {(selectedUser?.status || "active") === "active" ? "Suspend User" : "Activate User"}
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => { handleDeleteUser(selectedUser?.email); setDrawerOpen(false) }}
                            className="border-red-400/30 text-red-400 hover:bg-red-400/10"
                          >
                            <Trash2 className="mr-2 h-4 w-4" /> Delete User
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </>
      )}

      {/* ══════════════════════ ISSUE CERTIFICATE DIALOG ══════════════════════ */}
      {showIssueCertDialog && (
        <>
          <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" onClick={() => setShowIssueCertDialog(false)} />
          <div className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border/60 bg-card p-6 shadow-2xl">
            <div className="mb-6 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-amber-400/15 p-2">
                  <Award className="h-5 w-5 text-amber-400" />
                </div>
                <h2 className="text-lg font-bold text-foreground">Issue Certificate</h2>
              </div>
              <button onClick={() => setShowIssueCertDialog(false)} className="rounded-lg p-2 text-muted-foreground hover:bg-muted/40">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-foreground">Recipient Email *</label>
                <select
                  value={certUserEmail}
                  onChange={e => setCertUserEmail(e.target.value)}
                  className="w-full rounded-lg border border-border/60 bg-muted/30 px-3 py-2 text-sm text-foreground focus:border-primary focus:outline-none"
                >
                  <option value="">Select a user...</option>
                  {users.filter(u => u.email !== "admin@gmail.com").map(u => (
                    <option key={u.email} value={u.email}>{u.name || u.email} ({u.email})</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-foreground">Course Title *</label>
                {courses.length > 0 ? (
                  <select
                    value={certCourseTitle}
                    onChange={e => {
                      const course = courses.find(c => c.playlist_title === e.target.value)
                      setCertCourseTitle(e.target.value)
                      if (course) setCertPlaylistId(course.playlist_id)
                    }}
                    className="w-full rounded-lg border border-border/60 bg-muted/30 px-3 py-2 text-sm text-foreground focus:border-primary focus:outline-none"
                  >
                    <option value="">Select a course...</option>
                    {courses.map(c => (
                      <option key={c.playlist_id} value={c.playlist_title}>{c.playlist_title}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    value={certCourseTitle}
                    onChange={e => setCertCourseTitle(e.target.value)}
                    placeholder="Enter course title"
                    className="w-full rounded-lg border border-border/60 bg-muted/30 px-3 py-2 text-sm text-foreground placeholder-muted-foreground focus:border-primary focus:outline-none"
                  />
                )}
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <Button variant="outline" size="sm" onClick={() => setShowIssueCertDialog(false)}>Cancel</Button>
                <Button
                  size="sm"
                  onClick={handleIssueCertificate}
                  disabled={!certUserEmail || !certCourseTitle || issuingCert}
                  className="bg-amber-500 text-white hover:bg-amber-600"
                >
                  {issuingCert ? "Issuing..." : "Issue Certificate"}
                </Button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

/* ==================== Enhanced Helper Components ==================== */

function KPICardEnhanced({ label, value, icon, color, subtext, trend }: {
  label: string; value: string | number; icon: React.ReactNode; color: string; subtext?: string;
  trend?: { pct: number; dir: "up" | "down" | "flat" }
}) {
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
          <div className="mt-1 flex items-center gap-2">
            {subtext && <p className="text-xs text-muted-foreground">{subtext}</p>}
            {trend && trend.dir !== "flat" && trend.pct > 0 && (
              <span className={`flex items-center gap-0.5 text-xs font-medium ${trend.dir === "up" ? "text-emerald-400" : "text-red-400"}`}>
                {trend.dir === "up" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />}
                {trend.pct}%
              </span>
            )}
          </div>
        </div>
        <div className={`rounded-xl p-3 ${c.bg}`}>
          <span className={c.text}>{icon}</span>
        </div>
      </div>
    </Card>
  )
}

function StatusRow({ label, value, status }: { label: string; value: string; status?: string }) {
  return (
    <div className="flex items-center justify-between rounded-lg bg-muted/30 px-3 py-2">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className={`flex items-center gap-1.5 text-sm font-medium ${status === "ok" ? "text-emerald-400" : "text-foreground"}`}>
        {status === "ok" && <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />}
        {value}
      </span>
    </div>
  )
}

function FunnelRow({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round(value / max * 100) : 0
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-medium text-foreground">{value} ({pct}%)</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-muted/40">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function StatCard({ label, value, icon }: { label: string; value: string | number; icon: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border/40 bg-muted/20 p-4">
      <div className="flex items-center gap-2 mb-1">
        {icon}
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
      </div>
      <p className="text-lg font-bold text-foreground">{value}</p>
    </div>
  )
}
