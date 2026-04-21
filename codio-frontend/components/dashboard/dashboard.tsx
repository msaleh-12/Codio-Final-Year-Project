"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import PlaylistInput from "./playlist-input"
import LearningView from "./learning-view"
import DashboardHome from "./dashboard-home"
import MyLearning from "./my-learning"
import AdminPanel from "./admin-panel"
import ProfilePage from "./profile-page"
import {
  Home,
  Search,
  BookOpen,
  CheckCircle2,
  ShieldCheck,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Menu,
  LayoutDashboard,
  Users,
  CreditCard,
  Award,
  MonitorPlay,
  BarChart3,
  ArrowLeftRight,
  UserCircle,
} from "lucide-react"

interface DashboardProps {
  user: { email: string; name: string }
  onLogout: () => void
}

// Video metadata that can be passed from search results to skip yt-dlp extraction
export interface PreloadedVideoMeta {
  video_id: string
  title: string
  thumbnail: string
  duration: number
  url: string
}

// Admin navigation sections (tabs inside AdminPanel)
type AdminSection = "overview" | "users" | "billing" | "certificates" | "courses" | "analytics"

// User navigation sections
type UserSection = "home" | "discover" | "my-learning" | "completed" | "profile"

// Combined type
type NavSection = UserSection | AdminSection | "admin-home"

const ADMIN_EMAIL = "admin@gmail.com"

export default function Dashboard({ user, onLogout }: DashboardProps) {
  const isAdmin = user.email === ADMIN_EMAIL

  const [activeSection, setActiveSection] = useState<NavSection>(isAdmin ? "overview" : "home")
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [adminMode, setAdminMode] = useState(isAdmin) // Admin starts in admin mode

  // Learning view state
  const [isLearning, setIsLearning] = useState(false)
  const [playlistUrl, setPlaylistUrl] = useState("")
  const [playlistTitle, setPlaylistTitle] = useState("")
  const [preloadedVideo, setPreloadedVideo] = useState<PreloadedVideoMeta | null>(null)

  const handleStartLearning = (url: string, title: string, videoMeta?: PreloadedVideoMeta) => {
    console.log("[Dashboard] Starting learning - URL:", url, "Title:", title)
    setPlaylistUrl(url)
    setPlaylistTitle(title)
    setPreloadedVideo(videoMeta || null)
    setIsLearning(true)
  }

  const handleBackToDashboard = () => {
    setIsLearning(false)
    setPlaylistUrl("")
    setPlaylistTitle("")
    setPreloadedVideo(null)
  }

  // Toggle between admin and user mode (only for admins)
  const toggleMode = () => {
    if (!isAdmin) return
    if (adminMode) {
      setAdminMode(false)
      setActiveSection("home")
    } else {
      setAdminMode(true)
      setActiveSection("overview")
    }
  }

  // Admin navigation items
  const adminNavItems: { id: NavSection; label: string; icon: React.ReactNode; tab: string }[] = [
    { id: "overview", label: "Overview", icon: <LayoutDashboard className="h-5 w-5" />, tab: "overview" },
    { id: "users", label: "User Management", icon: <Users className="h-5 w-5" />, tab: "users" },
    { id: "billing", label: "Billing", icon: <CreditCard className="h-5 w-5" />, tab: "billing" },
    { id: "certificates", label: "Certificates", icon: <Award className="h-5 w-5" />, tab: "certificates" },
    { id: "courses", label: "Courses", icon: <MonitorPlay className="h-5 w-5" />, tab: "courses" },
    { id: "analytics", label: "Analytics", icon: <BarChart3 className="h-5 w-5" />, tab: "analytics" },
  ]

  // User navigation items
  const userNavItems: { id: NavSection; label: string; icon: React.ReactNode }[] = [
    { id: "home", label: "Dashboard", icon: <Home className="h-5 w-5" /> },
    { id: "discover", label: "Discover", icon: <Search className="h-5 w-5" /> },
    { id: "my-learning", label: "My Learning", icon: <BookOpen className="h-5 w-5" /> },
    { id: "completed", label: "Completed", icon: <CheckCircle2 className="h-5 w-5" /> },
    { id: "profile", label: "Profile", icon: <UserCircle className="h-5 w-5" /> },
  ]

  const currentNavItems = adminMode ? adminNavItems : userNavItems

  // Get the active admin tab name for AdminPanel
  const getAdminTab = (): string => {
    const adminItem = adminNavItems.find(item => item.id === activeSection)
    return adminItem?.tab || "overview"
  }

  // If in learning view, show full-screen learning
  if (isLearning) {
    return (
      <div className="min-h-screen">
        <LearningView
          playlistUrl={playlistUrl}
          playlistTitle={playlistTitle}
          userEmail={user.email}
          onBack={handleBackToDashboard}
          preloadedVideo={preloadedVideo}
        />
      </div>
    )
  }

  return (
    <div className="flex min-h-screen bg-background">
      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-border/40 bg-card/95 backdrop-blur-xl transition-all duration-300
          ${sidebarCollapsed ? "w-[72px]" : "w-64"}
          ${mobileMenuOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
        `}
      >
        {/* Logo */}
        <div className="flex h-16 items-center gap-3 border-b border-border/40 px-4">
          <div className={`flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl border shadow-[0_0_24px_-10px_var(--color-primary)] ${adminMode ? "border-red-500/35 bg-red-500/15" : "border-primary/35 bg-primary/15"}`}>
            <span className={`text-lg font-black ${adminMode ? "text-red-400" : "text-primary"}`}>
              {adminMode ? "A" : "C"}
            </span>
          </div>
          {!sidebarCollapsed && (
            <div className="overflow-hidden">
              <h1 className="text-lg font-bold tracking-tight text-foreground">
                {adminMode ? "Admin" : "Codio"}
              </h1>
              <p className="text-[10px] text-muted-foreground">
                {adminMode ? "Management Console" : "Interactive Learning"}
              </p>
            </div>
          )}
        </div>

        {/* Mode indicator for admin */}
        {isAdmin && !sidebarCollapsed && (
          <div className="mx-3 mt-3 mb-1">
            <button
              onClick={toggleMode}
              className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-all ${
                adminMode
                  ? "bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20"
                  : "bg-primary/10 text-primary hover:bg-primary/20 border border-primary/20"
              }`}
            >
              <ArrowLeftRight className="h-3.5 w-3.5" />
              <span>Switch to {adminMode ? "Learner" : "Admin"} View</span>
            </button>
          </div>
        )}
        {isAdmin && sidebarCollapsed && (
          <div className="mx-auto mt-3 mb-1">
            <button
              onClick={toggleMode}
              className={`flex h-8 w-8 items-center justify-center rounded-lg transition-all ${
                adminMode
                  ? "bg-red-500/10 text-red-400 hover:bg-red-500/20"
                  : "bg-primary/10 text-primary hover:bg-primary/20"
              }`}
              title={`Switch to ${adminMode ? "Learner" : "Admin"} View`}
            >
              <ArrowLeftRight className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {/* Section Label */}
        {!sidebarCollapsed && (
          <div className="px-5 pt-3 pb-1">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
              {adminMode ? "Administration" : "Navigation"}
            </p>
          </div>
        )}

        {/* Nav Items */}
        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-2">
          {currentNavItems.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setActiveSection(item.id)
                setMobileMenuOpen(false)
              }}
              className={`group flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all
                ${
                  activeSection === item.id
                    ? adminMode
                      ? "bg-red-500/15 text-red-400 shadow-sm"
                      : "bg-primary/15 text-primary shadow-sm"
                    : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
                }
                ${sidebarCollapsed ? "justify-center" : ""}
              `}
              title={sidebarCollapsed ? item.label : undefined}
            >
              <span className={
                activeSection === item.id
                  ? adminMode ? "text-red-400" : "text-primary"
                  : "text-muted-foreground group-hover:text-foreground"
              }>
                {item.icon}
              </span>
              {!sidebarCollapsed && <span>{item.label}</span>}
            </button>
          ))}
        </nav>

        {/* User Section */}
        <div className="border-t border-border/40 p-3">
          {!sidebarCollapsed && (
            <div className="mb-3 rounded-xl bg-muted/40 px-3 py-2 cursor-pointer hover:bg-muted/60 transition-colors"
              onClick={() => { if (!adminMode) { setActiveSection("profile"); setMobileMenuOpen(false) } }}>
              <p className="truncate text-sm font-medium text-foreground">{user.name}</p>
              <p className="truncate text-xs text-muted-foreground">{user.email}</p>
              {isAdmin && (
                <span className={`mt-1 inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                  adminMode ? "bg-red-500/15 text-red-400" : "bg-primary/15 text-primary"
                }`}>
                  {adminMode ? "Admin Mode" : "Learner Mode"}
                </span>
              )}
            </div>
          )}
          <div className="flex items-center gap-2">
            <Button
              onClick={onLogout}
              variant="ghost"
              size="sm"
              className={`text-muted-foreground hover:text-destructive ${sidebarCollapsed ? "w-full justify-center" : "flex-1"}`}
              title="Logout"
            >
              <LogOut className="h-4 w-4" />
              {!sidebarCollapsed && <span className="ml-2">Logout</span>}
            </Button>
          </div>
        </div>

        {/* Collapse Toggle (desktop only) */}
        <button
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          className="absolute -right-3 top-20 hidden h-6 w-6 items-center justify-center rounded-full border border-border/60 bg-card text-muted-foreground shadow-sm hover:text-foreground lg:flex"
        >
          {sidebarCollapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronLeft className="h-3 w-3" />}
        </button>
      </aside>

      {/* Main Content */}
      <div className={`flex-1 transition-all duration-300 ${sidebarCollapsed ? "lg:ml-[72px]" : "lg:ml-64"}`}>
        {/* Top Bar */}
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-border/40 bg-background/80 px-4 backdrop-blur-xl sm:px-6">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="rounded-lg p-2 text-muted-foreground hover:bg-muted/60 hover:text-foreground lg:hidden"
            >
              <Menu className="h-5 w-5" />
            </button>
            <h2 className="text-lg font-semibold text-foreground">
              {adminMode ? "Admin Console" : (currentNavItems.find((i) => i.id === activeSection)?.label || "Dashboard")}
            </h2>
          </div>
          <div className="flex items-center gap-3">
            <div className={`hidden rounded-full border px-3 py-1 text-xs sm:block ${
              adminMode
                ? "border-red-500/30 bg-red-500/10 text-red-400"
                : "border-border/60 bg-muted/40 text-muted-foreground"
            }`}>
              {adminMode
                ? (currentNavItems.find((i) => i.id === activeSection)?.label || "Overview")
                : activeSection === "home" ? "Overview" : activeSection === "discover" ? "Search & Learn" : "Progress"
              }
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          {/* Admin Mode Content */}
          {adminMode && (
            <AdminPanel userEmail={user.email} activeTab={getAdminTab()} />
          )}

          {/* User Mode Content */}
          {!adminMode && activeSection === "home" && (
            <DashboardHome
              user={user}
              onStartLearning={handleStartLearning}
              onNavigate={(section: string) => setActiveSection(section as NavSection)}
            />
          )}
          {!adminMode && activeSection === "discover" && (
            <PlaylistInput onStartLearning={handleStartLearning} userEmail={user.email} />
          )}
          {!adminMode && activeSection === "my-learning" && (
            <MyLearning
              userEmail={user.email}
              onStartLearning={handleStartLearning}
              filter="in-progress"
            />
          )}
          {!adminMode && activeSection === "completed" && (
            <MyLearning
              userEmail={user.email}
              onStartLearning={handleStartLearning}
              filter="completed"
            />
          )}
          {!adminMode && activeSection === "profile" && (
            <ProfilePage user={user} />
          )}
        </main>
      </div>
    </div>
  )
}
