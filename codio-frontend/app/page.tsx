"use client"

import { useState, useEffect } from "react"
import LoginScreen from "@/components/auth/login-screen"
import SignupScreen from "@/components/auth/signup-screen"
import Dashboard from "@/components/dashboard/dashboard"
import { api, clearTokens, getAccessToken } from "@/lib/api"

export default function Home() {
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [user, setUser] = useState<{ email: string; name: string } | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [showSignup, setShowSignup] = useState(false)
  const [activeView, setActiveView] = useState<"login" | "signup" | "dashboard">("login")
  const [isViewExiting, setIsViewExiting] = useState(false)

  // Check for existing session on mount
  useEffect(() => {
    console.log("[Home] Checking for existing user session...")
    const storedUser = localStorage.getItem("codio_user")
    const token = getAccessToken()
    
    if (storedUser && token) {
      // Both user data and JWT token exist — restore session
      try {
        const userData = JSON.parse(storedUser)
        console.log("[Home] Found stored user with valid token:", userData.email)
        setUser(userData)
        setIsLoggedIn(true)
      } catch (error) {
        console.error("[Home] Error parsing stored user:", error)
        localStorage.removeItem("codio_user")
        clearTokens()
      }
    } else if (storedUser && !token) {
      // User data exists but no token — session expired, force re-login
      console.log("[Home] Found stored user but no JWT token — session expired, clearing")
      localStorage.removeItem("codio_user")
    } else {
      console.log("[Home] No stored user found")
    }
    
    setIsLoading(false)
  }, [])

  const handleLogin = async (email: string, name: string) => {
    console.log("[Home] handleLogin called for:", email)
    
    // Store user in localStorage
    const userData = { email, name }
    localStorage.setItem("codio_user", JSON.stringify(userData))
    console.log("[Home] User data stored in localStorage")
    
    setUser(userData)
    setIsLoggedIn(true)
    setActiveView("dashboard")
    console.log("[Home] Login complete")
  }

  const handleSignup = async (email: string, name: string) => {
    console.log("[Home] handleSignup called for:", email)
    
    // Store user in localStorage (already created in backend)
    const userData = { email, name }
    localStorage.setItem("codio_user", JSON.stringify(userData))
    console.log("[Home] User data stored in localStorage")
    
    setUser(userData)
    setIsLoggedIn(true)
    setActiveView("dashboard")
    console.log("[Home] Signup and login complete")
  }

  const handleLogout = () => {
    console.log("[Home] User logout initiated")
    
    // Clear JWT tokens
    clearTokens()
    console.log("[Home] JWT tokens cleared")
    
    // Clear user data
    localStorage.removeItem("codio_user")
    console.log("[Home] User data cleared from localStorage")
    
    setIsLoggedIn(false)
    setUser(null)
    setShowSignup(false) // Ensure we go to login screen, not signup
    setActiveView("login")
    console.log("[Home] Logout complete")
  }

  useEffect(() => {
    if (isLoading) {
      return
    }

    const nextView: "login" | "signup" | "dashboard" = isLoggedIn ? "dashboard" : showSignup ? "signup" : "login"
    if (nextView === activeView) {
      return
    }

    setIsViewExiting(true)
    const timer = setTimeout(() => {
      setActiveView(nextView)
      setIsViewExiting(false)
    }, 220)

    return () => clearTimeout(timer)
  }, [isLoading, isLoggedIn, showSignup, activeView])

  if (isLoading) {
    return (
      <main className="min-h-screen flex items-center justify-center px-4">
        <div className="surface-glass text-center rounded-2xl border border-border/60 px-8 py-10">
          <div className="float-soft mb-4 inline-flex h-16 w-16 items-center justify-center rounded-xl border border-primary/40 bg-primary/15">
            <div className="text-3xl font-bold text-primary">C</div>
          </div>
          <p className="text-muted-foreground">Preparing your interactive workspace...</p>
        </div>
      </main>
    )
  }

  return (
    <main className="min-h-screen">
      <div className="view-shell">
        <div className={`view-stage ${isViewExiting ? "is-exiting" : ""}`}>
          {activeView === "signup" ? (
            <SignupScreen
              onSignup={handleSignup}
              onSwitchToLogin={() => setShowSignup(false)}
            />
          ) : activeView === "dashboard" ? (
            <Dashboard user={user!} onLogout={handleLogout} />
          ) : (
            <LoginScreen
              onLogin={handleLogin}
              onSwitchToSignup={() => setShowSignup(true)}
            />
          )}
        </div>
      </div>
    </main>
  )
}
