"use client"

import { useState, useEffect } from "react"
import LoginScreen from "@/components/auth/login-screen"
import SignupScreen from "@/components/auth/signup-screen"
import Dashboard from "@/components/dashboard/dashboard"
import { api, clearTokens } from "@/lib/api"

export default function Home() {
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [user, setUser] = useState<{ email: string; name: string } | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [showSignup, setShowSignup] = useState(false)

  // Check for existing session on mount
  useEffect(() => {
    const checkSession = async () => {
      console.log("[Home] Checking for existing user session...")
      
      // Check if server has restarted
      try {
        const response = await fetch('http://localhost:8080/health')
        const data = await response.json()
        const serverStartTime = data.server_start_time
        
        // Get stored server start time
        const storedStartTime = localStorage.getItem('codio_server_start_time')
        
        if (storedStartTime && storedStartTime !== serverStartTime) {
          // Server restarted - clear session
          console.log("[Home] Server restarted detected - clearing session")
          clearTokens()
          localStorage.removeItem("codio_user")
          localStorage.setItem('codio_server_start_time', serverStartTime)
          setIsLoading(false)
          return
        }
        
        // Store current server start time
        if (!storedStartTime) {
          localStorage.setItem('codio_server_start_time', serverStartTime)
        }
      } catch (error) {
        console.error("[Home] Error checking server status:", error)
      }
      
      const storedUser = localStorage.getItem("codio_user")
      
      if (storedUser) {
        try {
          const userData = JSON.parse(storedUser)
          console.log("[Home] Found stored user:", userData.email)
          setUser(userData)
          setIsLoggedIn(true)
        } catch (error) {
          console.error("[Home] Error parsing stored user:", error)
          localStorage.removeItem("codio_user")
        }
      } else {
        console.log("[Home] No stored user found")
      }
      
      setIsLoading(false)
    }
    
    checkSession()
  }, [])

  const handleLogin = async (email: string, name: string) => {
    console.log("[Home] handleLogin called for:", email)
    
    // Store user in localStorage
    const userData = { email, name }
    localStorage.setItem("codio_user", JSON.stringify(userData))
    console.log("[Home] User data stored in localStorage")
    
    setUser(userData)
    setIsLoggedIn(true)
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
    console.log("[Home] Logout complete")
  }

  if (isLoading) {
    return (
      <main className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-lg bg-primary/10 mb-4 animate-pulse">
            <div className="text-3xl font-bold text-primary">C</div>
          </div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </main>
    )
  }

  return (
    <main className="min-h-screen bg-background">
      {!isLoggedIn ? (
        showSignup ? (
          <SignupScreen 
            onSignup={handleSignup} 
            onSwitchToLogin={() => setShowSignup(false)} 
          />
        ) : (
          <LoginScreen 
            onLogin={handleLogin} 
            onSwitchToSignup={() => setShowSignup(true)} 
          />
        )
      ) : (
        <Dashboard user={user!} onLogout={handleLogout} />
      )}
    </main>
  )
}
