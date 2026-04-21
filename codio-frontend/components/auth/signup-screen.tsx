"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { Sparkles, Layers3, WandSparkles } from "lucide-react"
import { api, setTokens } from "@/lib/api"

interface SignupScreenProps {
  onSignup: (email: string, name: string) => void
  onSwitchToLogin: () => void
}

export default function SignupScreen({ onSignup, onSwitchToLogin }: SignupScreenProps) {
  const [email, setEmail] = useState("")
  const [name, setName] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  const validateEmail = (nextEmail: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(nextEmail)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setSuccess("")
    console.log("[SignupScreen] Form submitted")

    if (!name.trim()) {
      setError("Please enter your name")
      return
    }

    if (name.trim().length < 2) {
      setError("Name must be at least 2 characters")
      return
    }

    if (!email.trim()) {
      setError("Please enter your email")
      return
    }

    if (!validateEmail(email)) {
      setError("Please enter a valid email address")
      return
    }

    if (!password) {
      setError("Please enter a password")
      return
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters")
      return
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match")
      return
    }

    setIsLoading(true)
    console.log("[SignupScreen] Creating account for:", email)

    try {
      const response = await api.signup(email.toLowerCase().trim(), name.trim(), password)
      console.log("[SignupScreen] Signup response:", response)

      if (response.success) {
        console.log("[SignupScreen] Account created successfully")
        setSuccess("Account created successfully! Logging you in...")

        if (response.access_token && response.refresh_token) {
          console.log("[SignupScreen] Storing JWT tokens")
          setTokens(response.access_token, response.refresh_token)
          console.log("[SignupScreen] Tokens stored successfully")
        }

        setTimeout(() => {
          onSignup(email.toLowerCase().trim(), name.trim())
        }, 1500)
      } else {
        console.error("[SignupScreen] Signup failed:", response.error)
        setError(response.error || "Failed to create account")
      }
    } catch (err: any) {
      console.error("[SignupScreen] Exception during signup:", err)
      setError(err?.message || "An error occurred. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen px-4 py-10 sm:py-16">
      <div className="mx-auto grid w-full max-w-6xl items-center gap-8 lg:grid-cols-[1.02fr_0.98fr]">
        <section className="stagger-in space-y-5">
          <div className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.13em] text-primary">
            <Sparkles className="h-3.5 w-3.5" />
            Build Your Learning Base
          </div>

          <h1 className="glow-title text-balance text-4xl font-semibold leading-tight text-foreground sm:text-5xl">
            Create Your Codio Profile and Enter Interactive Learning Mode
          </h1>

          <p className="max-w-xl text-pretty text-muted-foreground sm:text-lg">
            Set up once and keep your playlists, progress, and adaptive quiz results connected across every coding session.
          </p>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="interactive-lift surface-glass rounded-2xl p-4">
              <Layers3 className="mb-2 h-5 w-5 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">Saved Learning Paths</h3>
              <p className="text-xs text-muted-foreground">Your playlists and completion status persist automatically.</p>
            </div>
            <div className="interactive-lift surface-glass rounded-2xl p-4">
              <WandSparkles className="mb-2 h-5 w-5 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">Adaptive Skill Growth</h3>
              <p className="text-xs text-muted-foreground">Quiz difficulty and recommendations evolve with performance.</p>
            </div>
          </div>
        </section>

        <div className="stagger-in" style={{ animationDelay: "90ms" }}>
          <Card className="surface-glass border-border/60 p-7 shadow-xl sm:p-8">
            <div className="mb-6 text-center">
              <div className="float-soft mb-3 inline-flex h-14 w-14 items-center justify-center rounded-xl border border-primary/40 bg-primary/15">
                <div className="text-2xl font-bold text-primary">C</div>
              </div>
              <h2 className="text-2xl font-semibold text-foreground">Create Account</h2>
              <p className="text-sm text-muted-foreground">Join Codio and start your first interactive session</p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="name" className="mb-2 block text-sm font-medium text-foreground">
                  Full Name
                </label>
                <Input
                  id="name"
                  type="text"
                  placeholder="Muhammad Saleh"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={isLoading}
                  className="h-11 border-border/60 bg-background/65"
                />
              </div>

              <div>
                <label htmlFor="email" className="mb-2 block text-sm font-medium text-foreground">
                  Email
                </label>
                <Input
                  id="email"
                  type="email"
                  placeholder="student@codio.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={isLoading}
                  className="h-11 border-border/60 bg-background/65"
                />
              </div>

              <div>
                <label htmlFor="password" className="mb-2 block text-sm font-medium text-foreground">
                  Password
                </label>
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isLoading}
                  className="h-11 border-border/60 bg-background/65"
                />
                <p className="mt-1 text-xs text-muted-foreground">At least 6 characters</p>
              </div>

              <div>
                <label htmlFor="confirmPassword" className="mb-2 block text-sm font-medium text-foreground">
                  Confirm Password
                </label>
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={isLoading}
                  className="h-11 border-border/60 bg-background/65"
                />
              </div>

              {error && (
                <div className="rounded-lg border border-destructive/25 bg-destructive/10 p-3 text-sm text-destructive">
                  {error}
                </div>
              )}

              {success && (
                <div className="rounded-lg border border-green-500/25 bg-green-500/10 p-3 text-sm text-green-600">
                  {success}
                </div>
              )}

              <Button
                type="submit"
                disabled={isLoading || !email || !password || !name || !confirmPassword}
                className="h-11 w-full bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
              >
                {isLoading ? "Creating Account..." : "Create Account"}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-sm text-muted-foreground">
                Already have an account?{" "}
                <button
                  onClick={onSwitchToLogin}
                  className="font-medium text-primary hover:underline"
                  disabled={isLoading}
                >
                  Login here
                </button>
              </p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
