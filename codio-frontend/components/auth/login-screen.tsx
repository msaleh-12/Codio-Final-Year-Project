"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { Sparkles, ShieldCheck, Rocket } from "lucide-react"
import { api, setTokens } from "@/lib/api"

interface LoginScreenProps {
  onLogin: (email: string, name: string) => void
  onSwitchToSignup: () => void
}

export default function LoginScreen({ onLogin, onSwitchToSignup }: LoginScreenProps) {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setIsLoading(true)
    console.log("[LoginScreen] Attempting login for:", email)

    try {
      const response = await api.login(email.toLowerCase().trim(), password)
      console.log("[LoginScreen] Login response:", response)

      if (response.success && response.user) {
        console.log("[LoginScreen] Login successful")

        if (response.access_token && response.refresh_token) {
          console.log("[LoginScreen] Storing JWT tokens")
          setTokens(response.access_token, response.refresh_token)
          console.log("[LoginScreen] Tokens stored successfully")
        } else {
          console.warn("[LoginScreen] No tokens received in response")
        }

        onLogin(response.user.email, response.user.name)
      } else {
        console.error("[LoginScreen] Login failed:", response.error)
        setError(response.error || "Invalid credentials")
      }
    } catch (err: any) {
      console.error("[LoginScreen] Exception during login:", err)
      setError(err?.message || "Failed to connect to server")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen px-4 py-10 sm:py-16">
      <div className="mx-auto grid w-full max-w-6xl items-center gap-8 lg:grid-cols-[1.08fr_0.92fr]">
        <section className="stagger-in space-y-5">
          <div className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.13em] text-primary">
            <Sparkles className="h-3.5 w-3.5" />
            Real Learning Momentum
          </div>

          <h1 className="glow-title text-balance text-4xl font-semibold leading-tight text-foreground sm:text-5xl">
            Codio Makes Tutorial Videos Feel Like Interactive Labs
          </h1>

          <p className="max-w-xl text-pretty text-muted-foreground sm:text-lg">
            Sign in to launch your command center for pause-to-code extraction, live practice, and adaptive quizzes connected to every video you watch.
          </p>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="interactive-lift surface-glass rounded-2xl p-4">
              <ShieldCheck className="mb-2 h-5 w-5 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">Secure Session</h3>
              <p className="text-xs text-muted-foreground">JWT-protected access with smooth re-entry into your saved playlists.</p>
            </div>
            <div className="interactive-lift surface-glass rounded-2xl p-4">
              <Rocket className="mb-2 h-5 w-5 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">Instant Resume</h3>
              <p className="text-xs text-muted-foreground">Jump straight back into your current learning flow and progress state.</p>
            </div>
          </div>
        </section>

        <div className="stagger-in" style={{ animationDelay: "90ms" }}>
          <Card className="surface-glass border-border/60 p-7 shadow-xl sm:p-8">
            <div className="mb-6 text-center">
              <div className="float-soft mb-3 inline-flex h-14 w-14 items-center justify-center rounded-xl border border-primary/40 bg-primary/15">
                <div className="text-2xl font-bold text-primary">C</div>
              </div>
              <h2 className="text-2xl font-semibold text-foreground">Welcome Back</h2>
              <p className="text-sm text-muted-foreground">Enter your account credentials to continue</p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
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
              </div>

              {error && (
                <div className="rounded-lg border border-destructive/25 bg-destructive/10 p-3 text-sm text-destructive">
                  {error}
                </div>
              )}

              <Button
                type="submit"
                disabled={isLoading || !email || !password}
                className="h-11 w-full bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
              >
                {isLoading ? "Signing in..." : "Sign In"}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-sm text-muted-foreground">
                Don&apos;t have an account?{" "}
                <button
                  onClick={onSwitchToSignup}
                  className="font-medium text-primary hover:underline"
                  disabled={isLoading}
                >
                  Sign up here
                </button>
              </p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
