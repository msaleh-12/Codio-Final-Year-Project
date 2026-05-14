const LOCAL_BACKEND_BASES = [
  "http://127.0.0.1:8080/api/v1",
  "http://localhost:8080/api/v1",
]

function getConfiguredBackendBase() {
  return process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL || ""
}

function uniqueBases(values: Array<string | undefined | null>) {
  return Array.from(
    new Set(
      values.filter((value): value is string => Boolean(value && value.trim()))
    )
  )
}

export function getClientApiBaseCandidates() {
  const candidates = ["/api/v1", getConfiguredBackendBase()]

  if (typeof window !== "undefined") {
    const host = window.location.hostname
    if (host === "localhost" || host === "127.0.0.1") {
      candidates.push(...LOCAL_BACKEND_BASES)
    }
  }

  return uniqueBases(candidates)
}

export function getServerApiBaseCandidates(origin?: string) {
  const candidates = [getConfiguredBackendBase()]

  if (origin) {
    candidates.push(`${origin}/api/v1`)
  }

  if (process.env.NODE_ENV !== "production") {
    candidates.push(...LOCAL_BACKEND_BASES)
  }

  return uniqueBases(candidates)
}
