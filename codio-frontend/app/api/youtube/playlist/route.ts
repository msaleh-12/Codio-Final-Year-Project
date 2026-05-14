import { type NextRequest, NextResponse } from "next/server"
import { getServerApiBaseCandidates } from "@/lib/backend-base"

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const playlistId = searchParams.get("playlistId")
  const playlistUrl = searchParams.get("playlistUrl")

  if (!playlistId && !playlistUrl) {
    return NextResponse.json({ error: "Missing playlistId or playlistUrl" }, { status: 400 })
  }

  const resolvedUrl = playlistUrl || `https://www.youtube.com/playlist?list=${playlistId}`

  try {
    const backendBases = getServerApiBaseCandidates(request.nextUrl.origin)

    let lastError: unknown = null

    for (const backendBase of backendBases) {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 15000)

      try {
        const response = await fetch(`${backendBase}/playlist/videos`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ playlist_url: resolvedUrl }),
          signal: controller.signal,
        })

        const data = await response.json()

        if (!response.ok) {
          lastError = data
          continue
        }

        const videos = (data?.videos || []).map((item: any) => ({
          id: item.video_id || item.id,
          title: item.title,
          description: item.description || "",
          thumbnail: item.thumbnail || "",
        }))

        return NextResponse.json({ videos })
      } catch (error) {
        lastError = error
      } finally {
        clearTimeout(timeoutId)
      }
    }

    console.error("Error fetching YouTube playlist:", lastError)
    return NextResponse.json({ error: "Failed to fetch playlist" }, { status: 500 })
  } catch (error) {
    console.error("Error fetching YouTube playlist:", error)
    return NextResponse.json({ error: "Failed to fetch playlist" }, { status: 500 })
  }
}
