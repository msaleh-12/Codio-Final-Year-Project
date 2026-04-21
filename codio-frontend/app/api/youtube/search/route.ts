import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const query = req.nextUrl.searchParams.get("q") || "";

  if (!query.trim()) {
    return NextResponse.json(
      { success: false, error: "Query parameter 'q' is required" },
      { status: 400 }
    );
  }

  try {
    const backendBases = [
      `${req.nextUrl.origin}/api/v1`,
      process.env.NEXT_PUBLIC_API_URL || "",
      "http://127.0.0.1:8080/api/v1",
      "http://localhost:8080/api/v1",
    ].filter(Boolean) as string[];

    let lastError: unknown = null;

    for (const backendBase of backendBases) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);

      try {
        const res = await fetch(
          `${backendBase}/youtube/search?q=${encodeURIComponent(query)}`,
          { signal: controller.signal }
        );

        const data = await res.json();

        if (!res.ok) {
          lastError = data;
          continue;
        }

        return NextResponse.json(data);
      } catch (err: any) {
        lastError = err;
      } finally {
        clearTimeout(timeoutId);
      }
    }

    console.error("[youtube/search proxy] Error:", (lastError as any)?.message || lastError);
    return NextResponse.json(
      { success: false, error: "Failed to search YouTube" },
      { status: 500 }
    );
  } catch (err: any) {
    console.error("[youtube/search proxy] Error:", err?.message || err);
    return NextResponse.json(
      { success: false, error: "Failed to search YouTube" },
      { status: 500 }
    );
  }
}
