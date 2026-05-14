
import { getClientApiBaseCandidates } from "@/lib/backend-base";

declare const process: {
    env: {
        NEXT_PUBLIC_API_URL?: string;
        BACKEND_URL?: string;
        NEXT_PUBLIC_API_TIMEOUT_MS?: string;
    };
};

const REQUEST_TIMEOUT_MS = Number(process.env.NEXT_PUBLIC_API_TIMEOUT_MS || 300000); // 5 minutes for video processing

function getApiBaseCandidates(): string[] {
    return getClientApiBaseCandidates();
}

// Types for API responses
interface ApiResponse<T = any> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
}

export interface QuizQuestion {
    id: string;
    type: "multiple_choice" | "true_false" | "fill_in_blank" | "output_prediction";
    difficulty: number;
    content: {
        question: string;
        options: string[];
        explanation?: string;
        codeTemplate?: string;
        codeSnippet?: string;
    };
}

export interface QuizStartResponse {
    success: boolean;
    session_id: string;
    first_question: QuizQuestion;
    current_level: number;
    learning_rate: number;
}

export interface QuizSubmitResponse {
    success: boolean;
    is_correct: boolean;
    explanation: string;
    new_level: number;
    learning_rate: number;
    next_question?: QuizQuestion | null;
    should_continue: boolean;
    progress?: {
        questionsAnswered: number;
        correctAnswers: number;
        shouldContinue: boolean;
    };
}

export interface CodeExecutionResponse {
    success: boolean;
    run: {
        code: number;
        stdout?: string;
        stderr?: string;
        output?: string;
    };
    error?: string;
}

export interface CodeCompletionResponse {
    success: boolean;
    completion: string;
    source?: "gemini" | "fallback";
    error?: string;
}

export interface VideoStatusResponse {
    success: boolean;
    video_id: string;
    status: string;
    progress: number;
    stage?: string;
    current_frame?: number;
    total_frames?: number;
    transcript_available?: boolean;
}

export interface ProcessVideoResponse {
    success: boolean;
    video_id: string;
    title: string;
    duration: number;
    status: string;
    message: string;
    processing_time?: number;
    transcript_available?: boolean;
}

export const clearTokens = () => {
    if (typeof window !== 'undefined') {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
    }
};

export const setTokens = (accessToken: string, refreshToken: string) => {
    if (typeof window !== 'undefined') {
        localStorage.setItem("access_token", accessToken);
        localStorage.setItem("refresh_token", refreshToken);
    }
};

export const getAccessToken = () => {
    if (typeof window !== 'undefined') {
        return localStorage.getItem("access_token");
    }
    return null;
};

// Generic request handler
async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = getAccessToken();

    const headers: any = {
        "Content-Type": "application/json",
        ...options.headers,
    };

    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const config: RequestInit = {
        ...options,
        headers,
    };

    const maxAttempts = 2;
    let lastError: unknown;

    const baseCandidates = getApiBaseCandidates();

    for (const baseUrl of baseCandidates) {
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            const timeoutController = new AbortController();
            const timeoutId = setTimeout(() => timeoutController.abort(), REQUEST_TIMEOUT_MS);
            const requestConfig: RequestInit = {
                ...config,
                signal: options.signal || timeoutController.signal,
            };

            try {
                const response = await fetch(`${baseUrl}${endpoint}`, requestConfig);
                const rawText = await response.text();
                let data: any = {};
                try {
                    data = rawText ? JSON.parse(rawText) : {};
                } catch {
                    data = { message: rawText };
                }

                if (!response.ok) {
                    // Handle 401 Unauthorized - could redirect to login or clear tokens
                    if (response.status === 401) {
                        clearTokens();
                    }
                    throw new Error(
                        data.error ||
                        data.message ||
                        `API Error ${response.status} on ${endpoint}`
                    );
                }

                return data as T;
            } catch (error) {
                lastError = error;
                const failedToFetch = error instanceof TypeError && String(error.message || "").toLowerCase().includes("failed to fetch");
                const timedOut = error instanceof DOMException && error.name === "AbortError";

                if ((failedToFetch || timedOut) && attempt < maxAttempts) {
                    await new Promise((resolve) => setTimeout(resolve, 350));
                    continue;
                }

                if (timedOut || failedToFetch) {
                    // Try next base candidate.
                    break;
                }

                console.error(`API Request failed for ${endpoint}:`, error);
                throw error;
            } finally {
                clearTimeout(timeoutId);
            }
        }
    }

    if (lastError instanceof DOMException && lastError.name === "AbortError") {
        throw new Error(`Request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    }

    const deploymentHint = process.env.NODE_ENV === "production"
        ? "Set BACKEND_URL or NEXT_PUBLIC_API_URL to your deployed backend in Vercel."
        : "Ensure the backend is running on port 8080.";

    throw new Error(`Cannot reach backend at ${baseCandidates.join(" or ")}. ${deploymentHint}`);
}

export const api = {
    get: <T>(endpoint: string) => request<T>(endpoint, { method: "GET" }),

    post: <T>(endpoint: string, body: any) =>
        request<T>(endpoint, {
            method: "POST",
            body: JSON.stringify(body)
        }),

    put: <T>(endpoint: string, body: any) =>
        request<T>(endpoint, {
            method: "PUT",
            body: JSON.stringify(body)
        }),

    delete: <T>(endpoint: string) => request<T>(endpoint, { method: "DELETE" }),

    // Auth methods
    login: (email: string, password: string) =>
        request<any>("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email, password }),
        }),

    signup: (email: string, name: string, password: string) =>
        request<any>("/auth/signup", {
            method: "POST",
            body: JSON.stringify({ email, name, password }),
        }),

    // User Playlist methods
    getUserPlaylists: (email: string) =>
        request<any>(`/user/${encodeURIComponent(email)}/playlists`),

    deleteUserPlaylist: (email: string, playlistId: string) =>
        request<any>(`/user/${encodeURIComponent(email)}/playlist/${encodeURIComponent(playlistId)}`, { method: "DELETE" }),

    saveUserPlaylist: (email: string, playlistId: string, playlistUrl: string, playlistTitle: string, totalVideos: number) =>
        request<any>(`/user/playlist`, {
            method: "POST",
            body: JSON.stringify({
                user_email: email,
                playlist_id: playlistId,
                playlist_url: playlistUrl,
                playlist_title: playlistTitle,
                total_videos: totalVideos
            }),
        }),

    // Video Learning methods
    getPlaylistVideos: (playlistUrl: string) =>
        request<any>("/playlist/videos", {
            method: "POST",
            body: JSON.stringify({ playlist_url: playlistUrl }),
        }),

    getVideoStatus: (videoId: string) =>
        request<VideoStatusResponse>(`/video/${videoId}/status`),

    processVideo: (youtubeUrl: string) =>
        request<ProcessVideoResponse>("/video/process", {
            method: "POST",
            body: JSON.stringify({ youtube_url: youtubeUrl }),
        }),

    cancelVideoProcessing: (videoId: string) =>
        request<any>(`/video/${videoId}/cancel`, { method: "POST" }),

    getFrameAtTimestamp: (videoId: string, timestamp: number) =>
        request<any>(`/video/${videoId}/frame?timestamp=${timestamp}`),

    executePythonCode: (code: string) =>
        request<CodeExecutionResponse>(`/code/execute`, {
            method: "POST",
            body: JSON.stringify({ code }),
        }),

    completePythonCode: (code: string, cursorPosition: number) =>
        request<CodeCompletionResponse>(`/code/complete`, {
            method: "POST",
            body: JSON.stringify({
                code,
                cursor_position: cursorPosition,
            }),
        }),

    // Progress methods
    getPlaylistProgress: (email: string, playlistId: string) =>
        request<any>(`/user/${encodeURIComponent(email)}/playlist/${encodeURIComponent(playlistId)}/progress`),

    saveVideoProgress: (email: string, playlistId: string, videoId: string, watchedSeconds: number, videoDuration: number, completed: boolean) =>
        request<any>(`/user/progress`, {
            method: "POST",
            body: JSON.stringify({
                user_email: email,
                playlist_id: playlistId,
                video_id: videoId,
                watched_seconds: watchedSeconds,
                duration: videoDuration,
                completed: completed
            }),
        }),

    // Transcript search methods
    searchTranscript: (videoId: string, query: string, caseSensitive?: boolean) =>
        request<any>(`/video/${videoId}/transcript/search?query=${encodeURIComponent(query)}${caseSensitive ? '&case_sensitive=true' : ''}`, {
            signal: new AbortController().signal // Don't timeout transcript search
        }),

    extractTranscript: (videoId: string) =>
        request<any>(`/video/${videoId}/transcript/extract`, {
            method: "POST",
        }),

    getFullTranscript: (videoId: string) =>
        request<any>(`/video/${videoId}/transcript`),

    // English transcript (translation) methods
    searchEnglishTranscript: (videoId: string, query: string, caseSensitive?: boolean) =>
        request<any>(`/video/${videoId}/transcript/english/search?query=${encodeURIComponent(query)}${caseSensitive ? '&case_sensitive=true' : ''}`, {
            signal: new AbortController().signal
        }),

    getEnglishTranscript: (videoId: string) =>
        request<any>(`/video/${videoId}/transcript/english`),

    // Concept detection methods
    getDetectedConcepts: (videoId: string) =>
        request<any>(`/video/${videoId}/concepts`),

    detectConcepts: (videoId: string) =>
        request<any>(`/video/${videoId}/concepts/detect`, {
            method: "POST",
        }),

    // Quiz methods
    startQuiz: (userEmail: string, transcript: string, videoId?: string) =>
        request<QuizStartResponse>(`/quiz/start`, {
            method: "POST",
            body: JSON.stringify({
                user_email: userEmail,
                transcript,
                video_id: videoId
            }),
        }),

    submitQuizAnswer: (sessionId: string, questionId: string, answer: number | string | boolean, timeTaken: number) =>
        request<QuizSubmitResponse>(`/quiz/submit-answer`, {
            method: "POST",
            body: JSON.stringify({
                session_id: sessionId,
                question_id: questionId,
                answer,
                time_taken: timeTaken
            }),
        }),

    getQuizSessionStatus: (sessionId: string) =>
        request<any>(`/quiz/session/${sessionId}`),

    endQuizSession: (sessionId: string) =>
        request<any>(`/quiz/end-session/${sessionId}`, {
            method: "POST",
        }),

    // YouTube Search (uses Next.js proxy route to avoid CORS)
    searchYouTube: async (query: string): Promise<any> => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000);
        try {
            const res = await fetch(`/api/youtube/search?q=${encodeURIComponent(query)}`, {
                signal: controller.signal,
            });
            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.error || `Search failed with status ${res.status}`);
            }
            return data;
        } catch (err: any) {
            if (err.name === "AbortError") {
                throw new Error("Search timed out. Please try again.");
            }
            throw err;
        } finally {
            clearTimeout(timeoutId);
        }
    },

    // Dashboard stats
    getUserDashboard: (email: string) =>
        request<any>(`/admin/dashboard/${encodeURIComponent(email)}`),

    // Admin endpoints
    getAdminStats: () =>
        request<any>('/admin/stats'),
    getAdminUsers: () =>
        request<any>('/admin/users'),
    getAdminUserStats: (email: string) =>
        request<any>(`/admin/user/${encodeURIComponent(email)}/stats`),

    // Enhanced endpoints
    getEnhancedAdminStats: () =>
        request<any>('/admin/enhanced-stats'),
    getEnhancedUserDashboard: (email: string) =>
        request<any>(`/admin/enhanced-dashboard/${encodeURIComponent(email)}`),

    // Admin User Management
    toggleUserStatus: (email: string, status: string) =>
        request<any>(`/admin/user/${encodeURIComponent(email)}/toggle-status`, {
            method: 'POST',
            body: JSON.stringify({ status }),
        }),
    updateUserRole: (email: string, role: string) =>
        request<any>(`/admin/user/${encodeURIComponent(email)}/role`, {
            method: 'POST',
            body: JSON.stringify({ role }),
        }),
    deleteUser: (email: string) =>
        request<any>(`/admin/user/${encodeURIComponent(email)}`, { method: 'DELETE' }),

    // Admin Subscriptions & Billing
    getSubscriptions: () =>
        request<any>('/admin/subscriptions'),
    getBillingOverview: () =>
        request<any>('/admin/billing/overview'),
    updateSubscription: (email: string, plan: string) =>
        request<any>(`/admin/subscription/${encodeURIComponent(email)}/update`, {
            method: 'POST',
            body: JSON.stringify({ plan }),
        }),

    // Admin Certificates
    getCertificates: () =>
        request<any>('/admin/certificates'),
    issueCertificate: (userEmail: string, courseTitle: string, playlistId?: string) =>
        request<any>('/admin/certificate/issue', {
            method: 'POST',
            body: JSON.stringify({ user_email: userEmail, course_title: courseTitle, playlist_id: playlistId || '' }),
        }),
    revokeCertificate: (certId: string) =>
        request<any>(`/admin/certificate/${encodeURIComponent(certId)}/revoke`, { method: 'POST' }),

    // Admin Course Management
    getAdminCourses: () =>
        request<any>('/admin/courses'),
    toggleCourseStatus: (playlistId: string, status: string) =>
        request<any>(`/admin/course/${encodeURIComponent(playlistId)}/toggle`, {
            method: 'POST',
            body: JSON.stringify({ status }),
        }),

    // Admin Analytics
    getEngagementAnalytics: () =>
        request<any>('/admin/analytics/engagement'),
    exportAnalytics: () =>
        request<any>('/admin/analytics/export'),

    // ── Enhancement APIs ─────────────────────────────────────────

    // Bookmarks
    getBookmarks: (videoId: string) =>
        request<any>(`/video/${videoId}/bookmarks`),
    addBookmark: (videoId: string, timestamp: number, note?: string) =>
        request<any>(`/video/${videoId}/bookmark`, {
            method: 'POST',
            body: JSON.stringify({ timestamp, note: note || '' }),
        }),
    deleteBookmark: (bookmarkId: string) =>
        request<any>(`/bookmark/${bookmarkId}`, { method: 'DELETE' }),

    // Video Notes
    getVideoNotes: (videoId: string) =>
        request<any>(`/video/${videoId}/notes`),
    saveVideoNote: (videoId: string, content: string, timestamp?: number, noteId?: string) =>
        request<any>(`/video/${videoId}/note`, {
            method: 'POST',
            body: JSON.stringify({ content, timestamp, note_id: noteId }),
        }),
    deleteVideoNote: (noteId: string) =>
        request<any>(`/note/${noteId}`, { method: 'DELETE' }),

    // Code History
    getCodeHistory: (videoId?: string, limit?: number) =>
        request<any>(`/code/history?${videoId ? `video_id=${videoId}&` : ''}limit=${limit || 20}`),
    saveCodeRun: (videoId: string, code: string, output?: string, error?: string) =>
        request<any>('/code/save-run', {
            method: 'POST',
            body: JSON.stringify({ video_id: videoId, code, output: output || '', error: error || '' }),
        }),

    // Notifications
    getNotifications: (unreadOnly?: boolean) =>
        request<any>(`/notifications${unreadOnly ? '?unread=true' : ''}`),
    markNotificationRead: (notificationId: string) =>
        request<any>(`/notification/${notificationId}/read`, { method: 'POST' }),
    markAllNotificationsRead: () =>
        request<any>('/notifications/read-all', { method: 'POST' }),

    // Goals
    getUserGoals: () =>
        request<any>('/user/goals'),
    updateUserGoals: (goals: { weekly_minutes_target?: number; weekly_videos_target?: number; weekly_quizzes_target?: number }) =>
        request<any>('/user/goals', {
            method: 'POST',
            body: JSON.stringify(goals),
        }),

    // Activity Heatmap
    getActivityHeatmap: (days?: number) =>
        request<any>(`/user/activity-heatmap?days=${days || 90}`),

    // Leaderboard
    getLeaderboard: (limit?: number) =>
        request<any>(`/leaderboard?limit=${limit || 10}`),

    // Preferences
    getUserPreferences: () =>
        request<any>('/user/preferences'),
    updateUserPreferences: (prefs: Record<string, any>) =>
        request<any>('/user/preferences', {
            method: 'POST',
            body: JSON.stringify(prefs),
        }),

    // Quiz History & Review
    getQuizHistory: (limit?: number) =>
        request<any>(`/quiz/history?limit=${limit || 20}`),
    getQuizReview: (sessionId: string) =>
        request<any>(`/quiz/review/${sessionId}`),

    // AI Error Explanation
    explainError: (code: string, error: string) =>
        request<any>('/code/explain-error', {
            method: 'POST',
            body: JSON.stringify({ code, error }),
        }),

    // AI Transcript Summary
    getTranscriptSummary: (videoId: string, transcript: string) =>
        request<any>(`/video/${videoId}/transcript/summary`, {
            method: 'POST',
            body: JSON.stringify({ transcript }),
        }),

    // AI Study Recommendations
    getRecommendations: () =>
        request<any>('/user/recommendations'),

    // AI Summary (fetches transcript internally then generates summary)
    getAiSummary: async (videoId: string): Promise<any> => {
        try {
            // First get the transcript
            const transcriptRes = await request<any>(`/video/${videoId}/transcript`);
            if (!transcriptRes.success || !transcriptRes.transcript) {
                return { success: false, error: 'No transcript available' };
            }
            // Then generate summary
            const summaryRes = await request<any>(`/video/${videoId}/transcript/summary`, {
                method: 'POST',
                body: JSON.stringify({ transcript: transcriptRes.transcript }),
            });
            if (summaryRes.success && summaryRes.summary) {
                // Parse the summary to extract key points
                const lines = summaryRes.summary.split('\n');
                const keyPoints: string[] = [];
                let summary = '';
                let inKeyPoints = false;
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (trimmed.toLowerCase().includes('key point') || trimmed.toLowerCase().includes('key term')) {
                        inKeyPoints = true;
                        continue;
                    }
                    if (inKeyPoints && (trimmed.startsWith('-') || trimmed.startsWith('*') || /^\d+\./.test(trimmed))) {
                        keyPoints.push(trimmed.replace(/^[-*\d.]+\s*\**/, '').replace(/\**/g, '').trim());
                    } else if (trimmed.toLowerCase().includes('summary') && !inKeyPoints) {
                        continue;
                    } else if (!inKeyPoints && trimmed.length > 10) {
                        summary += (summary ? ' ' : '') + trimmed.replace(/\**/g, '');
                    }
                }
                return { success: true, summary: summary || summaryRes.summary, key_points: keyPoints };
            }
            return summaryRes;
        } catch (error: any) {
            return { success: false, error: error.message };
        }
    },
};
