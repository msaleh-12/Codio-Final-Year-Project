/**
 * Codio Frontend - Application Constants
 *
 * Centralized configuration constants used across the application.
 * Values are read from environment variables where applicable.
 */

// ============================================================================
// API Configuration
// ============================================================================

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

export const API_ENDPOINTS = {
  // Auth
  AUTH_SIGNUP: "/api/v1/auth/signup",
  AUTH_LOGIN: "/api/v1/auth/login",
  AUTH_REFRESH: "/api/v1/auth/refresh",

  // Video
  VIDEO_PROCESS: "/api/v1/video/process",
  VIDEO_STATUS: (videoId: string) => `/api/v1/video/${videoId}/status`,
  VIDEO_FRAME: (videoId: string) => `/api/v1/video/${videoId}/frame`,
  VIDEO_SEGMENTS: (videoId: string) => `/api/v1/video/${videoId}/segments`,
  VIDEO_INFO: (videoId: string) => `/api/v1/video/${videoId}/info`,

  // Playlist
  PLAYLIST_VIDEOS: "/api/v1/playlist/videos",

  // Transcript
  TRANSCRIPT: (videoId: string) => `/api/v1/video/${videoId}/transcript`,
  TRANSCRIPT_SEARCH: (videoId: string) =>
    `/api/v1/video/${videoId}/transcript/search`,
  TRANSCRIPT_EXTRACT: (videoId: string) =>
    `/api/v1/video/${videoId}/transcript/extract`,

  // Concepts
  CONCEPTS: (videoId: string) => `/api/v1/video/${videoId}/concepts`,
  CONCEPTS_DETECT: (videoId: string) =>
    `/api/v1/video/${videoId}/concepts/detect`,

  // Code
  CODE_EXECUTE: "/api/v1/code/execute",
  CODE_COMPLETE: "/api/v1/code/complete",

  // User
  USER_PLAYLISTS: (email: string) => `/api/v1/user/${email}/playlists`,
  USER_PLAYLIST_SAVE: "/api/v1/user/playlist",
  USER_PROGRESS_SAVE: "/api/v1/user/progress",
  USER_PLAYLIST_PROGRESS: (email: string, playlistId: string) =>
    `/api/v1/user/${email}/playlist/${playlistId}/progress`,
  USER_PLAYLIST_DELETE: (email: string, playlistId: string) =>
    `/api/v1/user/${email}/playlist/${playlistId}`,

  // Quiz
  QUIZ_START: "/api/v1/quiz/start",
  QUIZ_SUBMIT: "/api/v1/quiz/submit-answer",
  QUIZ_SESSION: (sessionId: string) => `/api/v1/quiz/session/${sessionId}`,
  QUIZ_END: (sessionId: string) => `/api/v1/quiz/end-session/${sessionId}`,

  // Health
  HEALTH: "/health",
} as const;

// ============================================================================
// Application Settings
// ============================================================================

export const APP_NAME = "Codio";
export const APP_DESCRIPTION =
  "AI-Powered Interactive Coding Education Platform";

// ============================================================================
// Local Storage Keys
// ============================================================================

export const STORAGE_KEYS = {
  ACCESS_TOKEN: "codio_access_token",
  REFRESH_TOKEN: "codio_refresh_token",
  USER_DATA: "codio_user_data",
} as const;

// ============================================================================
// UI Constants
// ============================================================================

export const SIDEBAR_WIDTH = 320;
export const VIDEO_PLAYER_ASPECT_RATIO = 16 / 9;
export const CODE_EDITOR_MIN_HEIGHT = 200;
export const QUIZ_TOTAL_QUESTIONS = 10;
