/**
 * Codio Frontend - Shared TypeScript Types
 *
 * Centralized type definitions used across the application.
 * Extracted from inline types in components for better reusability.
 */

// ============================================================================
// Authentication
// ============================================================================

export interface User {
  email: string;
  name: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
}

// ============================================================================
// Video & Playlist
// ============================================================================

export interface PlaylistVideo {
  video_id: string;
  title: string;
  duration: number;
  thumbnail: string;
  url: string;
}

export interface Playlist {
  playlist_id: string;
  playlist_url: string;
  playlist_title: string;
  total_videos: number;
  completed_videos: number;
  progress_percentage: number;
  first_accessed: string;
  last_accessed: string;
}

export interface VideoStatus {
  status: string;
  video_id: string;
  video_title?: string;
  duration?: number;
  total_segments?: number;
}

export interface CodeSegment {
  start_time: number;
  end_time: number;
  code_content: string;
  segment_type: string;
  confidence: number;
  language: string;
}

// ============================================================================
// Transcript
// ============================================================================

export interface TranscriptMatch {
  text: string;
  start: number;
  duration: number;
  highlight_start: number;
  highlight_end: number;
}

// ============================================================================
// Concepts
// ============================================================================

export interface DetectedConcept {
  name: string;
  category: string;
  confidence: number;
  first_seen: number;
  description: string;
  related_code: string;
}

// ============================================================================
// Quiz
// ============================================================================

export interface QuizQuestion {
  id: string;
  type: "multiple_choice" | "true_false" | "fill_in_blank" | "output_prediction";
  difficulty: number;
  content: {
    question: string;
    options: string[];
    explanation: string;
    codeTemplate?: string;   // fill_in_blank: code with _____ placeholder
    codeSnippet?: string;    // output_prediction: code to analyze
  };
}

export interface QuizSession {
  session_id: string;
  first_question: QuizQuestion;
  current_level: number;
  learning_rate: number;
}

export interface QuizProgress {
  questionsAnswered: number;
  correctAnswers: number;
  shouldContinue: boolean;
  totalQuestions: number;
}

// ============================================================================
// Code Execution
// ============================================================================

export interface CodeExecutionResult {
  success: boolean;
  run: {
    code: number;
    stdout: string;
    stderr: string;
    output: string;
  };
  source?: string;
}

// ============================================================================
// API Responses
// ============================================================================

export interface ApiResponse<T = unknown> {
  success: boolean;
  error?: string;
  message?: string;
  data?: T;
}
