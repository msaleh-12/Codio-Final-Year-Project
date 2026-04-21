# Codio — AI-Powered Interactive Coding Education Platform

Codio is a full-stack web application that transforms YouTube programming tutorials into interactive, hands-on coding experiences. It uses **Gemini Vision AI** to extract code from video frames in real-time, enabling a unique "Pause-to-Code" workflow where students can pause a tutorial, edit the extracted code, and run it — all within a single interface.

---

## Project Structure

```
Codio/
├── codio-backend/              # Python Flask REST API
│   ├── run.py                  # Application entry point (Flask app factory)
│   ├── config/                 # Centralized configuration
│   │   ├── settings.py         # Environment variables & constants
│   │   └── logging.py          # Logging setup
│   ├── app/
│   │   ├── models/
│   │   │   └── database.py     # SQLite database (CodioDatabase class)
│   │   ├── routes/             # Flask Blueprints (organized by domain)
│   │   │   ├── auth.py         # Signup, Login, Token Refresh
│   │   │   ├── video.py        # Video processing, status, playlists, transcripts, concepts
│   │   │   ├── code.py         # Code execution proxy & AI completion
│   │   │   ├── user.py         # User playlists & progress tracking
│   │   │   └── quiz.py         # Adaptive quiz sessions
│   │   ├── services/           # Business logic (separated by concern)
│   │   │   ├── pause_to_code.py       # Orchestrator (PauseToCodeService)
│   │   │   ├── video_processing.py    # YouTube download, transcript extraction
│   │   │   ├── gemini_extractor.py    # Gemini Vision AI code extraction
│   │   │   ├── concept_detection.py   # AI-powered concept detection
│   │   │   ├── code_execution.py      # Piston API proxy + local fallback
│   │   │   └── quiz_service.py        # Quiz question generation
│   │   └── utils/              # Shared utilities
│   │       ├── jwt_auth.py     # JWT token management & middleware
│   │       └── helpers.py      # Sanitization, normalization helpers
│   ├── tests/                  # Test directory (ready for pytest)
│   ├── requirements.txt        # Python dependencies
│   ├── .env.example            # Environment variable template
│   └── .gitignore
│
├── codio-frontend/             # Next.js 14 React Application
│   ├── app/                    # Next.js App Router
│   │   ├── layout.tsx          # Root layout
│   │   ├── page.tsx            # Entry page (auth gate)
│   │   └── api/youtube/        # Server-side API route
│   ├── components/
│   │   ├── auth/               # Login & Signup screens
│   │   ├── dashboard/          # Dashboard, playlist input, learning view
│   │   ├── learning/           # Video player, code editor, quiz, transcript, concepts
│   │   └── ui/                 # Reusable UI primitives (shadcn/ui)
│   ├── config/
│   │   └── constants.ts        # API endpoints & app constants
│   ├── types/
│   │   └── index.ts            # Shared TypeScript interfaces
│   ├── hooks/                  # Custom React hooks
│   ├── lib/                    # API client & utility functions
│   ├── styles/                 # Global CSS
│   └── public/                 # Static assets
│
└── README.md                   # This file
```

---

## Key Features

| Feature | Description |
|---|---|
| **Pause-to-Code** | Pause any YouTube tutorial and instantly get editable code extracted from the video frame via Gemini Vision AI |
| **Integrated Code Editor** | Monaco-based Python editor with syntax highlighting, AI auto-completion, and one-click execution |
| **Adaptive Quiz System** | AI-generated quizzes that adjust difficulty based on student performance |
| **Transcript Search** | Full-text search across video transcripts with timestamp navigation |
| **Concept Detection** | Automatic identification of programming concepts (variables, loops, functions, etc.) from video content |
| **Playlist Management** | Import YouTube playlists, track progress across videos, and resume where you left off |
| **JWT Authentication** | Secure signup/login with access and refresh token flow |

---

## Getting Started

### Prerequisites

- **Python 3.10+** (backend)
- **Node.js 18+** (frontend)
- **Google Gemini API Key** (for AI features)

### Backend Setup

```bash
cd codio-backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your GEMINI_API_KEY and JWT_SECRET_KEY

# Start the server
python run.py
```

The API will be available at `http://localhost:8080`.

### Frontend Setup

```bash
cd codio-frontend

# Install dependencies
npm install

# Configure environment
# Edit .env.local — set NEXT_PUBLIC_API_URL to your backend URL

# Start development server
npm run dev
```

The app will be available at `http://localhost:3000`.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Next.js Frontend                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │   Auth    │  │Dashboard │  │ Learning │  │  Quiz   │ │
│  │  Screens  │  │  View    │  │   View   │  │  Panel  │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│       └──────────────┴─────────────┴─────────────┘       │
│                         │ REST API                        │
└─────────────────────────┼───────────────────────────────┘
                          │
┌─────────────────────────┼───────────────────────────────┐
│                  Flask Backend                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │   Auth   │  │  Video   │  │   Code   │  │  Quiz   │ │
│  │  Routes  │  │  Routes  │  │  Routes  │  │ Routes  │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│       └──────────────┴─────────────┴─────────────┘       │
│                         │                                 │
│  ┌──────────────────────┴──────────────────────────────┐ │
│  │              Service Layer                           │ │
│  │  PauseToCodeService │ VideoProcessor │ GeminiExtractor│
│  │  ConceptDetector    │ QuizService    │ CodeExecution  │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│  ┌──────────────────────┴──────────────────────────────┐ │
│  │           Data Layer (SQLite + File Cache)           │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │   External Services    │
              │  • Google Gemini AI    │
              │  • YouTube (yt-dlp)    │
              │  • Piston API          │
              └───────────────────────┘
```

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/signup` | Create new account |
| POST | `/api/v1/auth/login` | Login with email/password |
| POST | `/api/v1/auth/refresh` | Refresh access token |

### Video Processing
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/video/process` | Process a YouTube video |
| GET | `/api/v1/video/{id}/status` | Get processing status |
| GET | `/api/v1/video/{id}/frame` | Extract & analyze frame at timestamp |
| GET | `/api/v1/video/{id}/segments` | Get all code segments |
| POST | `/api/v1/playlist/videos` | Extract playlist videos |

### Code Execution
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/code/execute` | Execute Python code |
| POST | `/api/v1/code/complete` | AI code completion |

### User Data
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/user/{email}/playlists` | Get user playlists |
| POST | `/api/v1/user/playlist` | Save playlist |
| POST | `/api/v1/user/progress` | Save video progress |
| DELETE | `/api/v1/user/{email}/playlist/{id}` | Delete playlist |

### Quiz
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/quiz/start` | Start quiz session |
| POST | `/api/v1/quiz/submit-answer` | Submit answer |
| GET | `/api/v1/quiz/session/{id}` | Get session status |
| POST | `/api/v1/quiz/end-session/{id}` | End session |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14, React, TypeScript, Tailwind CSS, shadcn/ui |
| Backend | Python, Flask, Flask-CORS |
| AI | Google Gemini Vision API (code extraction, quiz generation, concept detection) |
| Database | SQLite (via Python sqlite3) |
| Video | yt-dlp, OpenCV, youtube-transcript-api |
| Code Execution | Piston API (with local Python fallback) |
| Authentication | JWT (PyJWT) |

---

## License

This project is developed as a Final Year Project for academic purposes.
