# Codio Frontend

AI-Powered Interactive Coding Education Platform — built with **Next.js 14**, **React**, **TypeScript**, and **Tailwind CSS**.

## Project Structure

```
codio-frontend/
├── app/                        # Next.js App Router
│   ├── api/youtube/playlist/   # Server-side API route (playlist proxy)
│   ├── globals.css             # Global styles
│   ├── layout.tsx              # Root layout
│   └── page.tsx                # Entry page (auth gate)
├── components/
│   ├── auth/                   # Authentication screens
│   │   ├── login-screen.tsx
│   │   └── signup-screen.tsx
│   ├── dashboard/              # Dashboard & learning views
│   │   ├── dashboard.tsx       # Main dashboard with playlist management
│   │   ├── learning-view.tsx   # Core learning interface (video + code + panels)
│   │   └── playlist-input.tsx  # Playlist URL input component
│   ├── learning/               # Feature-specific learning components
│   │   ├── concept-detector.tsx
│   │   ├── progress-sidebar.tsx
│   │   ├── python-compiler.tsx
│   │   ├── quiz-panel.tsx
│   │   ├── transcript-search.tsx
│   │   └── video-player.tsx
│   ├── ui/                     # Reusable UI primitives (shadcn/ui)
│   └── theme-provider.tsx      # Dark/light theme provider
├── config/
│   └── constants.ts            # Centralized app constants & API endpoints
├── hooks/                      # Custom React hooks
│   ├── use-mobile.ts
│   └── use-toast.ts
├── lib/
│   ├── api.ts                  # API client utilities
│   └── utils.ts                # General utility functions
├── types/
│   └── index.ts                # Shared TypeScript interfaces
├── styles/
│   └── globals.css             # Additional global styles
└── public/                     # Static assets
```

## Getting Started

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.local.example .env.local
# Edit .env.local with your backend URL

# Start development server
npm run dev
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | Backend API base URL | `http://localhost:8080` |
