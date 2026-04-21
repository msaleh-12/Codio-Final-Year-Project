# Codio Backend

Python Flask REST API for the Codio AI-Powered Interactive Coding Education Platform.

## Project Structure

```
codio-backend/
├── run.py                          # Entry point — Flask app factory
├── config/
│   ├── settings.py                 # All env vars & constants (single source of truth)
│   └── logging.py                  # Logging configuration
├── app/
│   ├── models/
│   │   └── database.py             # CodioDatabase — SQLite schema & queries
│   ├── routes/                     # Flask Blueprints (one per domain)
│   │   ├── __init__.py             # Blueprint exports
│   │   ├── auth.py                 # POST /auth/signup, /auth/login, /auth/refresh
│   │   ├── video.py                # Video processing, status, frame analysis, playlists
│   │   ├── code.py                 # POST /code/execute, /code/complete
│   │   ├── user.py                 # User playlists & progress CRUD
│   │   └── quiz.py                 # Adaptive quiz session lifecycle
│   ├── services/                   # Business logic (no Flask dependency)
│   │   ├── pause_to_code.py        # PauseToCodeService orchestrator
│   │   ├── video_processing.py     # VideoProcessor — download, transcript, caching
│   │   ├── gemini_extractor.py     # GeminiCodeExtractor — Vision AI integration
│   │   ├── concept_detection.py    # ConceptDetector — AI concept analysis
│   │   ├── code_execution.py       # Piston proxy + local fallback + AI completion
│   │   └── quiz_service.py         # Quiz question generation & difficulty logic
│   └── utils/
│       ├── jwt_auth.py             # JWTManager + @token_required decorator
│       └── helpers.py              # sanitize_error_text, normalize_question_text
├── tests/                          # Test directory (pytest-ready)
├── requirements.txt
├── .env.example
└── .gitignore
```

## Key Design Decisions

1. **Flask Blueprints** — Each domain (auth, video, code, user, quiz) is a separate Blueprint, making the codebase navigable and testable in isolation.

2. **Service Layer Pattern** — Business logic lives in `app/services/` with zero Flask imports. Services are injected into routes via `init_*_routes(db, service)` functions, enabling easy unit testing with mocks.

3. **Centralized Config** — All environment variables are loaded once in `config/settings.py`. No scattered `os.getenv()` calls throughout the codebase.

4. **Dependency Injection** — The `create_app()` factory in `run.py` creates shared `db` and `service` instances and passes them to route initializers, avoiding global state.

## Getting Started

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Fill in GEMINI_API_KEY and JWT_SECRET_KEY

# Run the server
python run.py
```

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/ -v --cov=app
```
