"""
Codio Backend - Centralized Configuration
All environment variables and constants are loaded here.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from backend-local .env
load_dotenv(Path(__file__).resolve().parent.parent / '.env')

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
APP_HOST = os.getenv('APP_HOST', '0.0.0.0')
APP_PORT = int(os.getenv('APP_PORT', '8080'))
APP_DEBUG = os.getenv('APP_DEBUG', 'false').lower() == 'true'
APP_VERSION = '1.0.0'

# ---------------------------------------------------------------------------
# Cache / Storage
# ---------------------------------------------------------------------------
CACHE_DIR = os.getenv('CACHE_DIR', 'codio_cache')
DB_PATH = os.getenv('DB_PATH', os.path.join(CACHE_DIR, 'codio.db'))

# ---------------------------------------------------------------------------
# Gemini API
# ---------------------------------------------------------------------------
PAUSE_TO_CODE_GEMINI_API_KEY = os.getenv('PAUSE_TO_CODE_GEMINI_API_KEY', '')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')

def get_gemini_api_key() -> str:
    """Return the best available Gemini API key."""
    return PAUSE_TO_CODE_GEMINI_API_KEY or GEMINI_API_KEY

# ---------------------------------------------------------------------------
# JWT Authentication
# ---------------------------------------------------------------------------
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'default_secret_key_change_in_production')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRE_MINUTES', '60'))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRE_DAYS', '7'))

# ---------------------------------------------------------------------------
# Quiz
# ---------------------------------------------------------------------------
QUIZ_USE_GEMINI = os.getenv('QUIZ_USE_GEMINI', 'false').lower() == 'true'
QUIZ_GEMINI_TIMEOUT_SECONDS = float(os.getenv('QUIZ_GEMINI_TIMEOUT_SECONDS', '4'))
QUIZ_TOTAL_QUESTIONS = 5

# ---------------------------------------------------------------------------
# Code Execution
# ---------------------------------------------------------------------------
PISTON_EXECUTE_URL = 'https://emkc.org/api/v2/piston/execute'
PISTON_TIMEOUT_SECONDS = float(os.getenv('PISTON_TIMEOUT_SECONDS', '12'))
CODE_COMPLETION_TIMEOUT_SECONDS = float(os.getenv('CODE_COMPLETION_TIMEOUT_SECONDS', '4'))

# ---------------------------------------------------------------------------
# yt-dlp / YouTube
# ---------------------------------------------------------------------------
YTDLP_COOKIE_FILE = os.getenv('YTDLP_COOKIE_FILE', '').strip()
YTDLP_COOKIES_FROM_BROWSER = os.getenv('YTDLP_COOKIES_FROM_BROWSER', '').strip()
YTDLP_COOKIES_BROWSER_PROFILE = os.getenv('YTDLP_COOKIES_BROWSER_PROFILE', '').strip()
