"""
Codio Backend - Route Blueprints
All Flask blueprints are registered from this package.
"""

from app.routes.auth import auth_bp
from app.routes.video import video_bp
from app.routes.code import code_bp
from app.routes.user import user_bp
from app.routes.quiz import quiz_bp
from app.routes.admin import admin_bp

__all__ = ['auth_bp', 'video_bp', 'code_bp', 'user_bp', 'quiz_bp', 'admin_bp']
