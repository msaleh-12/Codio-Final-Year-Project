#!/usr/bin/env python3
"""
Codio Database Layer
SQLite database for user playlists and progress tracking
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import logging
import hashlib

logger = logging.getLogger(__name__)


class CodioDatabase:
    """Database manager for Codio user data"""
    
    def __init__(self, db_path: str = "codio_cache/codio.db"):
        """Initialize database connection"""
        self.db_path = db_path
        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        self._ensure_admin_tables()
        logger.info(f"[Database] Initialized database at {db_path}")
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        return conn
    
    def _init_database(self):
        """Initialize database tables"""
        logger.info("[Database] Creating/verifying database tables...")
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT NOT NULL
            )
        """)
        
        # Playlists table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS playlists (
                playlist_id TEXT PRIMARY KEY,
                playlist_url TEXT NOT NULL,
                playlist_title TEXT NOT NULL,
                total_videos INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # User playlists (junction table)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_playlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                playlist_id TEXT NOT NULL,
                first_accessed TEXT NOT NULL,
                last_accessed TEXT NOT NULL,
                FOREIGN KEY (user_email) REFERENCES users(email),
                FOREIGN KEY (playlist_id) REFERENCES playlists(playlist_id),
                UNIQUE(user_email, playlist_id)
            )
        """)
        
        # Video progress table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS video_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                playlist_id TEXT NOT NULL,
                video_id TEXT NOT NULL,
                watched_seconds REAL NOT NULL DEFAULT 0,
                duration REAL NOT NULL DEFAULT 0,
                completed INTEGER NOT NULL DEFAULT 0,
                last_updated TEXT NOT NULL,
                FOREIGN KEY (user_email) REFERENCES users(email),
                FOREIGN KEY (playlist_id) REFERENCES playlists(playlist_id),
                UNIQUE(user_email, playlist_id, video_id)
            )
        """)

        # Quiz sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quiz_sessions (
                session_id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                video_id TEXT,
                transcript_text TEXT NOT NULL,
                current_level INTEGER NOT NULL DEFAULT 1,
                learning_rate REAL NOT NULL DEFAULT 0,
                questions_answered INTEGER NOT NULL DEFAULT 0,
                correct_answers INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                FOREIGN KEY (user_email) REFERENCES users(email)
            )
        """)

        # Quiz questions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quiz_questions (
                question_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                question_type TEXT NOT NULL,
                difficulty INTEGER NOT NULL,
                question_text TEXT NOT NULL,
                options_json TEXT,
                correct_answer TEXT NOT NULL,
                explanation TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES quiz_sessions(session_id)
            )
        """)

        # Quiz attempts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                question_id TEXT NOT NULL,
                user_answer TEXT NOT NULL,
                is_correct INTEGER NOT NULL DEFAULT 0,
                time_taken INTEGER NOT NULL DEFAULT 0,
                attempted_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES quiz_sessions(session_id),
                FOREIGN KEY (question_id) REFERENCES quiz_questions(question_id)
            )
        """)
        
        # Create indexes for faster queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_playlists_user 
            ON user_playlists(user_email)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_video_progress_user 
            ON video_progress(user_email, playlist_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_quiz_sessions_user
            ON quiz_sessions(user_email, started_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_quiz_questions_session
            ON quiz_questions(session_id, created_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_quiz_attempts_session
            ON quiz_attempts(session_id, attempted_at)
        """)
        conn.commit()
        conn.close()
        logger.info("[Database] Database tables created/verified successfully")
        
        # Create default admin account if it doesn't exist
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin account on first run"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM users WHERE email = ?", ('admin@gmail.com',))
            if not cursor.fetchone():
                now = datetime.now().isoformat()
                password_hash = self._hash_password('admin123')
                cursor.execute(
                    "INSERT INTO users (email, name, password_hash, created_at, last_login) VALUES (?, ?, ?, ?, ?)",
                    ('admin@gmail.com', 'Admin', password_hash, now, now)
                )
                conn.commit()
                logger.info("[Database] Default admin account created (admin@gmail.com / admin123)")
            conn.close()
        except Exception as e:
            logger.error(f"[Database] Error creating default admin: {e}")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return self._hash_password(password) == password_hash
    
    def create_user(self, email: str, name: str, password: str) -> Dict:
        """Create a new user account"""
        logger.info(f"[Database] Creating new user: {email}")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                conn.close()
                logger.warning(f"[Database] User {email} already exists")
                return {"success": False, "error": "Email already registered"}
            
            # Create new user
            now = datetime.now().isoformat()
            password_hash = self._hash_password(password)
            
            cursor.execute(
                "INSERT INTO users (email, name, password_hash, created_at, last_login) VALUES (?, ?, ?, ?, ?)",
                (email, name, password_hash, now, now)
            )
            
            conn.commit()
            conn.close()
            logger.info(f"[Database] User {email} created successfully")
            return {"success": True, "message": "User created successfully"}
            
        except Exception as e:
            logger.error(f"[Database] Error creating user: {e}")
            return {"success": False, "error": str(e)}
    
    def authenticate_user(self, email: str, password: str) -> Dict:
        """Authenticate user with email and password"""
        logger.info(f"[Database] Authenticating user: {email}")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get user
            cursor.execute("SELECT email, name, password_hash FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                logger.warning(f"[Database] User {email} not found")
                return {"success": False, "error": "Invalid email or password"}
            
            # Verify password
            if not self._verify_password(password, user['password_hash']):
                conn.close()
                logger.warning(f"[Database] Invalid password for {email}")
                return {"success": False, "error": "Invalid email or password"}
            
            # Update last login
            now = datetime.now().isoformat()
            cursor.execute("UPDATE users SET last_login = ? WHERE email = ?", (now, email))
            conn.commit()
            conn.close()
            
            logger.info(f"[Database] User {email} authenticated successfully")
            return {
                "success": True,
                "user": {
                    "email": user['email'],
                    "name": user['name']
                }
            }
            
        except Exception as e:
            logger.error(f"[Database] Error authenticating user: {e}")
            return {"success": False, "error": str(e)}
    
    def add_or_update_user(self, email: str, name: str) -> bool:
        """Add or update user information (legacy method for backward compatibility)"""
        logger.info(f"[Database] Adding/updating user: {email}")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            # Check if user exists
            cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
            exists = cursor.fetchone()
            
            if exists:
                # Update last login
                cursor.execute(
                    "UPDATE users SET last_login = ? WHERE email = ?",
                    (now, email)
                )
                logger.info(f"[Database] Updated last_login for {email}")
            else:
                # Create new user with empty password (legacy)
                cursor.execute(
                    "INSERT INTO users (email, name, password_hash, created_at, last_login) VALUES (?, ?, ?, ?, ?)",
                    (email, name, '', now, now)
                )
                logger.info(f"[Database] Created new user {email}")
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"[Database] Error adding/updating user: {e}")
            return False
    
    def add_or_update_playlist(self, playlist_id: str, playlist_url: str, playlist_title: str, total_videos: int) -> bool:
        """Add or update playlist information"""
        logger.info(f"[Database] Adding/updating playlist: {playlist_id}")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("SELECT playlist_id FROM playlists WHERE playlist_id = ?", (playlist_id,))
            exists = cursor.fetchone()
            
            if exists:
                cursor.execute(
                    "UPDATE playlists SET playlist_url = ?, playlist_title = ?, total_videos = ?, updated_at = ? WHERE playlist_id = ?",
                    (playlist_url, playlist_title, total_videos, now, playlist_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO playlists (playlist_id, playlist_url, playlist_title, total_videos, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (playlist_id, playlist_url, playlist_title, total_videos, now, now)
                )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"[Database] Error adding/updating playlist: {e}")
            return False
    
    def link_user_to_playlist(self, user_email: str, playlist_id: str) -> bool:
        """Link a user to a playlist"""
        logger.info(f"[Database] Linking user {user_email} to playlist {playlist_id}")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute(
                "SELECT id FROM user_playlists WHERE user_email = ? AND playlist_id = ?",
                (user_email, playlist_id)
            )
            exists = cursor.fetchone()
            
            if exists:
                cursor.execute(
                    "UPDATE user_playlists SET last_accessed = ? WHERE user_email = ? AND playlist_id = ?",
                    (now, user_email, playlist_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO user_playlists (user_email, playlist_id, first_accessed, last_accessed) VALUES (?, ?, ?, ?)",
                    (user_email, playlist_id, now, now)
                )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"[Database] Error linking user to playlist: {e}")
            return False
    
    def get_user_playlists(self, user_email: str) -> List[Dict]:
        """Get all playlists for a user with progress"""
        logger.info(f"[Database] Getting playlists for user: {user_email}")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    p.playlist_id,
                    p.playlist_url,
                    p.playlist_title,
                    p.total_videos,
                    up.first_accessed,
                    up.last_accessed
                FROM user_playlists up
                JOIN playlists p ON up.playlist_id = p.playlist_id
                WHERE up.user_email = ?
                ORDER BY up.last_accessed DESC
            """, (user_email,))
            
            playlists = []
            for row in cursor.fetchall():
                playlist = dict(row)
                
                # Get progress for this playlist
                cursor.execute("""
                    SELECT COUNT(*) as completed_count
                    FROM video_progress
                    WHERE user_email = ? AND playlist_id = ? AND completed = 1
                """, (user_email, playlist['playlist_id']))
                
                completed = cursor.fetchone()['completed_count']
                total = playlist['total_videos']
                progress = round((completed / total * 100), 1) if total > 0 else 0
                
                playlist['completed_videos'] = completed
                playlist['progress_percentage'] = progress
                playlists.append(playlist)
            
            conn.close()
            return playlists
            
        except Exception as e:
            logger.error(f"[Database] Error getting user playlists: {e}")
            return []
    
    def delete_user_playlist(self, user_email: str, playlist_id: str) -> bool:
        """Delete a playlist from user's list and associated progress"""
        logger.info(f"[Database] Deleting playlist {playlist_id} for user {user_email}")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Delete progress
            cursor.execute(
                "DELETE FROM video_progress WHERE user_email = ? AND playlist_id = ?",
                (user_email, playlist_id)
            )
            
            # Delete user-playlist link
            cursor.execute(
                "DELETE FROM user_playlists WHERE user_email = ? AND playlist_id = ?",
                (user_email, playlist_id)
            )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"[Database] Error deleting user playlist: {e}")
            return False
    
    def save_video_progress(self, user_email: str, playlist_id: str, video_id: str,
                           watched_seconds: float, duration: float, completed: bool) -> bool:
        """Save video watch progress"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT INTO video_progress (user_email, playlist_id, video_id, watched_seconds, duration, completed, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_email, playlist_id, video_id) 
                DO UPDATE SET 
                    watched_seconds = MAX(video_progress.watched_seconds, excluded.watched_seconds),
                    duration = excluded.duration,
                    completed = MAX(video_progress.completed, excluded.completed),
                    last_updated = excluded.last_updated
            """, (user_email, playlist_id, video_id, watched_seconds, duration, int(completed), now))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"[Database] Error saving video progress: {e}")
            return False
    
    def get_playlist_progress(self, user_email: str, playlist_id: str) -> Dict:
        """Get progress for all videos in a playlist"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT video_id, watched_seconds, duration, completed, last_updated
                FROM video_progress
                WHERE user_email = ? AND playlist_id = ?
            """, (user_email, playlist_id))
            
            progress = {}
            for row in cursor.fetchall():
                progress[row['video_id']] = {
                    'watchedSeconds': row['watched_seconds'],
                    'duration': row['duration'],
                    'completed': bool(row['completed']),
                    'lastUpdated': row['last_updated']
                }
            
            conn.close()
            return progress
            
        except Exception as e:
            logger.error(f"[Database] Error getting playlist progress: {e}")
            return {}

    # ------------------------------------------------------------------
    # Quiz persistence
    # ------------------------------------------------------------------

    def create_quiz_session(self, session_id: str, user_email: str,
                            transcript_text: str, video_id: str = None) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            cursor.execute(
                "INSERT INTO quiz_sessions (session_id, user_email, video_id, transcript_text, started_at) VALUES (?, ?, ?, ?, ?)",
                (session_id, user_email, video_id, transcript_text, now)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"[Database] Error creating quiz session: {e}")
            return False

    def get_quiz_session(self, session_id: str) -> Optional[Dict]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quiz_sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            conn.close()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"[Database] Error getting quiz session: {e}")
            return None

    def add_quiz_question(self, question_id: str, session_id: str,
                          question_type: str, difficulty: int,
                          question_text: str, options: list,
                          correct_answer: str, explanation: str) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            cursor.execute(
                "INSERT INTO quiz_questions (question_id, session_id, question_type, difficulty, question_text, options_json, correct_answer, explanation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (question_id, session_id, question_type, difficulty, question_text, json.dumps(options), correct_answer, explanation, now)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"[Database] Error adding quiz question: {e}")
            return False

    def get_quiz_session_question_texts(self, session_id: str) -> List[str]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT question_text FROM quiz_questions WHERE session_id = ? ORDER BY created_at",
                (session_id,)
            )
            texts = [row['question_text'] for row in cursor.fetchall()]
            conn.close()
            return texts
        except Exception as e:
            logger.error(f"[Database] Error getting quiz question texts: {e}")
            return []

    def get_quiz_question(self, question_id: str) -> Optional[Dict]:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quiz_questions WHERE question_id = ?", (question_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                d = dict(row)
                d['options'] = json.loads(d.get('options_json', '[]'))
                return d
            return None
        except Exception as e:
            logger.error(f"[Database] Error getting quiz question: {e}")
            return None

    def record_quiz_attempt(self, session_id: str, question_id: str,
                            user_answer: str, is_correct: bool,
                            time_taken: int) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            cursor.execute(
                "INSERT INTO quiz_attempts (session_id, question_id, user_answer, is_correct, time_taken, attempted_at) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, question_id, user_answer, int(is_correct), time_taken, now)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"[Database] Error recording quiz attempt: {e}")
            return False

    def update_quiz_session_progress(self, session_id: str, current_level: int,
                                     learning_rate: float, questions_answered: int,
                                     correct_answers: int) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE quiz_sessions SET current_level = ?, learning_rate = ?, questions_answered = ?, correct_answers = ? WHERE session_id = ?",
                (current_level, learning_rate, questions_answered, correct_answers, session_id)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"[Database] Error updating quiz session progress: {e}")
            return False

    def end_quiz_session(self, session_id: str) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            cursor.execute(
                "UPDATE quiz_sessions SET ended_at = ? WHERE session_id = ?",
                (now, session_id)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"[Database] Error ending quiz session: {e}")
            return False

    def get_quiz_attempt_stats(self, session_id: str) -> Dict:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_attempts,
                    SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_attempts,
                    AVG(time_taken) as average_time
                FROM quiz_attempts
                WHERE session_id = ?
            """, (session_id,))
            row = cursor.fetchone()
            conn.close()
            return {
                'total_attempts': row['total_attempts'] or 0,
                'correct_attempts': row['correct_attempts'] or 0,
                'average_time': round(row['average_time'] or 0, 2)
            }
        except Exception as e:
            logger.error(f"[Database] Error getting quiz attempt stats: {e}")
            return {'total_attempts': 0, 'correct_attempts': 0, 'average_time': 0}

    # ------------------------------------------------------------------
    # Admin / Dashboard aggregate queries
    # ------------------------------------------------------------------

    def get_all_users(self) -> List[Dict]:
        """Get all users with their learning stats (admin only)"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    u.email,
                    u.name,
                    u.created_at,
                    u.last_login,
                    COUNT(DISTINCT up.playlist_id) as total_playlists,
                    COALESCE(SUM(CASE WHEN vp.completed = 1 THEN 1 ELSE 0 END), 0) as completed_videos,
                    COALESCE(SUM(vp.watched_seconds), 0) as total_watch_time,
                    COUNT(DISTINCT qs.session_id) as quiz_sessions
                FROM users u
                LEFT JOIN user_playlists up ON u.email = up.user_email
                LEFT JOIN video_progress vp ON u.email = vp.user_email
                LEFT JOIN quiz_sessions qs ON u.email = qs.user_email
                GROUP BY u.email
                ORDER BY u.last_login DESC
            """)
            users = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return users
        except Exception as e:
            logger.error(f"[Database] Error getting all users: {e}")
            return []

    def get_system_stats(self) -> Dict:
        """Get system-wide statistics (admin only)"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            stats = {}

            cursor.execute("SELECT COUNT(*) as count FROM users")
            stats['total_users'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM playlists")
            stats['total_playlists'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(DISTINCT video_id) as count FROM video_progress")
            stats['total_videos_watched'] = cursor.fetchone()['count']

            cursor.execute("SELECT COALESCE(SUM(watched_seconds), 0) as total FROM video_progress")
            stats['total_watch_time_seconds'] = cursor.fetchone()['total']

            cursor.execute("SELECT COUNT(*) as count FROM video_progress WHERE completed = 1")
            stats['total_completions'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM quiz_sessions")
            stats['total_quiz_sessions'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM quiz_attempts")
            stats['total_quiz_attempts'] = cursor.fetchone()['count']

            cursor.execute("SELECT COALESCE(SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END), 0) as correct, COUNT(*) as total FROM quiz_attempts")
            row = cursor.fetchone()
            stats['quiz_accuracy'] = round((row['correct'] / row['total'] * 100), 1) if row['total'] > 0 else 0

            conn.close()
            return stats
        except Exception as e:
            logger.error(f"[Database] Error getting system stats: {e}")
            return {}

    def get_user_dashboard_stats(self, user_email: str) -> Dict:
        """Get dashboard stats for a specific user"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            stats = {}

            # Playlists count
            cursor.execute(
                "SELECT COUNT(*) as count FROM user_playlists WHERE user_email = ?",
                (user_email,))
            stats['total_playlists'] = cursor.fetchone()['count']

            # Videos in progress (started but not completed)
            cursor.execute("""
                SELECT COUNT(*) as count FROM video_progress
                WHERE user_email = ? AND completed = 0 AND watched_seconds > 0
            """, (user_email,))
            stats['videos_in_progress'] = cursor.fetchone()['count']

            # Completed videos
            cursor.execute(
                "SELECT COUNT(*) as count FROM video_progress WHERE user_email = ? AND completed = 1",
                (user_email,))
            stats['completed_videos'] = cursor.fetchone()['count']

            # Total watch time
            cursor.execute(
                "SELECT COALESCE(SUM(watched_seconds), 0) as total FROM video_progress WHERE user_email = ?",
                (user_email,))
            stats['total_watch_time_seconds'] = cursor.fetchone()['total']

            # Quiz stats
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT qs.session_id) as sessions,
                    COALESCE(SUM(qs.questions_answered), 0) as questions,
                    COALESCE(SUM(qs.correct_answers), 0) as correct
                FROM quiz_sessions qs WHERE qs.user_email = ?
            """, (user_email,))
            row = cursor.fetchone()
            stats['quiz_sessions'] = row['sessions']
            stats['quiz_questions_answered'] = row['questions']
            stats['quiz_correct_answers'] = row['correct']
            stats['quiz_accuracy'] = round((row['correct'] / row['questions'] * 100), 1) if row['questions'] > 0 else 0

            # Recent activity (last 5 videos watched)
            cursor.execute("""
                SELECT vp.video_id, vp.playlist_id, vp.watched_seconds, vp.duration, 
                       vp.completed, vp.last_updated,
                       p.playlist_title
                FROM video_progress vp
                LEFT JOIN playlists p ON vp.playlist_id = p.playlist_id
                WHERE vp.user_email = ?
                ORDER BY vp.last_updated DESC
                LIMIT 5
            """, (user_email,))
            stats['recent_activity'] = [dict(r) for r in cursor.fetchall()]

            # In-progress playlists (for "Continue Learning")
            cursor.execute("""
                SELECT 
                    p.playlist_id, p.playlist_url, p.playlist_title, p.total_videos,
                    up.last_accessed,
                    COUNT(CASE WHEN vp.completed = 1 THEN 1 END) as completed_videos,
                    COALESCE(SUM(vp.watched_seconds), 0) as watched_seconds
                FROM user_playlists up
                JOIN playlists p ON up.playlist_id = p.playlist_id
                LEFT JOIN video_progress vp ON up.user_email = vp.user_email AND up.playlist_id = vp.playlist_id
                WHERE up.user_email = ?
                GROUP BY p.playlist_id
                HAVING completed_videos < p.total_videos OR completed_videos IS NULL
                ORDER BY up.last_accessed DESC
                LIMIT 5
            """, (user_email,))
            stats['continue_learning'] = [dict(r) for r in cursor.fetchall()]

            conn.close()
            return stats
        except Exception as e:
            logger.error(f"[Database] Error getting user dashboard stats: {e}")
            return {}
    def get_enhanced_admin_stats(self) -> Dict:
        """Get comprehensive admin KPIs including billing, engagement, content analytics"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            stats = {}

            # === Core KPIs ===
            cursor.execute("SELECT COUNT(*) as c FROM users")
            stats['total_users'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM playlists")
            stats['total_playlists'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(DISTINCT video_id) as c FROM video_progress")
            stats['total_videos_watched'] = cursor.fetchone()['c']

            cursor.execute("SELECT COALESCE(SUM(watched_seconds), 0) as t FROM video_progress")
            stats['total_watch_time_seconds'] = cursor.fetchone()['t']

            cursor.execute("SELECT COUNT(*) as c FROM video_progress WHERE completed = 1")
            stats['total_completions'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM quiz_sessions")
            stats['total_quiz_sessions'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM quiz_attempts")
            stats['total_quiz_attempts'] = cursor.fetchone()['c']

            cursor.execute("SELECT COALESCE(SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END),0) as correct, COUNT(*) as total FROM quiz_attempts")
            row = cursor.fetchone()
            stats['quiz_accuracy'] = round((row['correct'] / row['total'] * 100), 1) if row['total'] > 0 else 0

            # === Engagement KPIs ===
            cursor.execute("SELECT COUNT(*) as c FROM users WHERE last_login >= datetime('now', '-7 days')")
            stats['active_users_7d'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM users WHERE last_login >= datetime('now', '-30 days')")
            stats['active_users_30d'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM users WHERE created_at >= datetime('now', '-7 days')")
            stats['new_users_week'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM users WHERE created_at >= datetime('now', '-30 days')")
            stats['new_users_month'] = cursor.fetchone()['c']

            # Completion rate
            cursor.execute("SELECT COUNT(*) as total FROM video_progress")
            total_vp = cursor.fetchone()['total']
            stats['completion_rate'] = round((stats['total_completions'] / total_vp * 100), 1) if total_vp > 0 else 0

            # Average session duration (watch time per user)
            stats['avg_watch_time_per_user'] = round(stats['total_watch_time_seconds'] / stats['total_users'], 0) if stats['total_users'] > 0 else 0

            # === Daily Active Users (last 7 days) ===
            dau_data = []
            cursor.execute("""
                SELECT date(last_login) as day, COUNT(DISTINCT email) as users
                FROM users
                WHERE last_login >= datetime('now', '-7 days')
                GROUP BY date(last_login)
                ORDER BY day ASC
            """)
            for r in cursor.fetchall():
                dau_data.append({'day': r['day'], 'users': r['users']})
            stats['dau_7d'] = dau_data

            # === Weekly Learning Hours (last 4 weeks) ===
            weekly_hours = []
            for i in range(3, -1, -1):
                cursor.execute(f"""
                    SELECT COALESCE(SUM(watched_seconds), 0) as total
                    FROM video_progress
                    WHERE last_updated >= datetime('now', '-{(i+1)*7} days')
                      AND last_updated < datetime('now', '-{i*7} days')
                """)
                weekly_hours.append({
                    'week': f'Week {4-i}',
                    'hours': round(cursor.fetchone()['total'] / 3600, 1)
                })
            stats['weekly_learning_hours'] = weekly_hours

            # === Top Courses (most enrolled) ===
            cursor.execute("""
                SELECT p.playlist_title, p.playlist_id, p.total_videos,
                       COUNT(DISTINCT up.user_email) as enrollments,
                       COALESCE(SUM(CASE WHEN vp.completed = 1 THEN 1 ELSE 0 END), 0) as completions
                FROM playlists p
                LEFT JOIN user_playlists up ON p.playlist_id = up.playlist_id
                LEFT JOIN video_progress vp ON p.playlist_id = vp.playlist_id
                GROUP BY p.playlist_id
                ORDER BY enrollments DESC
                LIMIT 5
            """)
            stats['top_courses'] = [dict(r) for r in cursor.fetchall()]

            # === User Adoption Funnel ===
            stats['funnel_signed_up'] = stats['total_users']
            cursor.execute("SELECT COUNT(DISTINCT user_email) as c FROM user_playlists")
            stats['funnel_started_course'] = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(DISTINCT user_email) as c FROM video_progress WHERE completed = 1")
            stats['funnel_completed_video'] = cursor.fetchone()['c']
            cursor.execute("SELECT COUNT(DISTINCT user_email) as c FROM quiz_sessions")
            stats['funnel_took_quiz'] = cursor.fetchone()['c']

            # === Billing / Revenue (simulated for demo) ===
            import random
            random.seed(42)
            pro_users = max(1, stats['total_users'] // 2)
            free_users = stats['total_users'] - pro_users
            stats['billing'] = {
                'total_revenue': round(pro_users * 29.99, 2),
                'monthly_revenue': round(pro_users * 29.99, 2),
                'active_subscriptions': pro_users,
                'free_users': free_users,
                'pro_users': pro_users,
                'arpu': round(pro_users * 29.99 / stats['total_users'], 2) if stats['total_users'] > 0 else 0,
                'mrr_growth': 12.5,
                'churn_rate': 3.2,
                'plan_breakdown': [
                    {'plan': 'Free', 'users': free_users, 'revenue': 0},
                    {'plan': 'Pro Monthly', 'users': max(1, pro_users // 2), 'revenue': round(max(1, pro_users // 2) * 29.99, 2)},
                    {'plan': 'Pro Annual', 'users': max(1, pro_users - pro_users // 2), 'revenue': round(max(1, pro_users - pro_users // 2) * 24.99, 2)},
                ],
                'revenue_trend': [
                    {'month': 'Jan', 'revenue': 120},
                    {'month': 'Feb', 'revenue': 180},
                    {'month': 'Mar', 'revenue': 250},
                    {'month': 'Apr', 'revenue': round(pro_users * 29.99, 2)},
                ]
            }

            # === Top Learners ===
            cursor.execute("""
                SELECT u.name, u.email,
                       COALESCE(SUM(vp.watched_seconds), 0) as total_watch,
                       COUNT(CASE WHEN vp.completed = 1 THEN 1 END) as completions
                FROM users u
                LEFT JOIN video_progress vp ON u.email = vp.user_email
                GROUP BY u.email
                ORDER BY total_watch DESC
                LIMIT 5
            """)
            stats['top_learners'] = [dict(r) for r in cursor.fetchall()]

            conn.close()
            return stats
        except Exception as e:
            logger.error(f"[Database] Error getting enhanced admin stats: {e}")
            import traceback
            traceback.print_exc()
            return {}

    def get_enhanced_user_stats(self, user_email: str) -> Dict:
        """Get comprehensive user dashboard KPIs including streaks, achievements, weekly activity"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            stats = {}

            # === Core Stats ===
            cursor.execute("SELECT COUNT(*) as c FROM user_playlists WHERE user_email = ?", (user_email,))
            stats['total_playlists'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM video_progress WHERE user_email = ? AND completed = 0 AND watched_seconds > 0", (user_email,))
            stats['videos_in_progress'] = cursor.fetchone()['c']

            cursor.execute("SELECT COUNT(*) as c FROM video_progress WHERE user_email = ? AND completed = 1", (user_email,))
            stats['completed_videos'] = cursor.fetchone()['c']

            cursor.execute("SELECT COALESCE(SUM(watched_seconds), 0) as t FROM video_progress WHERE user_email = ?", (user_email,))
            stats['total_watch_time_seconds'] = cursor.fetchone()['t']

            # Quiz stats
            cursor.execute("""
                SELECT COUNT(DISTINCT qs.session_id) as sessions,
                       COALESCE(SUM(qs.questions_answered), 0) as questions,
                       COALESCE(SUM(qs.correct_answers), 0) as correct
                FROM quiz_sessions qs WHERE qs.user_email = ?
            """, (user_email,))
            row = cursor.fetchone()
            stats['quiz_sessions'] = row['sessions']
            stats['quiz_questions_answered'] = row['questions']
            stats['quiz_correct_answers'] = row['correct']
            stats['quiz_accuracy'] = round((row['correct'] / row['questions'] * 100), 1) if row['questions'] > 0 else 0

            # === Learning Streak ===
            cursor.execute("""
                SELECT DISTINCT date(last_updated) as day
                FROM video_progress
                WHERE user_email = ?
                ORDER BY day DESC
            """, (user_email,))
            activity_days = [r['day'] for r in cursor.fetchall()]
            streak = 0
            if activity_days:
                from datetime import date, timedelta
                today = date.today()
                check_date = today
                for day_str in activity_days:
                    if day_str is None:
                        break
                    day = date.fromisoformat(day_str)
                    if day == check_date or day == check_date - timedelta(days=1):
                        streak += 1
                        check_date = day - timedelta(days=1)
                    else:
                        break
            stats['learning_streak'] = streak

            # === Weekly Activity (last 7 days, minutes per day) ===
            weekly_activity = []
            from datetime import date, timedelta
            today = date.today()
            for i in range(6, -1, -1):
                d = today - timedelta(days=i)
                d_str = d.isoformat()
                cursor.execute("""
                    SELECT COALESCE(SUM(watched_seconds), 0) as total
                    FROM video_progress
                    WHERE user_email = ? AND date(last_updated) = ?
                """, (user_email, d_str))
                mins = round(cursor.fetchone()['total'] / 60, 1)
                weekly_activity.append({
                    'day': d.strftime('%a'),
                    'date': d_str,
                    'minutes': mins
                })
            stats['weekly_activity'] = weekly_activity

            # === Weekly Goal Progress ===
            weekly_target_minutes = 120
            total_week_minutes = sum(d['minutes'] for d in weekly_activity)
            stats['weekly_goal'] = {
                'target_minutes': weekly_target_minutes,
                'current_minutes': round(total_week_minutes, 1),
                'progress_pct': min(100, round(total_week_minutes / weekly_target_minutes * 100, 1))
            }

            # === Concepts Learned ===
            cursor.execute("SELECT COUNT(DISTINCT qq.question_id) as c FROM quiz_questions qq JOIN quiz_sessions qs ON qq.session_id = qs.session_id WHERE qs.user_email = ?", (user_email,))
            stats['concepts_learned'] = cursor.fetchone()['c']

            # === Achievements / Badges ===
            achievements = []
            if stats['total_playlists'] >= 1:
                achievements.append({'id': 'first_course', 'title': 'First Steps', 'description': 'Started your first course', 'icon': 'rocket', 'earned': True})
            else:
                achievements.append({'id': 'first_course', 'title': 'First Steps', 'description': 'Start your first course', 'icon': 'rocket', 'earned': False})

            if stats['completed_videos'] >= 1:
                achievements.append({'id': 'video_watcher', 'title': 'Video Watcher', 'description': 'Completed your first video', 'icon': 'play', 'earned': True})
            else:
                achievements.append({'id': 'video_watcher', 'title': 'Video Watcher', 'description': 'Complete your first video', 'icon': 'play', 'earned': False})

            if stats['quiz_sessions'] >= 1:
                achievements.append({'id': 'quiz_taker', 'title': 'Quiz Taker', 'description': 'Completed your first quiz', 'icon': 'brain', 'earned': True})
            else:
                achievements.append({'id': 'quiz_taker', 'title': 'Quiz Taker', 'description': 'Take your first quiz', 'icon': 'brain', 'earned': False})

            if stats['quiz_sessions'] >= 5:
                achievements.append({'id': 'quiz_master', 'title': 'Quiz Master', 'description': 'Completed 5 quizzes', 'icon': 'trophy', 'earned': True})
            else:
                achievements.append({'id': 'quiz_master', 'title': 'Quiz Master', 'description': f"Complete 5 quizzes ({stats['quiz_sessions']}/5)", 'icon': 'trophy', 'earned': False})

            if streak >= 3:
                achievements.append({'id': 'streak_warrior', 'title': 'Streak Warrior', 'description': '3-day learning streak', 'icon': 'flame', 'earned': True})
            else:
                achievements.append({'id': 'streak_warrior', 'title': 'Streak Warrior', 'description': f'Reach a 3-day streak ({streak}/3)', 'icon': 'flame', 'earned': False})

            if stats['concepts_learned'] >= 10:
                achievements.append({'id': 'knowledge_explorer', 'title': 'Knowledge Explorer', 'description': 'Explored 10+ concepts', 'icon': 'compass', 'earned': True})
            else:
                achievements.append({'id': 'knowledge_explorer', 'title': 'Knowledge Explorer', 'description': f"Explore 10 concepts ({stats['concepts_learned']}/10)", 'icon': 'compass', 'earned': False})

            hours = stats['total_watch_time_seconds'] / 3600
            if hours >= 1:
                achievements.append({'id': 'hour_milestone', 'title': 'Dedicated Learner', 'description': '1+ hour of learning', 'icon': 'clock', 'earned': True})
            else:
                achievements.append({'id': 'hour_milestone', 'title': 'Dedicated Learner', 'description': f'Learn for 1 hour ({round(hours*60)}m/60m)', 'icon': 'clock', 'earned': False})

            stats['achievements'] = achievements
            stats['achievements_earned'] = sum(1 for a in achievements if a['earned'])
            stats['achievements_total'] = len(achievements)

            # === Skill Progress ===
            cursor.execute("""
                SELECT p.playlist_title,
                       COUNT(CASE WHEN vp.completed = 1 THEN 1 END) as completed,
                       p.total_videos
                FROM user_playlists up
                JOIN playlists p ON up.playlist_id = p.playlist_id
                LEFT JOIN video_progress vp ON up.user_email = vp.user_email AND up.playlist_id = vp.playlist_id
                WHERE up.user_email = ?
                GROUP BY p.playlist_id
                ORDER BY up.last_accessed DESC
            """, (user_email,))
            skills = []
            for r in cursor.fetchall():
                pct = round(r['completed'] / r['total_videos'] * 100) if r['total_videos'] > 0 else 0
                skills.append({'name': r['playlist_title'], 'progress': pct, 'completed': r['completed'], 'total': r['total_videos']})
            stats['skill_progress'] = skills

            # === Recent Activity ===
            cursor.execute("""
                SELECT vp.video_id, vp.playlist_id, vp.watched_seconds, vp.duration,
                       vp.completed, vp.last_updated, p.playlist_title
                FROM video_progress vp
                LEFT JOIN playlists p ON vp.playlist_id = p.playlist_id
                WHERE vp.user_email = ?
                ORDER BY vp.last_updated DESC LIMIT 5
            """, (user_email,))
            stats['recent_activity'] = [dict(r) for r in cursor.fetchall()]

            conn.close()
            return stats
        except Exception as e:
            logger.error(f"[Database] Error getting enhanced user stats: {e}")
            import traceback
            traceback.print_exc()
            return {}

    # ══════════════════════════════════════════════════════════════════
    # NEW: Admin Management Methods
    # ══════════════════════════════════════════════════════════════════

    def _ensure_admin_tables(self):
        """Create additional tables for subscriptions, certificates, etc."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                status TEXT NOT NULL DEFAULT 'active',
                started_at TEXT NOT NULL,
                expires_at TEXT,
                amount REAL NOT NULL DEFAULT 0,
                payment_method TEXT DEFAULT 'card',
                FOREIGN KEY (user_email) REFERENCES users(email)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                cert_id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                course_title TEXT NOT NULL,
                playlist_id TEXT,
                issued_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                grade TEXT DEFAULT 'Pass',
                FOREIGN KEY (user_email) REFERENCES users(email)
            )
        """)

        # Add role and status columns to users if not exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'learner'")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        except:
            pass

        # Add status column to playlists if not exist
        try:
            cursor.execute("ALTER TABLE playlists ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        except:
            pass

        conn.commit()

        # Seed demo subscriptions if empty
        cursor.execute("SELECT COUNT(*) as c FROM subscriptions")
        if cursor.fetchone()['c'] == 0:
            self._seed_demo_subscriptions(cursor)
            conn.commit()

        # Seed demo certificates if empty
        cursor.execute("SELECT COUNT(*) as c FROM certificates")
        if cursor.fetchone()['c'] == 0:
            self._seed_demo_certificates(cursor)
            conn.commit()

        conn.close()

    def _seed_demo_subscriptions(self, cursor):
        """Seed demo subscription data"""
        from datetime import datetime, timedelta
        import uuid
        now = datetime.utcnow()

        cursor.execute("SELECT email FROM users")
        users = [r['email'] for r in cursor.fetchall()]

        plans = [
            ('pro_monthly', 29.99),
            ('pro_annual', 199.99),
            ('free', 0),
            ('enterprise', 99.99),
        ]

        for i, email in enumerate(users):
            plan_name, amount = plans[i % len(plans)]
            started = now - timedelta(days=30 * (i + 1))
            expires = started + timedelta(days=365 if 'annual' in plan_name else 30)
            cursor.execute("""
                INSERT INTO subscriptions (user_email, plan, status, started_at, expires_at, amount, payment_method)
                VALUES (?, ?, 'active', ?, ?, ?, ?)
            """, (email, plan_name, started.isoformat(), expires.isoformat(), amount, 'card' if amount > 0 else 'none'))

    def _seed_demo_certificates(self, cursor):
        """Seed demo certificate data"""
        from datetime import datetime, timedelta
        import uuid

        # Find users who completed courses
        cursor.execute("""
            SELECT DISTINCT vp.user_email, p.playlist_title, vp.playlist_id
            FROM video_progress vp
            JOIN playlists p ON vp.playlist_id = p.playlist_id
            WHERE vp.completed = 1
        """)
        completions = cursor.fetchall()

        for comp in completions:
            cert_id = f"CERT-{uuid.uuid4().hex[:8].upper()}"
            cursor.execute("""
                INSERT OR IGNORE INTO certificates (cert_id, user_email, course_title, playlist_id, issued_at, status, grade)
                VALUES (?, ?, ?, ?, ?, 'active', 'Pass')
            """, (cert_id, comp['user_email'], comp['playlist_title'], comp['playlist_id'], datetime.utcnow().isoformat()))

    # ── User Management ───────────────────────────────────────────────

    def update_user_status(self, email: str, status: str):
        """Update user active/suspended status"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = ? WHERE email = ?", (status, email))
        conn.commit()
        conn.close()

    def update_user_role(self, email: str, role: str):
        """Update user role (learner/admin/instructor)"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE email = ?", (role, email))
        conn.commit()
        conn.close()

    def delete_user(self, email: str):
        """Delete a user and all their data"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM quiz_attempts WHERE session_id IN (SELECT session_id FROM quiz_sessions WHERE user_email = ?)", (email,))
        cursor.execute("DELETE FROM quiz_questions WHERE session_id IN (SELECT session_id FROM quiz_sessions WHERE user_email = ?)", (email,))
        cursor.execute("DELETE FROM quiz_sessions WHERE user_email = ?", (email,))
        cursor.execute("DELETE FROM video_progress WHERE user_email = ?", (email,))
        cursor.execute("DELETE FROM user_playlists WHERE user_email = ?", (email,))
        cursor.execute("DELETE FROM subscriptions WHERE user_email = ?", (email,))
        cursor.execute("DELETE FROM certificates WHERE user_email = ?", (email,))
        cursor.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()
        conn.close()

    # ── Subscriptions & Billing ───────────────────────────────────────

    def get_all_subscriptions(self) -> List[Dict]:
        """Get all subscriptions with user info"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, u.name as user_name
            FROM subscriptions s
            JOIN users u ON s.user_email = u.email
            ORDER BY s.started_at DESC
        """)
        subs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return subs

    def get_billing_overview(self) -> Dict:
        """Get comprehensive billing overview"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Total revenue
        cursor.execute("SELECT COALESCE(SUM(amount), 0) as total FROM subscriptions WHERE status = 'active'")
        total_revenue = cursor.fetchone()['total']

        # Monthly revenue (current month)
        cursor.execute("""
            SELECT COALESCE(SUM(amount), 0) as mrr
            FROM subscriptions
            WHERE status = 'active'
              AND started_at >= datetime('now', 'start of month')
        """)
        monthly_revenue = cursor.fetchone()['mrr']
        # If no subs this month, use total as MRR approximation
        if monthly_revenue == 0:
            monthly_revenue = total_revenue

        # Plan breakdown
        cursor.execute("""
            SELECT plan, COUNT(*) as users, COALESCE(SUM(amount), 0) as revenue
            FROM subscriptions
            WHERE status = 'active'
            GROUP BY plan
        """)
        plan_breakdown = [dict(r) for r in cursor.fetchall()]

        # Active vs expired
        cursor.execute("SELECT COUNT(*) as c FROM subscriptions WHERE status = 'active'")
        active_subs = cursor.fetchone()['c']

        cursor.execute("SELECT COUNT(*) as c FROM subscriptions WHERE status = 'expired'")
        expired_subs = cursor.fetchone()['c']

        # Total users
        cursor.execute("SELECT COUNT(*) as c FROM users")
        total_users = cursor.fetchone()['c']

        # ARPU
        arpu = round(total_revenue / total_users, 2) if total_users > 0 else 0

        # Revenue trend (last 6 months simulated from data)
        revenue_trend = []
        months = ['Nov', 'Dec', 'Jan', 'Feb', 'Mar', 'Apr']
        import random
        random.seed(42)
        base = max(total_revenue * 0.3, 50)
        for i, m in enumerate(months):
            revenue_trend.append({
                'month': m,
                'revenue': round(base + (base * 0.15 * i) + random.uniform(-10, 20), 2)
            })
        revenue_trend[-1]['revenue'] = round(total_revenue, 2)

        # Recent transactions
        cursor.execute("""
            SELECT s.user_email, u.name as user_name, s.plan, s.amount, s.started_at, s.status
            FROM subscriptions s
            JOIN users u ON s.user_email = u.email
            ORDER BY s.started_at DESC
            LIMIT 10
        """)
        recent_transactions = [dict(r) for r in cursor.fetchall()]

        conn.close()

        return {
            'total_revenue': round(total_revenue, 2),
            'monthly_revenue': round(monthly_revenue, 2),
            'active_subscriptions': active_subs,
            'expired_subscriptions': expired_subs,
            'arpu': arpu,
            'mrr_growth': 12.5,
            'churn_rate': 3.2,
            'plan_breakdown': plan_breakdown,
            'revenue_trend': revenue_trend,
            'recent_transactions': recent_transactions,
            'total_users': total_users,
            'paid_users': active_subs,
            'free_users': total_users - active_subs if total_users > active_subs else 0,
        }

    def update_user_subscription(self, email: str, plan: str):
        """Update or create user subscription"""
        from datetime import datetime, timedelta
        conn = self._get_connection()
        cursor = conn.cursor()

        amounts = {'free': 0, 'pro_monthly': 29.99, 'pro_annual': 199.99, 'enterprise': 99.99}
        amount = amounts.get(plan, 0)
        now = datetime.utcnow()
        expires = now + timedelta(days=365 if 'annual' in plan else 30)

        cursor.execute("DELETE FROM subscriptions WHERE user_email = ?", (email,))
        cursor.execute("""
            INSERT INTO subscriptions (user_email, plan, status, started_at, expires_at, amount, payment_method)
            VALUES (?, ?, 'active', ?, ?, ?, ?)
        """, (email, plan, now.isoformat(), expires.isoformat(), amount, 'card' if amount > 0 else 'none'))
        conn.commit()
        conn.close()

    # ── Certificates ──────────────────────────────────────────────────

    def get_all_certificates(self) -> List[Dict]:
        """Get all issued certificates"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.*, u.name as user_name
            FROM certificates c
            JOIN users u ON c.user_email = u.email
            ORDER BY c.issued_at DESC
        """)
        certs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return certs

    def issue_certificate(self, user_email: str, course_title: str, playlist_id: str = '') -> Dict:
        """Issue a new certificate"""
        import uuid
        from datetime import datetime
        cert_id = f"CERT-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.utcnow().isoformat()

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO certificates (cert_id, user_email, course_title, playlist_id, issued_at, status, grade)
            VALUES (?, ?, ?, ?, ?, 'active', 'Pass')
        """, (cert_id, user_email, course_title, playlist_id, now))
        conn.commit()

        cursor.execute("SELECT c.*, u.name as user_name FROM certificates c JOIN users u ON c.user_email = u.email WHERE c.cert_id = ?", (cert_id,))
        cert = dict(cursor.fetchone())
        conn.close()
        return cert

    def revoke_certificate(self, cert_id: str):
        """Revoke a certificate"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE certificates SET status = 'revoked' WHERE cert_id = ?", (cert_id,))
        conn.commit()
        conn.close()

    # ── Course Management ─────────────────────────────────────────────

    def get_all_courses_admin(self) -> List[Dict]:
        """Get all courses with admin-level stats"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.playlist_id, p.playlist_title, p.total_videos, p.created_at,
                   COALESCE(p.status, 'active') as status,
                   COUNT(DISTINCT up.user_email) as enrolled_users,
                   COALESCE(SUM(CASE WHEN vp.completed = 1 THEN 1 ELSE 0 END), 0) as completions,
                   COALESCE(SUM(vp.watched_seconds), 0) as total_watch_time,
                   COUNT(DISTINCT vp.video_id) as videos_started
            FROM playlists p
            LEFT JOIN user_playlists up ON p.playlist_id = up.playlist_id
            LEFT JOIN video_progress vp ON p.playlist_id = vp.playlist_id
            GROUP BY p.playlist_id
            ORDER BY enrolled_users DESC
        """)
        courses = []
        for r in cursor.fetchall():
            course = dict(r)
            course['completion_rate'] = round(
                (course['completions'] / (course['enrolled_users'] * max(course['total_videos'], 1)) * 100), 1
            ) if course['enrolled_users'] > 0 else 0
            courses.append(course)
        conn.close()
        return courses

    def update_course_status(self, playlist_id: str, status: str):
        """Update course active/archived status"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE playlists SET status = ? WHERE playlist_id = ?", (status, playlist_id))
        conn.commit()
        conn.close()

    # ── Analytics & Reports ───────────────────────────────────────────

    def get_engagement_analytics(self) -> Dict:
        """Get comprehensive engagement analytics"""
        conn = self._get_connection()
        cursor = conn.cursor()
        analytics = {}

        # Daily active users (last 14 days)
        dau = []
        cursor.execute("""
            SELECT date(last_login) as day, COUNT(DISTINCT email) as users
            FROM users
            WHERE last_login >= datetime('now', '-14 days')
            GROUP BY date(last_login)
            ORDER BY day ASC
        """)
        for r in cursor.fetchall():
            dau.append({'day': r['day'], 'users': r['users']})
        analytics['daily_active_users'] = dau

        # Weekly learning hours (last 8 weeks)
        weekly = []
        for i in range(7, -1, -1):
            cursor.execute(f"""
                SELECT COALESCE(SUM(watched_seconds), 0) as total
                FROM video_progress
                WHERE last_updated >= datetime('now', '-{(i+1)*7} days')
                  AND last_updated < datetime('now', '-{i*7} days')
            """)
            weekly.append({
                'week': f'W{8-i}',
                'hours': round(cursor.fetchone()['total'] / 3600, 1)
            })
        analytics['weekly_learning_hours'] = weekly

        # Course completion rates
        cursor.execute("""
            SELECT p.playlist_title,
                   COUNT(DISTINCT up.user_email) as enrolled,
                   COALESCE(SUM(CASE WHEN vp.completed = 1 THEN 1 ELSE 0 END), 0) as completed
            FROM playlists p
            LEFT JOIN user_playlists up ON p.playlist_id = up.playlist_id
            LEFT JOIN video_progress vp ON p.playlist_id = vp.playlist_id
            GROUP BY p.playlist_id
            ORDER BY enrolled DESC
        """)
        analytics['course_completion_rates'] = [dict(r) for r in cursor.fetchall()]

        # Top performers
        cursor.execute("""
            SELECT u.name, u.email,
                   COALESCE(SUM(vp.watched_seconds), 0) as total_watch,
                   COUNT(CASE WHEN vp.completed = 1 THEN 1 END) as completions,
                   COUNT(DISTINCT qs.session_id) as quizzes,
                   COALESCE(
                       ROUND(SUM(CASE WHEN qa.is_correct = 1 THEN 1.0 ELSE 0 END) / NULLIF(COUNT(qa.id), 0) * 100, 1),
                       0
                   ) as quiz_accuracy
            FROM users u
            LEFT JOIN video_progress vp ON u.email = vp.user_email
            LEFT JOIN quiz_sessions qs ON u.email = qs.user_email
            LEFT JOIN quiz_attempts qa ON qs.session_id = qa.session_id
            GROUP BY u.email
            ORDER BY total_watch DESC
            LIMIT 10
        """)
        analytics['top_performers'] = [dict(r) for r in cursor.fetchall()]

        # User engagement distribution
        cursor.execute("""
            SELECT
                CASE
                    WHEN total_time = 0 THEN 'Inactive'
                    WHEN total_time < 600 THEN 'Low (<10m)'
                    WHEN total_time < 3600 THEN 'Medium (10m-1h)'
                    ELSE 'High (>1h)'
                END as segment,
                COUNT(*) as users
            FROM (
                SELECT u.email, COALESCE(SUM(vp.watched_seconds), 0) as total_time
                FROM users u
                LEFT JOIN video_progress vp ON u.email = vp.user_email
                GROUP BY u.email
            )
            GROUP BY segment
        """)
        analytics['engagement_distribution'] = [dict(r) for r in cursor.fetchall()]

        # Quiz performance overview
        cursor.execute("""
            SELECT
                COUNT(DISTINCT qs.session_id) as total_sessions,
                COUNT(qa.id) as total_attempts,
                COALESCE(SUM(CASE WHEN qa.is_correct = 1 THEN 1 ELSE 0 END), 0) as correct,
                COALESCE(AVG(qa.time_taken), 0) as avg_time_per_question
            FROM quiz_sessions qs
            LEFT JOIN quiz_attempts qa ON qs.session_id = qa.session_id
        """)
        quiz_row = cursor.fetchone()
        analytics['quiz_overview'] = {
            'total_sessions': quiz_row['total_sessions'],
            'total_attempts': quiz_row['total_attempts'],
            'correct_answers': quiz_row['correct'],
            'accuracy': round(quiz_row['correct'] / quiz_row['total_attempts'] * 100, 1) if quiz_row['total_attempts'] > 0 else 0,
            'avg_time_per_question': round(quiz_row['avg_time_per_question'], 1)
        }

        conn.close()
        return analytics

    def export_analytics_data(self) -> Dict:
        """Export all analytics data for download"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Users export
        cursor.execute("""
            SELECT u.email, u.name, u.created_at, u.last_login,
                   COALESCE(u.role, 'learner') as role,
                   COALESCE(u.status, 'active') as status,
                   COUNT(DISTINCT up.playlist_id) as courses,
                   COALESCE(SUM(vp.watched_seconds), 0) as watch_time,
                   COUNT(CASE WHEN vp.completed = 1 THEN 1 END) as completions
            FROM users u
            LEFT JOIN user_playlists up ON u.email = up.user_email
            LEFT JOIN video_progress vp ON u.email = vp.user_email
            GROUP BY u.email
        """)
        users = [dict(r) for r in cursor.fetchall()]

        # Courses export
        cursor.execute("""
            SELECT p.playlist_id, p.playlist_title, p.total_videos, p.created_at,
                   COUNT(DISTINCT up.user_email) as enrollments,
                   COALESCE(SUM(CASE WHEN vp.completed = 1 THEN 1 ELSE 0 END), 0) as completions
            FROM playlists p
            LEFT JOIN user_playlists up ON p.playlist_id = up.playlist_id
            LEFT JOIN video_progress vp ON p.playlist_id = vp.playlist_id
            GROUP BY p.playlist_id
        """)
        courses = [dict(r) for r in cursor.fetchall()]

        conn.close()
        return {'users': users, 'courses': courses, 'exported_at': datetime.utcnow().isoformat()}
