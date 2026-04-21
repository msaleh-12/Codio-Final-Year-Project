"""
Codio Database Enhancements
New tables and methods for bookmarks, notes, code history, notifications,
goals, leaderboard, and activity heatmap.
"""

import sqlite3
import json
import uuid
import logging
from datetime import datetime, date, timedelta
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def apply_enhancements(db):
    """Apply all enhancement tables and methods to the existing CodioDatabase instance."""
    _create_enhancement_tables(db)
    # Bind new methods to the db instance
    import types
    for name, func in _METHODS.items():
        setattr(db, name, types.MethodType(func, db))
    logger.info("[DB-Enhancements] All enhancement methods bound to database instance")


def _create_enhancement_tables(db):
    conn = db._get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS bookmarks (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            video_id TEXT NOT NULL,
            timestamp REAL NOT NULL,
            note TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_user_video ON bookmarks(user_email, video_id)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS video_notes (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            video_id TEXT NOT NULL,
            timestamp REAL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_notes_user_video ON video_notes(user_email, video_id)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS code_history (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            video_id TEXT,
            code TEXT NOT NULL,
            output TEXT DEFAULT '',
            error TEXT DEFAULT '',
            language TEXT DEFAULT 'python',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_code_history_user ON code_history(user_email, created_at)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_email, read, created_at)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL UNIQUE,
            weekly_minutes_target INTEGER DEFAULT 120,
            weekly_videos_target INTEGER DEFAULT 5,
            weekly_quizzes_target INTEGER DEFAULT 3,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_preferences (
            user_email TEXT PRIMARY KEY,
            editor_theme TEXT DEFAULT 'dark',
            playback_speed REAL DEFAULT 1.0,
            auto_resume INTEGER DEFAULT 1,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_email) REFERENCES users(email)
        )
    """)

    conn.commit()
    conn.close()
    logger.info("[DB-Enhancements] Enhancement tables created/verified")


# ── Method implementations ────────────────────────────────────────────

def _get_bookmarks(self, user_email: str, video_id: str) -> List[Dict]:
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM bookmarks WHERE user_email = ? AND video_id = ? ORDER BY timestamp", (user_email, video_id))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def _add_bookmark(self, user_email: str, video_id: str, timestamp: float, note: str = '') -> Dict:
    bk_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO bookmarks (id, user_email, video_id, timestamp, note, created_at) VALUES (?, ?, ?, ?, ?, ?)",
              (bk_id, user_email, video_id, timestamp, note, now))
    conn.commit()
    conn.close()
    return {'id': bk_id, 'user_email': user_email, 'video_id': video_id, 'timestamp': timestamp, 'note': note, 'created_at': now}

def _delete_bookmark(self, bookmark_id: str) -> bool:
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM bookmarks WHERE id = ?", (bookmark_id,))
    conn.commit()
    conn.close()
    return True

def _get_video_notes(self, user_email: str, video_id: str) -> List[Dict]:
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM video_notes WHERE user_email = ? AND video_id = ? ORDER BY COALESCE(timestamp, 0)", (user_email, video_id))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def _save_video_note(self, user_email: str, video_id: str, content: str, timestamp: float = None, note_id: str = None) -> Dict:
    now = datetime.utcnow().isoformat()
    conn = self._get_connection()
    c = conn.cursor()
    if note_id:
        c.execute("UPDATE video_notes SET content = ?, timestamp = ?, updated_at = ? WHERE id = ? AND user_email = ?",
                  (content, timestamp, now, note_id, user_email))
        conn.commit()
        c.execute("SELECT * FROM video_notes WHERE id = ?", (note_id,))
        row = dict(c.fetchone()) if c.fetchone() else {}
    else:
        note_id = str(uuid.uuid4())[:8]
        c.execute("INSERT INTO video_notes (id, user_email, video_id, timestamp, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (note_id, user_email, video_id, timestamp, content, now, now))
        conn.commit()
        row = {'id': note_id, 'user_email': user_email, 'video_id': video_id, 'timestamp': timestamp, 'content': content, 'created_at': now, 'updated_at': now}
    conn.close()
    return row

def _delete_video_note(self, note_id: str) -> bool:
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM video_notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()
    return True

def _save_code_run(self, user_email: str, video_id: str, code: str, output: str = '', error: str = '') -> Dict:
    run_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO code_history (id, user_email, video_id, code, output, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (run_id, user_email, video_id, code, output, error, now))
    conn.commit()
    conn.close()
    return {'id': run_id, 'created_at': now}

def _get_code_history(self, user_email: str, video_id: str = None, limit: int = 20) -> List[Dict]:
    conn = self._get_connection()
    c = conn.cursor()
    if video_id:
        c.execute("SELECT * FROM code_history WHERE user_email = ? AND video_id = ? ORDER BY created_at DESC LIMIT ?", (user_email, video_id, limit))
    else:
        c.execute("SELECT * FROM code_history WHERE user_email = ? ORDER BY created_at DESC LIMIT ?", (user_email, limit))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def _get_notifications(self, user_email: str, unread_only: bool = False) -> List[Dict]:
    conn = self._get_connection()
    c = conn.cursor()
    if unread_only:
        c.execute("SELECT * FROM notifications WHERE user_email = ? AND read = 0 ORDER BY created_at DESC LIMIT 50", (user_email,))
    else:
        c.execute("SELECT * FROM notifications WHERE user_email = ? ORDER BY created_at DESC LIMIT 50", (user_email,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def _add_notification(self, user_email: str, ntype: str, title: str, message: str) -> Dict:
    nid = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO notifications (id, user_email, type, title, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
              (nid, user_email, ntype, title, message, now))
    conn.commit()
    conn.close()
    return {'id': nid, 'type': ntype, 'title': title, 'message': message, 'read': 0, 'created_at': now}

def _mark_notification_read(self, notification_id: str) -> bool:
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("UPDATE notifications SET read = 1 WHERE id = ?", (notification_id,))
    conn.commit()
    conn.close()
    return True

def _mark_all_notifications_read(self, user_email: str) -> bool:
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("UPDATE notifications SET read = 1 WHERE user_email = ?", (user_email,))
    conn.commit()
    conn.close()
    return True

def _get_user_goals(self, user_email: str) -> Dict:
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM user_goals WHERE user_email = ?", (user_email,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {'user_email': user_email, 'weekly_minutes_target': 120, 'weekly_videos_target': 5, 'weekly_quizzes_target': 3}

def _update_user_goals(self, user_email: str, minutes: int = None, videos: int = None, quizzes: int = None) -> Dict:
    now = datetime.utcnow().isoformat()
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM user_goals WHERE user_email = ?", (user_email,))
    existing = c.fetchone()
    if existing:
        m = minutes if minutes is not None else existing['weekly_minutes_target']
        v = videos if videos is not None else existing['weekly_videos_target']
        q = quizzes if quizzes is not None else existing['weekly_quizzes_target']
        c.execute("UPDATE user_goals SET weekly_minutes_target = ?, weekly_videos_target = ?, weekly_quizzes_target = ?, updated_at = ? WHERE user_email = ?",
                  (m, v, q, now, user_email))
    else:
        m = minutes or 120
        v = videos or 5
        q = quizzes or 3
        c.execute("INSERT INTO user_goals (user_email, weekly_minutes_target, weekly_videos_target, weekly_quizzes_target, updated_at) VALUES (?, ?, ?, ?, ?)",
                  (user_email, m, v, q, now))
    conn.commit()
    conn.close()
    return {'user_email': user_email, 'weekly_minutes_target': m, 'weekly_videos_target': v, 'weekly_quizzes_target': q}

def _get_activity_heatmap(self, user_email: str, days: int = 90) -> List[Dict]:
    """Get daily activity data for heatmap (last N days)."""
    conn = self._get_connection()
    c = conn.cursor()
    start_date = (date.today() - timedelta(days=days)).isoformat()
    c.execute("""
        SELECT date(last_updated) as day, 
               COALESCE(SUM(watched_seconds), 0) as seconds,
               COUNT(DISTINCT video_id) as videos
        FROM video_progress
        WHERE user_email = ? AND date(last_updated) >= ?
        GROUP BY date(last_updated)
        ORDER BY day ASC
    """, (user_email, start_date))
    data = {r['day']: {'seconds': r['seconds'], 'videos': r['videos']} for r in c.fetchall()}
    conn.close()
    
    # Fill in missing days
    result = []
    current = date.today() - timedelta(days=days)
    while current <= date.today():
        day_str = current.isoformat()
        d = data.get(day_str, {'seconds': 0, 'videos': 0})
        result.append({'date': day_str, 'minutes': round(d['seconds'] / 60, 1), 'videos': d['videos']})
        current += timedelta(days=1)
    return result

def _get_leaderboard(self, limit: int = 10) -> List[Dict]:
    """Get top learners by watch time and quiz accuracy."""
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT u.name, u.email,
               COALESCE(SUM(vp.watched_seconds), 0) as total_watch_seconds,
               COUNT(CASE WHEN vp.completed = 1 THEN 1 END) as completions,
               COUNT(DISTINCT qs.session_id) as quiz_sessions,
               COALESCE(
                   ROUND(SUM(CASE WHEN qa.is_correct = 1 THEN 1.0 ELSE 0 END) / NULLIF(COUNT(qa.id), 0) * 100, 1),
                   0
               ) as quiz_accuracy
        FROM users u
        LEFT JOIN video_progress vp ON u.email = vp.user_email
        LEFT JOIN quiz_sessions qs ON u.email = qs.user_email
        LEFT JOIN quiz_attempts qa ON qs.session_id = qa.session_id
        GROUP BY u.email
        HAVING total_watch_seconds > 0
        ORDER BY total_watch_seconds DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    # Add rank
    for i, r in enumerate(rows):
        r['rank'] = i + 1
    return rows

def _get_user_preferences(self, user_email: str) -> Dict:
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM user_preferences WHERE user_email = ?", (user_email,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {'user_email': user_email, 'editor_theme': 'dark', 'playback_speed': 1.0, 'auto_resume': 1}

def _update_user_preferences(self, user_email: str, **kwargs) -> Dict:
    now = datetime.utcnow().isoformat()
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM user_preferences WHERE user_email = ?", (user_email,))
    existing = c.fetchone()
    if existing:
        prefs = dict(existing)
        for k, v in kwargs.items():
            if k in prefs and k != 'user_email':
                prefs[k] = v
        c.execute("UPDATE user_preferences SET editor_theme = ?, playback_speed = ?, auto_resume = ?, updated_at = ? WHERE user_email = ?",
                  (prefs['editor_theme'], prefs['playback_speed'], prefs['auto_resume'], now, user_email))
    else:
        prefs = {'user_email': user_email, 'editor_theme': 'dark', 'playback_speed': 1.0, 'auto_resume': 1}
        for k, v in kwargs.items():
            if k in prefs:
                prefs[k] = v
        c.execute("INSERT INTO user_preferences (user_email, editor_theme, playback_speed, auto_resume, updated_at) VALUES (?, ?, ?, ?, ?)",
                  (user_email, prefs['editor_theme'], prefs['playback_speed'], prefs['auto_resume'], now))
    conn.commit()
    conn.close()
    return prefs

def _get_quiz_history(self, user_email: str, limit: int = 20) -> List[Dict]:
    """Get quiz session history with scores for a user."""
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT qs.session_id, qs.video_id, qs.current_level, qs.learning_rate,
               qs.questions_answered, qs.correct_answers, qs.started_at, qs.ended_at,
               CASE WHEN qs.questions_answered > 0 
                    THEN ROUND(qs.correct_answers * 100.0 / qs.questions_answered, 1) 
                    ELSE 0 END as accuracy
        FROM quiz_sessions qs
        WHERE qs.user_email = ?
        ORDER BY qs.started_at DESC
        LIMIT ?
    """, (user_email, limit))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def _get_quiz_review(self, session_id: str) -> List[Dict]:
    """Get all questions and answers for a quiz session (review mode)."""
    conn = self._get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT qq.question_id, qq.question_type, qq.difficulty, qq.question_text,
               qq.options_json, qq.correct_answer, qq.explanation,
               qa.user_answer, qa.is_correct, qa.time_taken
        FROM quiz_questions qq
        LEFT JOIN quiz_attempts qa ON qq.question_id = qa.question_id
        WHERE qq.session_id = ?
        ORDER BY qq.created_at
    """, (session_id,))
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d['options'] = json.loads(d.get('options_json', '[]'))
        del d['options_json']
        rows.append(d)
    conn.close()
    return rows


# Registry of methods to bind
_METHODS = {
    'get_bookmarks': _get_bookmarks,
    'add_bookmark': _add_bookmark,
    'delete_bookmark': _delete_bookmark,
    'get_video_notes': _get_video_notes,
    'save_video_note': _save_video_note,
    'delete_video_note': _delete_video_note,
    'save_code_run': _save_code_run,
    'get_code_history': _get_code_history,
    'get_notifications': _get_notifications,
    'add_notification': _add_notification,
    'mark_notification_read': _mark_notification_read,
    'mark_all_notifications_read': _mark_all_notifications_read,
    'get_user_goals': _get_user_goals,
    'update_user_goals': _update_user_goals,
    'get_activity_heatmap': _get_activity_heatmap,
    'get_leaderboard': _get_leaderboard,
    'get_user_preferences': _get_user_preferences,
    'update_user_preferences': _update_user_preferences,
    'get_quiz_history': _get_quiz_history,
    'get_quiz_review': _get_quiz_review,
}
