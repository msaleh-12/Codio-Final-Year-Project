"""
Codio Backend - Enhancement Routes
Handles bookmarks, notes, code history, notifications, goals, leaderboard,
preferences, quiz history/review, and AI-powered features.
"""

import logging
import os
from flask import Blueprint, request, jsonify
from app.utils.jwt_auth import token_required

logger = logging.getLogger(__name__)

enhance_bp = Blueprint('enhancements', __name__, url_prefix='/api/v1')


def init_enhancement_routes(db):
    """Register enhancement routes with the shared database instance."""

    # ── Bookmarks ─────────────────────────────────────────────────────

    @enhance_bp.route('/video/<video_id>/bookmarks', methods=['GET'])
    @token_required
    def get_bookmarks(video_id):
        email = request.current_user['email']
        bookmarks = db.get_bookmarks(email, video_id)
        return jsonify({'success': True, 'bookmarks': bookmarks})

    @enhance_bp.route('/video/<video_id>/bookmark', methods=['POST'])
    @token_required
    def add_bookmark(video_id):
        email = request.current_user['email']
        data = request.get_json()
        timestamp = data.get('timestamp', 0)
        note = data.get('note', '')
        bk = db.add_bookmark(email, video_id, timestamp, note)
        return jsonify({'success': True, 'bookmark': bk})

    @enhance_bp.route('/bookmark/<bookmark_id>', methods=['DELETE'])
    @token_required
    def delete_bookmark(bookmark_id):
        db.delete_bookmark(bookmark_id)
        return jsonify({'success': True})

    # ── Video Notes ───────────────────────────────────────────────────

    @enhance_bp.route('/video/<video_id>/notes', methods=['GET'])
    @token_required
    def get_notes(video_id):
        email = request.current_user['email']
        notes = db.get_video_notes(email, video_id)
        return jsonify({'success': True, 'notes': notes})

    @enhance_bp.route('/video/<video_id>/note', methods=['POST'])
    @token_required
    def save_note(video_id):
        email = request.current_user['email']
        data = request.get_json()
        note = db.save_video_note(email, video_id, data.get('content', ''), data.get('timestamp'), data.get('note_id'))
        return jsonify({'success': True, 'note': note})

    @enhance_bp.route('/note/<note_id>', methods=['DELETE'])
    @token_required
    def delete_note(note_id):
        db.delete_video_note(note_id)
        return jsonify({'success': True})

    # ── Code History ──────────────────────────────────────────────────

    @enhance_bp.route('/code/history', methods=['GET'])
    @token_required
    def get_code_history():
        email = request.current_user['email']
        video_id = request.args.get('video_id')
        limit = int(request.args.get('limit', 20))
        history = db.get_code_history(email, video_id, limit)
        return jsonify({'success': True, 'history': history})

    @enhance_bp.route('/code/save-run', methods=['POST'])
    @token_required
    def save_code_run():
        email = request.current_user['email']
        data = request.get_json()
        result = db.save_code_run(email, data.get('video_id', ''), data.get('code', ''), data.get('output', ''), data.get('error', ''))
        return jsonify({'success': True, 'run': result})

    # ── Notifications ─────────────────────────────────────────────────

    @enhance_bp.route('/notifications', methods=['GET'])
    @token_required
    def get_notifications():
        email = request.current_user['email']
        unread_only = request.args.get('unread', 'false').lower() == 'true'
        notifications = db.get_notifications(email, unread_only)
        return jsonify({'success': True, 'notifications': notifications})

    @enhance_bp.route('/notification/<nid>/read', methods=['POST'])
    @token_required
    def mark_read(nid):
        db.mark_notification_read(nid)
        return jsonify({'success': True})

    @enhance_bp.route('/notifications/read-all', methods=['POST'])
    @token_required
    def mark_all_read():
        email = request.current_user['email']
        db.mark_all_notifications_read(email)
        return jsonify({'success': True})

    # ── Goals ─────────────────────────────────────────────────────────

    @enhance_bp.route('/user/goals', methods=['GET'])
    @token_required
    def get_goals():
        email = request.current_user['email']
        goals = db.get_user_goals(email)
        return jsonify({'success': True, 'goals': goals})

    @enhance_bp.route('/user/goals', methods=['POST'])
    @token_required
    def update_goals():
        email = request.current_user['email']
        data = request.get_json()
        goals = db.update_user_goals(email, data.get('weekly_minutes_target'), data.get('weekly_videos_target'), data.get('weekly_quizzes_target'))
        return jsonify({'success': True, 'goals': goals})

    # ── Activity Heatmap ──────────────────────────────────────────────

    @enhance_bp.route('/user/activity-heatmap', methods=['GET'])
    @token_required
    def get_heatmap():
        email = request.current_user['email']
        days = int(request.args.get('days', 90))
        data = db.get_activity_heatmap(email, days)
        return jsonify({'success': True, 'heatmap': data})

    # ── Leaderboard ───────────────────────────────────────────────────

    @enhance_bp.route('/leaderboard', methods=['GET'])
    @token_required
    def get_leaderboard():
        limit = int(request.args.get('limit', 10))
        data = db.get_leaderboard(limit)
        return jsonify({'success': True, 'leaderboard': data})

    # ── Preferences ───────────────────────────────────────────────────

    @enhance_bp.route('/user/preferences', methods=['GET'])
    @token_required
    def get_preferences():
        email = request.current_user['email']
        prefs = db.get_user_preferences(email)
        return jsonify({'success': True, 'preferences': prefs})

    @enhance_bp.route('/user/preferences', methods=['POST'])
    @token_required
    def update_preferences():
        email = request.current_user['email']
        data = request.get_json()
        prefs = db.update_user_preferences(email, **data)
        return jsonify({'success': True, 'preferences': prefs})

    # ── Quiz History & Review ─────────────────────────────────────────

    @enhance_bp.route('/quiz/history', methods=['GET'])
    @token_required
    def get_quiz_history():
        email = request.current_user['email']
        limit = int(request.args.get('limit', 20))
        history = db.get_quiz_history(email, limit)
        return jsonify({'success': True, 'history': history})

    @enhance_bp.route('/quiz/review/<session_id>', methods=['GET'])
    @token_required
    def get_quiz_review(session_id):
        questions = db.get_quiz_review(session_id)
        return jsonify({'success': True, 'questions': questions})

    # ── AI Error Explanation ──────────────────────────────────────────

    @enhance_bp.route('/code/explain-error', methods=['POST'])
    @token_required
    def explain_error():
        data = request.get_json()
        code = data.get('code', '')
        error = data.get('error', '')
        if not error:
            return jsonify({'success': False, 'error': 'No error provided'})
        
        try:
            import google.generativeai as genai
            api_key = os.environ.get('PAUSE_TO_CODE_GEMINI_API_KEY') or os.environ.get('GEMINI_API_KEY')
            if not api_key:
                return jsonify({'success': True, 'explanation': f"Error: {error}\n\nTip: Check your code for syntax errors, undefined variables, or type mismatches."})
            
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-2.5-flash')
            prompt = f"""Explain this Python error in simple terms for a beginner. Be concise (2-3 sentences max).
Also suggest a fix.

Code:
```python
{code[:500]}
```

Error:
{error[:300]}

Format: 
**What went wrong:** [explanation]
**How to fix:** [suggestion]"""
            
            response = model.generate_content(prompt)
            return jsonify({'success': True, 'explanation': response.text})
        except Exception as e:
            logger.error(f"Error explanation failed: {e}")
            return jsonify({'success': True, 'explanation': f"Error: {error}\n\nTip: Check your code for syntax errors, undefined variables, or type mismatches."})

    # ── AI Transcript Summary ─────────────────────────────────────────

    @enhance_bp.route('/video/<video_id>/transcript/summary', methods=['POST'])
    @token_required
    def get_transcript_summary(video_id):
        data = request.get_json()
        transcript = data.get('transcript', '')
        if not transcript:
            return jsonify({'success': False, 'error': 'No transcript provided'})
        
        try:
            import google.generativeai as genai
            api_key = os.environ.get('PAUSE_TO_CODE_GEMINI_API_KEY') or os.environ.get('GEMINI_API_KEY')
            if not api_key:
                return jsonify({'success': False, 'error': 'AI service not configured'})
            
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-2.5-flash')
            prompt = f"""Analyze this video transcript and provide:

1. **Summary** (2-3 sentences)
2. **Key Points** (bullet list, max 5)
3. **Key Terms** (list of important technical terms mentioned)

Transcript:
{transcript[:3000]}

Format your response in clean markdown."""
            
            response = model.generate_content(prompt)
            return jsonify({'success': True, 'summary': response.text})
        except Exception as e:
            logger.error(f"Transcript summary failed: {e}")
            return jsonify({'success': False, 'error': str(e)})

    # ── AI Study Recommendations ──────────────────────────────────────

    @enhance_bp.route('/user/recommendations', methods=['GET'])
    @token_required
    def get_recommendations():
        email = request.current_user['email']
        try:
            # Get user stats for context
            stats = db.get_enhanced_user_stats(email)
            quiz_history = db.get_quiz_history(email, 5)
            
            # Build context
            weak_areas = []
            for qh in quiz_history:
                if qh.get('accuracy', 0) < 60:
                    weak_areas.append(f"Quiz session (accuracy: {qh['accuracy']}%)")
            
            recommendations = []
            
            # Rule-based recommendations (no AI cost)
            if stats.get('learning_streak', 0) == 0:
                recommendations.append({
                    'type': 'streak',
                    'title': 'Start a Learning Streak',
                    'description': 'Watch at least one video today to begin your streak!',
                    'priority': 'high'
                })
            
            if stats.get('quiz_sessions', 0) == 0:
                recommendations.append({
                    'type': 'quiz',
                    'title': 'Take Your First Quiz',
                    'description': 'Test your knowledge with an AI-generated quiz after watching a video.',
                    'priority': 'high'
                })
            elif stats.get('quiz_accuracy', 0) < 60:
                recommendations.append({
                    'type': 'review',
                    'title': 'Review Previous Topics',
                    'description': f'Your quiz accuracy is {stats.get("quiz_accuracy", 0)}%. Try re-watching recent videos and retaking quizzes.',
                    'priority': 'high'
                })
            
            if stats.get('videos_in_progress', 0) > 0:
                recommendations.append({
                    'type': 'continue',
                    'title': 'Continue Where You Left Off',
                    'description': f'You have {stats["videos_in_progress"]} videos in progress. Keep the momentum going!',
                    'priority': 'medium'
                })
            
            weekly_goal = stats.get('weekly_goal', {})
            if weekly_goal.get('progress_pct', 0) < 50:
                recommendations.append({
                    'type': 'goal',
                    'title': 'Reach Your Weekly Goal',
                    'description': f'You\'re at {weekly_goal.get("progress_pct", 0)}% of your weekly goal. Keep going!',
                    'priority': 'medium'
                })
            
            if stats.get('completed_videos', 0) >= 5 and stats.get('quiz_sessions', 0) < 3:
                recommendations.append({
                    'type': 'quiz',
                    'title': 'Challenge Yourself with Quizzes',
                    'description': 'You\'ve watched several videos. Test your understanding with quizzes!',
                    'priority': 'medium'
                })
            
            # Always add a general tip
            recommendations.append({
                'type': 'tip',
                'title': 'Use Pause to Code',
                'description': 'When you see code in a video, pause and practice it in the built-in compiler.',
                'priority': 'low'
            })
            
            return jsonify({'success': True, 'recommendations': recommendations[:5]})
        except Exception as e:
            logger.error(f"Recommendations failed: {e}")
            return jsonify({'success': True, 'recommendations': []})
