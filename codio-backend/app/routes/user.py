"""
Codio Backend - User Routes
Handles user playlists and video progress tracking.
Logic is unchanged from the original pause_to_code_api.py.
"""

import logging
import traceback
from datetime import datetime

from flask import Blueprint, request, jsonify

from app.utils.jwt_auth import token_required

logger = logging.getLogger(__name__)

user_bp = Blueprint('user', __name__, url_prefix='/api/v1/user')


def init_user_routes(db):
    """Register routes that depend on the shared database instance."""

    @user_bp.route('/<email>/playlists', methods=['GET'])
    @token_required
    def get_user_playlists(email):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== GET /api/v1/user/{email}/playlists START ==========")

        try:
            current_user = request.current_user
            if current_user['email'] != email:
                logger.warning(f"[{request_id}] Authorization failed: User {current_user['email']} attempted to access {email}'s playlists")
                return jsonify({
                    "success": False,
                    "error": "Unauthorized: You can only access your own playlists"
                }), 403

            logger.info(f"[{request_id}] Authorization verified for user: {email}")
            logger.info(f"[{request_id}] Fetching playlists for user: {email}")
            playlists = db.get_user_playlists(email)

            logger.info(f"[{request_id}] Found {len(playlists)} playlists for {email}")
            return jsonify({
                "success": True,
                "playlists": playlists
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/user/{email}/playlists END ==========\n")

    @user_bp.route('/playlist', methods=['POST'])
    @token_required
    def save_user_playlist():
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/user/playlist START ==========")

        try:
            data = request.get_json()

            required_fields = ['user_email', 'playlist_id', 'playlist_url', 'playlist_title', 'total_videos']
            for field in required_fields:
                if field not in data:
                    return jsonify({
                        "success": False,
                        "error": f"Missing {field} in request body"
                    }), 400

            user_email = data['user_email']
            playlist_id = data['playlist_id']
            playlist_url = data['playlist_url']
            playlist_title = data['playlist_title']
            total_videos = data['total_videos']

            logger.info(f"[{request_id}] Saving playlist {playlist_id} for user {user_email}")

            success1 = db.add_or_update_playlist(playlist_id, playlist_url, playlist_title, total_videos)
            success2 = db.link_user_to_playlist(user_email, playlist_id)

            if success1 and success2:
                logger.info(f"[{request_id}] Playlist saved successfully")
                return jsonify({
                    "success": True,
                    "message": "Playlist saved successfully"
                }), 200
            else:
                return jsonify({
                    "success": False,
                    "error": "Failed to save playlist"
                }), 500

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/user/playlist END ==========\n")

    @user_bp.route('/progress', methods=['POST'])
    @token_required
    def save_video_progress():
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/user/progress START ==========")

        try:
            data = request.get_json()

            required_fields = ['user_email', 'playlist_id', 'video_id', 'watched_seconds', 'duration', 'completed']
            for field in required_fields:
                if field not in data:
                    return jsonify({
                        "success": False,
                        "error": f"Missing {field} in request body"
                    }), 400

            user_email = data['user_email']
            playlist_id = data['playlist_id']
            video_id = data['video_id']
            watched_seconds = float(data['watched_seconds'])
            duration = float(data['duration'])
            completed = bool(data['completed'])

            logger.info(f"[{request_id}] Saving progress: {user_email}/{playlist_id}/{video_id}")

            success = db.save_video_progress(
                user_email, playlist_id, video_id,
                watched_seconds, duration, completed
            )

            if success:
                logger.info(f"[{request_id}] Progress saved successfully")
                return jsonify({
                    "success": True,
                    "message": "Progress saved successfully"
                }), 200
            else:
                return jsonify({
                    "success": False,
                    "error": "Failed to save progress"
                }), 500

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/user/progress END ==========\n")

    @user_bp.route('/<email>/playlist/<path:playlist_id>/progress', methods=['GET'])
    @token_required
    def get_playlist_progress(email, playlist_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== GET /api/v1/user/{email}/playlist/{playlist_id}/progress START ==========")

        try:
            logger.info(f"[{request_id}] Fetching progress for {email}/{playlist_id}")
            progress = db.get_playlist_progress(email, playlist_id)

            logger.info(f"[{request_id}] Found progress for {len(progress)} videos")
            return jsonify({
                "success": True,
                "progress": progress
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/user/{email}/playlist/{playlist_id}/progress END ==========\n")

    @user_bp.route('/<email>/playlist/<path:playlist_id>', methods=['DELETE'])
    @token_required
    def delete_user_playlist(email, playlist_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== DELETE /api/v1/user/{email}/playlist/{playlist_id} START ==========")

        try:
            logger.info(f"[{request_id}] Deleting playlist {playlist_id} for user {email}")
            success = db.delete_user_playlist(email, playlist_id)

            if success:
                logger.info(f"[{request_id}] Playlist deleted successfully")
                return jsonify({
                    "success": True,
                    "message": "Playlist deleted successfully"
                }), 200
            else:
                return jsonify({
                    "success": False,
                    "error": "Failed to delete playlist"
                }), 500

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== DELETE /api/v1/user/{email}/playlist/{playlist_id} END ==========\n")
