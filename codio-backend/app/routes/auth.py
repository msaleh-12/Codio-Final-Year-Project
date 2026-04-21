"""
Codio Backend - Authentication Routes
Handles signup, login, and token refresh.
Logic is unchanged from the original pause_to_code_api.py.
"""

import logging
import traceback
from datetime import datetime
from flask import Blueprint, request, jsonify

from app.utils.jwt_auth import jwt_manager

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


def init_auth_routes(db):
    """Register routes that depend on the shared database instance."""

    @auth_bp.route('/signup', methods=['POST'])
    def auth_signup():
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/auth/signup START ==========")

        try:
            data = request.get_json()

            required_fields = ['email', 'name', 'password']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({
                        "success": False,
                        "error": f"Missing or empty {field}"
                    }), 400

            email = data['email'].strip().lower()
            name = data['name'].strip()
            password = data['password']

            if '@' not in email or '.' not in email:
                return jsonify({
                    "success": False,
                    "error": "Invalid email format"
                }), 400

            if len(password) < 6:
                return jsonify({
                    "success": False,
                    "error": "Password must be at least 6 characters"
                }), 400

            if len(name) < 2:
                return jsonify({
                    "success": False,
                    "error": "Name must be at least 2 characters"
                }), 400

            logger.info(f"[{request_id}] Creating account for: {email}")

            result = db.create_user(email, name, password)

            if result['success']:
                logger.info(f"[{request_id}] Account created successfully")

                access_token = jwt_manager.generate_access_token(email, name)
                refresh_token = jwt_manager.generate_refresh_token(email)

                logger.info(f"[{request_id}] Signup complete for {email}")
                return jsonify({
                    "success": True,
                    "message": "Account created successfully",
                    "user": {
                        "email": email,
                        "name": name
                    },
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer"
                }), 201
            else:
                logger.warning(f"[{request_id}] Account creation failed: {result.get('error')}")
                status_code = 409 if "already registered" in result.get('error', '').lower() else 400
                return jsonify(result), status_code

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/auth/signup END ==========\n")

    @auth_bp.route('/login', methods=['POST'])
    def auth_login():
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/auth/login START ==========")

        try:
            data = request.get_json()

            if not data or 'email' not in data or 'password' not in data:
                return jsonify({
                    "success": False,
                    "error": "Missing email or password"
                }), 400

            email = data['email'].strip().lower()
            password = data['password']

            logger.info(f"[{request_id}] Login attempt for: {email}")

            result = db.authenticate_user(email, password)

            if result['success']:
                user_data = result['user']
                logger.info(f"[{request_id}] Authentication successful for {email}")

                access_token = jwt_manager.generate_access_token(user_data['email'], user_data['name'])
                refresh_token = jwt_manager.generate_refresh_token(user_data['email'])

                logger.info(f"[{request_id}] Login complete for {email}")
                return jsonify({
                    "success": True,
                    "user": user_data,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer"
                }), 200
            else:
                logger.warning(f"[{request_id}] Authentication failed for {email}: {result.get('error')}")
                return jsonify(result), 401

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/auth/login END ==========\n")

    @auth_bp.route('/refresh', methods=['POST'])
    def auth_refresh():
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/auth/refresh START ==========")

        try:
            data = request.get_json()

            if not data or 'refresh_token' not in data:
                logger.warning(f"[{request_id}] Missing refresh token in request")
                return jsonify({
                    "success": False,
                    "error": "Missing refresh_token in request body"
                }), 400

            refresh_token = data['refresh_token']

            logger.info(f"[{request_id}] Validating refresh token")

            is_valid, payload, error = jwt_manager.verify_token(refresh_token, token_type='refresh')

            if not is_valid:
                logger.warning(f"[{request_id}] Invalid refresh token: {error}")
                return jsonify({
                    "success": False,
                    "error": "Invalid or expired refresh token"
                }), 401

            email = payload.get('email')
            logger.info(f"[{request_id}] Refresh token valid for user: {email}")

            conn = db._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            conn.close()

            if not user:
                logger.error(f"[{request_id}] User not found in database: {email}")
                return jsonify({
                    "success": False,
                    "error": "User not found"
                }), 404

            logger.info(f"[{request_id}] Generating new access token for {email}")
            new_access_token = jwt_manager.generate_access_token(email, user['name'])

            logger.info(f"[{request_id}] Token refresh successful for {email}")
            return jsonify({
                "success": True,
                "access_token": new_access_token,
                "token_type": "Bearer"
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/auth/refresh END ==========\n")
