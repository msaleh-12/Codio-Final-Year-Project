#!/usr/bin/env python3
"""
JWT Authentication Module
Handles token generation, validation, and user authentication
"""

import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from functools import wraps
from flask import request, jsonify
import logging

from config.settings import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_REFRESH_TOKEN_EXPIRE_DAYS,
)

logger = logging.getLogger(__name__)

logger.info(
    f"[JWT] Configuration loaded - Algorithm: {JWT_ALGORITHM}, "
    f"Access Token TTL: {JWT_ACCESS_TOKEN_EXPIRE_MINUTES}min, "
    f"Refresh Token TTL: {JWT_REFRESH_TOKEN_EXPIRE_DAYS}days"
)


class JWTAuthManager:
    """JWT Authentication Manager"""

    def __init__(self):
        """Initialize JWT manager"""
        self.secret_key = JWT_SECRET_KEY
        self.algorithm = JWT_ALGORITHM
        self.access_token_expire_minutes = JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = JWT_REFRESH_TOKEN_EXPIRE_DAYS

        if self.secret_key == 'default_secret_key_change_in_production':
            logger.warning("[JWT] WARNING: Using default JWT secret key. Change this in production!")

        logger.info("[JWT] JWT Authentication Manager initialized")

    def generate_access_token(self, user_email: str, user_name: str) -> str:
        """Generate JWT access token."""
        logger.info(f"[JWT] Generating access token for user: {user_email}")

        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=self.access_token_expire_minutes)

        payload = {
            'email': user_email,
            'name': user_name,
            'type': 'access',
            'iat': now,
            'exp': expires_at
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        logger.info(f"[JWT] Access token generated for {user_email}, expires at {expires_at.isoformat()}")
        return token

    def generate_refresh_token(self, user_email: str) -> str:
        """Generate JWT refresh token."""
        logger.info(f"[JWT] Generating refresh token for user: {user_email}")

        now = datetime.utcnow()
        expires_at = now + timedelta(days=self.refresh_token_expire_days)

        payload = {
            'email': user_email,
            'type': 'refresh',
            'iat': now,
            'exp': expires_at
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        logger.info(f"[JWT] Refresh token generated for {user_email}, expires at {expires_at.isoformat()}")
        return token

    def verify_token(self, token: str, token_type: str = 'access') -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Verify and decode JWT token."""
        logger.info(f"[JWT] Verifying {token_type} token")

        if not token:
            logger.warning("[JWT] Token verification failed: No token provided")
            return False, None, "No token provided"

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            if payload.get('type') != token_type:
                logger.warning(f"[JWT] Token type mismatch: expected {token_type}, got {payload.get('type')}")
                return False, None, f"Invalid token type: expected {token_type}"

            exp_timestamp = payload.get('exp')
            if exp_timestamp:
                exp_datetime = datetime.utcfromtimestamp(exp_timestamp)
                logger.info(f"[JWT] Token valid for user {payload.get('email')}, expires at {exp_datetime.isoformat()}")

            logger.info(f"[JWT] Token verified successfully for user: {payload.get('email')}")
            return True, payload, None

        except jwt.ExpiredSignatureError:
            logger.warning("[JWT] Token verification failed: Token has expired")
            return False, None, "Token has expired"

        except jwt.InvalidTokenError as e:
            logger.warning(f"[JWT] Token verification failed: Invalid token - {str(e)}")
            return False, None, f"Invalid token: {str(e)}"

        except Exception as e:
            logger.error(f"[JWT] Token verification failed with unexpected error: {str(e)}")
            return False, None, f"Token verification error: {str(e)}"

    def extract_token_from_header(self, auth_header: Optional[str]) -> Optional[str]:
        """Extract JWT token from Authorization header."""
        if not auth_header:
            logger.debug("[JWT] No Authorization header provided")
            return None

        parts = auth_header.split()

        if len(parts) != 2:
            logger.warning(f"[JWT] Invalid Authorization header format: {auth_header[:20]}...")
            return None

        scheme, token = parts

        if scheme.lower() != 'bearer':
            logger.warning(f"[JWT] Invalid Authorization scheme: {scheme}")
            return None

        logger.debug("[JWT] Token extracted from header successfully")
        return token

    def get_current_user(self, request) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Get current user from request."""
        logger.debug("[JWT] Extracting current user from request")

        auth_header = request.headers.get('Authorization')

        if not auth_header:
            logger.debug("[JWT] No Authorization header in request")
            return False, None, "No authorization header"

        token = self.extract_token_from_header(auth_header)

        if not token:
            logger.warning("[JWT] Failed to extract token from header")
            return False, None, "Invalid authorization header format"

        is_valid, payload, error = self.verify_token(token, token_type='access')

        if not is_valid:
            logger.warning(f"[JWT] Token validation failed: {error}")
            return False, None, error

        user_data = {
            'email': payload.get('email'),
            'name': payload.get('name')
        }

        logger.info(f"[JWT] Current user identified: {user_data['email']}")
        return True, user_data, None


# Global JWT manager instance
jwt_manager = JWTAuthManager()


def token_required(f):
    """Decorator to protect routes with JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[JWT][{request_id}] Checking authentication for {request.path}")

        is_authenticated, user_data, error = jwt_manager.get_current_user(request)

        if not is_authenticated:
            logger.warning(f"[JWT][{request_id}] Authentication failed: {error}")
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'message': error
            }), 401

        logger.info(f"[JWT][{request_id}] Authentication successful for {user_data['email']}")

        request.current_user = user_data

        return f(*args, **kwargs)

    return decorated


def optional_token(f):
    """Decorator that allows optional authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        logger.debug(f"[JWT] Optional auth check for {request.path}")

        is_authenticated, user_data, error = jwt_manager.get_current_user(request)

        if is_authenticated:
            logger.info(f"[JWT] Optional auth: User authenticated as {user_data['email']}")
            request.current_user = user_data
        else:
            logger.debug(f"[JWT] Optional auth: Continuing as guest ({error})")
            request.current_user = None

        return f(*args, **kwargs)

    return decorated
