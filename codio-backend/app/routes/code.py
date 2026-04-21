"""
Codio Backend - Code Execution & Completion Routes
Handles Python code execution proxy and AI-powered code completion.
Logic is unchanged from the original pause_to_code_api.py.
"""

import logging
import traceback
from datetime import datetime

import requests as http_requests
from flask import Blueprint, request, jsonify

from config.settings import PISTON_EXECUTE_URL, PISTON_TIMEOUT_SECONDS
from app.services.code_execution import (
    execute_python_code_locally,
    generate_ai_code_completion,
)

logger = logging.getLogger(__name__)

code_bp = Blueprint('code', __name__, url_prefix='/api/v1/code')


@code_bp.route('/execute', methods=['POST'])
def execute_python_code():
    """Execute Python code through backend proxy to avoid browser-side network/CORS issues."""
    request_id = f"exec_{datetime.now().timestamp()}"
    logger.info(f"[{request_id}] ========== POST /api/v1/code/execute START ==========")

    try:
        data = request.get_json() or {}
        code = data.get('code', '')

        if not isinstance(code, str) or not code.strip():
            return jsonify({
                "success": False,
                "error": "Missing code in request body"
            }), 400

        payload = {
            "language": "python",
            "version": "3.10.0",
            "files": [{"content": code}],
        }

        upstream = http_requests.post(
            PISTON_EXECUTE_URL,
            json=payload,
            timeout=PISTON_TIMEOUT_SECONDS,
        )

        upstream.raise_for_status()
        result = upstream.json() or {}
        run = result.get("run", {}) if isinstance(result, dict) else {}

        return jsonify({
            "success": True,
            "run": {
                "code": run.get("code", 1),
                "stdout": run.get("stdout", ""),
                "stderr": run.get("stderr", ""),
                "output": run.get("output", ""),
            }
        }), 200

    except http_requests.Timeout:
        logger.warning(f"[{request_id}] Upstream execution timed out. Falling back to local Python execution.")
        local_run = execute_python_code_locally(code)
        return jsonify({
            "success": True,
            "source": "local_python_fallback",
            "run": local_run,
        }), 200
    except http_requests.RequestException as e:
        logger.error(f"[{request_id}] Upstream execution request failed: {e}")
        local_run = execute_python_code_locally(code)
        return jsonify({
            "success": True,
            "source": "local_python_fallback",
            "run": local_run,
        }), 200
    except Exception as e:
        logger.error(f"[{request_id}] EXCEPTION: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    finally:
        logger.info(f"[{request_id}] ========== POST /api/v1/code/execute END ==========\n")


@code_bp.route('/complete', methods=['POST'])
def complete_python_code():
    """Generate inline Python completion for editor assistance."""
    request_id = f"complete_{datetime.now().timestamp()}"
    logger.info(f"[{request_id}] ========== POST /api/v1/code/complete START ==========")

    try:
        data = request.get_json() or {}
        code = data.get('code', '')
        cursor_position = data.get('cursor_position', 0)

        if not isinstance(code, str):
            return jsonify({
                "success": False,
                "error": "Invalid code payload"
            }), 400

        completion, source = generate_ai_code_completion(code, int(cursor_position or 0))

        return jsonify({
            "success": True,
            "completion": completion,
            "source": source,
        }), 200
    except Exception as e:
        logger.error(f"[{request_id}] EXCEPTION: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    finally:
        logger.info(f"[{request_id}] ========== POST /api/v1/code/complete END ==========\n")
