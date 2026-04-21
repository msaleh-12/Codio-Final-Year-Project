"""
Codio Backend - Application Entry Point
Creates the Flask app, registers all blueprints, and starts the server.
"""

import logging
from datetime import datetime

from flask import Flask, jsonify
from flask_cors import CORS

from config.settings import APP_HOST, APP_PORT, APP_DEBUG, CACHE_DIR, DB_PATH
from config.logging import setup_logging

from app.models.database import CodioDatabase
from app.services.pause_to_code import PauseToCodeService

from app.routes.auth import auth_bp, init_auth_routes
from app.routes.video import video_bp, init_video_routes
from app.routes.code import code_bp
from app.routes.user import user_bp, init_user_routes
from app.routes.quiz import quiz_bp, init_quiz_routes
from app.routes.admin import admin_bp, init_admin_routes, init_dashboard_routes
from app.routes.enhancements import enhance_bp, init_enhancement_routes
from app.models.db_enhancements import apply_enhancements


def create_app():
    """Application factory: create and configure the Flask app."""

    # Set up logging
    setup_logging()
    logger = logging.getLogger(__name__)

    # Create Flask app
    app = Flask(__name__)
    CORS(app)

    # Initialize shared services
    service = PauseToCodeService(cache_dir=CACHE_DIR)
    db = CodioDatabase(db_path=DB_PATH)

    # Apply database enhancements (new tables + methods)
    apply_enhancements(db)

    # Initialize route modules with shared dependencies
    init_auth_routes(db)
    init_video_routes(service)
    init_user_routes(db)
    init_quiz_routes(db, service)
    init_admin_routes(db)
    init_dashboard_routes(db)
    init_enhancement_routes(db)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(video_bp)
    app.register_blueprint(code_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(quiz_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(enhance_bp)

    # ------------------------------------------------------------------
    # Global routes (health, error handlers)
    # ------------------------------------------------------------------

    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            "status": "healthy",
            "service": "Codio Pause-to-Code API",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        })

    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        return jsonify({
            "success": False,
            "error": "Endpoint not found",
            "message": "Please check the API documentation"
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors"""
        logger.error(f"Internal server error: {error}")
        return jsonify({
            "success": False,
            "error": "Internal server error",
            "message": "Please try again later or contact support"
        }), 500

    logger.info("Codio Flask application created and configured")
    return app


# ------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------

if __name__ == '__main__':
    app = create_app()
    logger = logging.getLogger(__name__)
    logger.info("Starting Codio Pause-to-Code API Server")
    logger.info(f"API Documentation: http://{APP_HOST}:{APP_PORT}/health")

    app.run(
        host=APP_HOST,
        port=APP_PORT,
        debug=APP_DEBUG,
        threaded=True
    )
