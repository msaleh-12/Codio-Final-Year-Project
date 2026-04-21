"""
Codio Backend - Admin Routes
Handles admin dashboard, user management, subscriptions, billing,
certificates, course management, and analytics.
"""

import logging
import traceback
from datetime import datetime

from flask import Blueprint, request, jsonify

from app.utils.jwt_auth import token_required

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/api/v1/admin')

ADMIN_EMAIL = 'admin@gmail.com'


def init_admin_routes(db):
    """Register admin routes that depend on the shared database instance."""

    def _require_admin():
        """Check if the current user is admin"""
        current_user = request.current_user
        return current_user and current_user.get('email') == ADMIN_EMAIL

    # ── Overview & Stats ──────────────────────────────────────────────

    @admin_bp.route('/stats', methods=['GET'])
    @token_required
    def get_system_stats():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            stats = db.get_system_stats()
            return jsonify({"success": True, "stats": stats}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting system stats: {e}")
            logger.error(traceback.format_exc())
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/enhanced-stats', methods=['GET'])
    @token_required
    def get_enhanced_stats():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            stats = db.get_enhanced_admin_stats()
            return jsonify({"success": True, "stats": stats}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting enhanced stats: {e}")
            logger.error(traceback.format_exc())
            return jsonify({"success": False, "error": str(e)}), 500

    # ── User Management ───────────────────────────────────────────────

    @admin_bp.route('/users', methods=['GET'])
    @token_required
    def get_all_users():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            users = db.get_all_users()
            return jsonify({"success": True, "users": users}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting all users: {e}")
            logger.error(traceback.format_exc())
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/user/<email>/stats', methods=['GET'])
    @token_required
    def get_user_stats(email):
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            stats = db.get_user_dashboard_stats(email)
            return jsonify({"success": True, "stats": stats}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting user stats: {e}")
            logger.error(traceback.format_exc())
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/user/<email>/toggle-status', methods=['POST'])
    @token_required
    def toggle_user_status(email):
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            data = request.get_json() or {}
            new_status = data.get('status', 'active')
            db.update_user_status(email, new_status)
            return jsonify({"success": True, "message": f"User status updated to {new_status}"}), 200
        except Exception as e:
            logger.error(f"[Admin] Error toggling user status: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/user/<email>/role', methods=['POST'])
    @token_required
    def update_user_role(email):
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            data = request.get_json() or {}
            new_role = data.get('role', 'learner')
            db.update_user_role(email, new_role)
            return jsonify({"success": True, "message": f"User role updated to {new_role}"}), 200
        except Exception as e:
            logger.error(f"[Admin] Error updating user role: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/user/<email>', methods=['DELETE'])
    @token_required
    def delete_user(email):
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        if email == ADMIN_EMAIL:
            return jsonify({"success": False, "error": "Cannot delete admin account"}), 400
        try:
            db.delete_user(email)
            return jsonify({"success": True, "message": "User deleted successfully"}), 200
        except Exception as e:
            logger.error(f"[Admin] Error deleting user: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    # ── Subscriptions & Billing ───────────────────────────────────────

    @admin_bp.route('/subscriptions', methods=['GET'])
    @token_required
    def get_subscriptions():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            subs = db.get_all_subscriptions()
            return jsonify({"success": True, "subscriptions": subs}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting subscriptions: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/billing/overview', methods=['GET'])
    @token_required
    def get_billing_overview():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            billing = db.get_billing_overview()
            return jsonify({"success": True, "billing": billing}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting billing overview: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/subscription/<email>/update', methods=['POST'])
    @token_required
    def update_subscription(email):
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            data = request.get_json() or {}
            plan = data.get('plan', 'free')
            db.update_user_subscription(email, plan)
            return jsonify({"success": True, "message": f"Subscription updated to {plan}"}), 200
        except Exception as e:
            logger.error(f"[Admin] Error updating subscription: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    # ── Certificates ──────────────────────────────────────────────────

    @admin_bp.route('/certificates', methods=['GET'])
    @token_required
    def get_certificates():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            certs = db.get_all_certificates()
            return jsonify({"success": True, "certificates": certs}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting certificates: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/certificate/issue', methods=['POST'])
    @token_required
    def issue_certificate():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            data = request.get_json() or {}
            cert = db.issue_certificate(
                user_email=data['user_email'],
                course_title=data['course_title'],
                playlist_id=data.get('playlist_id', '')
            )
            return jsonify({"success": True, "certificate": cert}), 200
        except Exception as e:
            logger.error(f"[Admin] Error issuing certificate: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/certificate/<cert_id>/revoke', methods=['POST'])
    @token_required
    def revoke_certificate(cert_id):
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            db.revoke_certificate(cert_id)
            return jsonify({"success": True, "message": "Certificate revoked"}), 200
        except Exception as e:
            logger.error(f"[Admin] Error revoking certificate: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    # ── Course Management ─────────────────────────────────────────────

    @admin_bp.route('/courses', methods=['GET'])
    @token_required
    def get_all_courses():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            courses = db.get_all_courses_admin()
            return jsonify({"success": True, "courses": courses}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting courses: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/course/<playlist_id>/toggle', methods=['POST'])
    @token_required
    def toggle_course_status(playlist_id):
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            data = request.get_json() or {}
            status = data.get('status', 'active')
            db.update_course_status(playlist_id, status)
            return jsonify({"success": True, "message": f"Course status updated to {status}"}), 200
        except Exception as e:
            logger.error(f"[Admin] Error toggling course: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    # ── Analytics & Reports ───────────────────────────────────────────

    @admin_bp.route('/analytics/engagement', methods=['GET'])
    @token_required
    def get_engagement_analytics():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            analytics = db.get_engagement_analytics()
            return jsonify({"success": True, "analytics": analytics}), 200
        except Exception as e:
            logger.error(f"[Admin] Error getting analytics: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/analytics/export', methods=['GET'])
    @token_required
    def export_analytics():
        if not _require_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        try:
            data = db.export_analytics_data()
            return jsonify({"success": True, "data": data}), 200
        except Exception as e:
            logger.error(f"[Admin] Error exporting analytics: {e}")
            return jsonify({"success": False, "error": str(e)}), 500


def init_dashboard_routes(db):
    """Register user dashboard routes."""

    @admin_bp.route('/dashboard/<email>', methods=['GET'])
    @token_required
    def get_user_dashboard(email):
        """Get dashboard stats for the logged-in user"""
        current_user = request.current_user
        if current_user['email'] != email and current_user['email'] != ADMIN_EMAIL:
            return jsonify({"success": False, "error": "Unauthorized"}), 403
        try:
            stats = db.get_user_dashboard_stats(email)
            return jsonify({"success": True, "stats": stats}), 200
        except Exception as e:
            logger.error(f"[Dashboard] Error getting dashboard stats: {e}")
            logger.error(traceback.format_exc())
            return jsonify({"success": False, "error": str(e)}), 500

    @admin_bp.route('/enhanced-dashboard/<email>', methods=['GET'])
    @token_required
    def get_enhanced_user_dashboard(email):
        """Get enhanced dashboard stats with streaks, achievements, weekly activity"""
        current_user = request.current_user
        if current_user['email'] != email and current_user['email'] != ADMIN_EMAIL:
            return jsonify({"success": False, "error": "Unauthorized"}), 403
        try:
            stats = db.get_enhanced_user_stats(email)
            return jsonify({"success": True, "stats": stats}), 200
        except Exception as e:
            logger.error(f"[Dashboard] Error getting enhanced dashboard stats: {e}")
            logger.error(traceback.format_exc())
            return jsonify({"success": False, "error": str(e)}), 500
