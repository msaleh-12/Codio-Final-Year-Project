#!/usr/bin/env python3
"""
Codio Pause-to-Code API Server
Flask REST API for video processing and code extraction with JWT Authentication
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import logging
from pathlib import Path
import traceback
from datetime import datetime
import os

# Import the main service, database, and JWT authentication
from pause_to_code_service import PauseToCodeService
from database import CodioDatabase
from jwt_auth import jwt_manager, token_required, optional_token

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend integration

# Initialize service and database
service = PauseToCodeService(cache_dir="codio_cache")
db = CodioDatabase(db_path="codio_cache/codio.db")

# Server startup timestamp (used to invalidate old sessions)
SERVER_START_TIME = datetime.now().isoformat()

# Request tracking
request_log = []


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Codio Pause-to-Code API",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "server_start_time": SERVER_START_TIME
    })


@app.route('/api/v1/video/process', methods=['POST'])
def process_video():
    """
    Process a YouTube video - supports both full processing and lazy loading
    
    Request body:
    {
        "youtube_url": "https://www.youtube.com/watch?v=...",
        "full_process": false (optional, default: false for lazy loading),
        "force_reprocess": false (optional)
    }
    
    Response:
    {
        "success": true,
        "video_id": "abc123",
        "video_title": "Python Tutorial",
        "duration": 600.5,
        "status": "completed",
        "message": "Video downloaded successfully"
    }
    """
    request_id = f"req_{datetime.now().timestamp()}"
    logger.info(f"[{request_id}] ========== /api/v1/video/process START ==========")
    
    try:
        logger.info(f"[{request_id}] Step 1: Parsing request JSON...")
        data = request.get_json()
        logger.info(f"[{request_id}] Step 2: Request data: {data}")
        
        if not data or 'youtube_url' not in data:
            logger.error(f"[{request_id}] ERROR - Missing youtube_url")
            return jsonify({
                "success": False,
                "error": "Missing youtube_url in request body"
            }), 400
        
        youtube_url = data['youtube_url']
        full_process = data.get('full_process', False)  # Default to lazy loading
        force_reprocess = data.get('force_reprocess', False)
        
        logger.info(f"[{request_id}] Step 3: URL={youtube_url}, full_process={full_process}")
        
        # Validate URL
        logger.info(f"[{request_id}] Step 4: Validating YouTube URL...")
        if not ('youtube.com' in youtube_url or 'youtu.be' in youtube_url):
            logger.error(f"[{request_id}] ERROR - Invalid YouTube URL")
            return jsonify({
                "success": False,
                "error": "Invalid YouTube URL"
            }), 400
        
        logger.info(f"[{request_id}] Step 5: URL validation passed")
        start_time = datetime.now()
        
        if full_process:
            # Full processing mode (extract all frames upfront)
            logger.info(f"[{request_id}] Step 6: Full processing mode")
            logger.info(f"[{request_id}] Step 7: Calling service.process_video()...")
            analysis = service.process_video(youtube_url, force_reprocess)
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Log request
            request_log.append({
                "timestamp": datetime.now().isoformat(),
                "endpoint": "/api/v1/video/process",
                "video_id": analysis.video_id,
                "processing_time": processing_time,
                "mode": "full"
            })
            
            return jsonify({
                "success": True,
                "video_id": analysis.video_id,
                "video_title": analysis.video_title,
                "duration": analysis.duration,
                "total_segments": len(analysis.code_segments),
                "processing_time": processing_time,
                "extraction_date": analysis.extraction_date,
                "status": "completed",
                "message": "Video processed successfully"
            }), 200
        else:
            # Lazy loading mode (download only, extract frames on-demand)
            logger.info(f"[{request_id}] Step 6: Lazy loading mode (download only)")
            logger.info(f"[{request_id}] Step 7: Calling service.download_video_only()...")
            result = service.download_video_only(youtube_url)
            processing_time = (datetime.now() - start_time).total_seconds()
            logger.info(f"[{request_id}] Step 8: Download completed in {processing_time}s")
            logger.info(f"[{request_id}] Step 9: Result: {result}")
            
            # Log request
            request_log.append({
                "timestamp": datetime.now().isoformat(),
                "endpoint": "/api/v1/video/process",
                "video_id": result['video_id'],
                "processing_time": processing_time,
                "mode": "lazy"
            })
            
            return jsonify({
                "success": True,
                **result,
                "processing_time": processing_time
            }), 200
        
    except Exception as e:
        logger.error(f"[{request_id}] EXCEPTION: {e}")
        logger.error(f"[{request_id}] Type: {type(e).__name__}")
        logger.error(f"[{request_id}] Traceback:")
        logger.error(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": str(e),
            "message": "Failed to process video"
        }), 500
    finally:
        logger.info(f"[{request_id}] ========== /api/v1/video/process END ==========\n")


@app.route('/api/v1/video/<video_id>/code', methods=['GET'])
def get_code_at_timestamp(video_id):
    """
    Get code at specific timestamp
    
    Query parameters:
    - timestamp: float (required) - timestamp in seconds
    - tolerance: float (optional, default=2.0) - tolerance in seconds
    
    Response:
    {
        "found": true,
        "timestamp_requested": 120.5,
        "timestamp_actual": 121.0,
        "time_difference": 0.5,
        "segment_type": "code",
        "code_content": "def hello():\n    print('Hello')",
        "explanation_text": null,
        "confidence": 0.95,
        "language": "python",
        "code_complete": true
    }
    """
    try:
        timestamp = request.args.get('timestamp', type=float)
        tolerance = request.args.get('tolerance', type=float, default=2.0)
        
        if timestamp is None:
            return jsonify({
                "success": False,
                "error": "Missing timestamp parameter"
            }), 400
        
        logger.info(f"Getting code for video {video_id} at timestamp {timestamp}s")
        
        result = service.get_code_at_timestamp(video_id, timestamp, tolerance)
        
        if "error" in result:
            return jsonify({
                "success": False,
                **result
            }), 404
        
        return jsonify({
            "success": True,
            **result
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting code at timestamp: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/v1/video/<video_id>/segments', methods=['GET'])
def get_all_segments(video_id):
    """
    Get all code segments for a video
    
    Query parameters:
    - type: string (optional) - filter by segment type (code/explanation/mixed)
    - min_confidence: float (optional) - minimum confidence threshold
    
    Response:
    {
        "success": true,
        "video_id": "abc123",
        "total_segments": 45,
        "segments": [...]
    }
    """
    try:
        segment_type = request.args.get('type', type=str)
        min_confidence = request.args.get('min_confidence', type=float, default=0.0)
        
        logger.info(f"Getting all segments for video {video_id}")
        
        segments = service.get_all_code_segments(video_id)
        
        if not segments:
            return jsonify({
                "success": False,
                "error": "Video not found or not processed",
                "video_id": video_id
            }), 404
        
        # Apply filters
        if segment_type:
            segments = [s for s in segments if s['segment_type'] == segment_type]
        
        if min_confidence > 0:
            segments = [s for s in segments if s['confidence'] >= min_confidence]
        
        return jsonify({
            "success": True,
            "video_id": video_id,
            "total_segments": len(segments),
            "segments": segments
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting segments: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/v1/video/<video_id>/timeline', methods=['GET'])
def get_code_timeline(video_id):
    """
    Get complete code timeline in markdown format
    
    Response: Markdown file download
    """
    try:
        output_file = f"timeline_{video_id}.md"
        service.export_code_timeline(video_id, output_file)
        
        if not os.path.exists(output_file):
            return jsonify({
                "success": False,
                "error": "Failed to generate timeline"
            }), 500
        
        return send_file(
            output_file,
            as_attachment=True,
            download_name=f"code_timeline_{video_id}.md",
            mimetype='text/markdown'
        )
        
    except Exception as e:
        logger.error(f"Error generating timeline: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/v1/video/<video_id>/info', methods=['GET'])
def get_video_info(video_id):
    """
    Get video metadata and processing information
    
    Response:
    {
        "success": true,
        "video_id": "abc123",
        "video_title": "Python Tutorial",
        "duration": 600.5,
        "total_segments": 45,
        "metadata": {...},
        "extraction_date": "2025-01-01T12:00:00"
    }
    """
    try:
        cache_file = Path(service.cache_dir) / f"{video_id}_analysis.json"
        
        if not cache_file.exists():
            return jsonify({
                "success": False,
                "error": "Video not found",
                "video_id": video_id
            }), 404
        
        analysis = service._load_cached_analysis(cache_file)
        
        return jsonify({
            "success": True,
            "video_id": analysis.video_id,
            "video_title": analysis.video_title,
            "duration": analysis.duration,
            "total_segments": len(analysis.code_segments),
            "total_frames_analyzed": analysis.total_frames_analyzed,
            "metadata": analysis.metadata,
            "extraction_date": analysis.extraction_date
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting video info: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/v1/videos', methods=['GET'])
def list_processed_videos():
    """
    List all processed videos
    
    Response:
    {
        "success": true,
        "total_videos": 10,
        "videos": [
            {
                "video_id": "abc123",
                "video_title": "Python Tutorial",
                "duration": 600.5,
                "extraction_date": "2025-01-01T12:00:00"
            },
            ...
        ]
    }
    """
    try:
        cache_dir = Path(service.cache_dir)
        analysis_files = list(cache_dir.glob("*_analysis.json"))
        
        videos = []
        for file in analysis_files:
            try:
                analysis = service._load_cached_analysis(file)
                videos.append({
                    "video_id": analysis.video_id,
                    "video_title": analysis.video_title,
                    "duration": analysis.duration,
                    "total_segments": len(analysis.code_segments),
                    "extraction_date": analysis.extraction_date
                })
            except Exception as e:
                logger.error(f"Error loading {file}: {e}")
                continue
        
        return jsonify({
            "success": True,
            "total_videos": len(videos),
            "videos": sorted(videos, key=lambda x: x['extraction_date'], reverse=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing videos: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
    """
    Get API usage statistics
    
    Response:
    {
        "success": true,
        "total_requests": 100,
        "total_videos_processed": 10,
        "cache_size_mb": 1234.5,
        "recent_requests": [...]
    }
    """
    try:
        cache_dir = Path(service.cache_dir)
        
        # Calculate cache size
        total_size = sum(f.stat().st_size for f in cache_dir.rglob('*') if f.is_file())
        cache_size_mb = total_size / (1024 * 1024)
        
        # Count processed videos
        analysis_files = list(cache_dir.glob("*_analysis.json"))
        
        return jsonify({
            "success": True,
            "total_requests": len(request_log),
            "total_videos_processed": len(analysis_files),
            "cache_size_mb": round(cache_size_mb, 2),
            "recent_requests": request_log[-10:]  # Last 10 requests
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


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


@app.route('/api/v1/playlist/videos', methods=['POST'])
def get_playlist_videos():
    """
    Extract video list from YouTube playlist
    
    Request body:
    {
        "playlist_url": "https://www.youtube.com/playlist?list=..."
    }
    
    Response:
    {
        "success": true,
        "playlist_title": "My Awesome Playlist",
        "videos": [
            {
                "video_id": "abc123",
                "title": "Video Title",
                "thumbnail": "https://...",
                "duration": 600
            }
        ]
    }
    """
    request_id = f"playlist_{datetime.now().timestamp()}"
    logger.info(f"[{request_id}] ========== /api/v1/playlist/videos START ==========")
    
    try:
        logger.info(f"[{request_id}] Step 1: Parsing request JSON...")
        data = request.get_json()
        logger.info(f"[{request_id}] Step 2: Request data: {data}")
        
        if not data or 'playlist_url' not in data:
            logger.error(f"[{request_id}] ERROR - Missing playlist_url")
            return jsonify({
                "success": False,
                "error": "Missing playlist_url in request body"
            }), 400
        
        playlist_url = data['playlist_url']
        logger.info(f"[{request_id}] Step 3: Playlist URL: {playlist_url}")
        logger.info(f"[{request_id}] Step 4: Calling service.get_playlist_videos()...")
        result = service.get_playlist_videos(playlist_url)
        logger.info(f"[{request_id}] Step 5: Retrieved {len(result['videos'])} videos")
        logger.info(f"[{request_id}] Step 6: Playlist title: {result['playlist_title']}")
        logger.info(f"[{request_id}] Step 7: Videos: {[v['video_id'] for v in result['videos']]}")
        
        logger.info(f"[{request_id}] Step 8: Returning success response")
        return jsonify({
            "success": True,
            "playlist_title": result['playlist_title'],
            "videos": result['videos']
        }), 200
        
    except Exception as e:
        logger.error(f"[{request_id}] EXCEPTION: {e}")
        logger.error(f"[{request_id}] Type: {type(e).__name__}")
        logger.error(f"[{request_id}] Traceback:")
        logger.error(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    finally:
        logger.info(f"[{request_id}] ========== /api/v1/playlist/videos END ==========\n")


@app.route('/api/v1/video/<video_id>/status', methods=['GET'])
def get_video_status(video_id):
    """
    Get processing status of a video
    
    Response:
    {
        "success": true,
        "video_id": "abc123",
        "status": "processing|completed|not_found",
        "progress": 45.5
    }
    """
    request_id = f"status_{datetime.now().timestamp()}"
    logger.info(f"[{request_id}] ========== /api/v1/video/{video_id}/status START ==========")
    
    try:
        logger.info(f"[{request_id}] Step 1: Calling service.get_video_status({video_id})...")
        status = service.get_video_status(video_id)
        logger.info(f"[{request_id}] Step 2: Status retrieved: {status}")
        
        logger.info(f"[{request_id}] Step 3: Returning success response")
        return jsonify({
            "success": True,
            **status
        }), 200
        
    except Exception as e:
        logger.error(f"[{request_id}] EXCEPTION: {e}")
        logger.error(f"[{request_id}] Traceback:")
        logger.error(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    finally:
        logger.info(f"[{request_id}] ========== /api/v1/video/{video_id}/status END ==========\n")


@app.route('/api/v1/video/<video_id>/cancel', methods=['POST'])
def cancel_video_processing(video_id):
    """
    Cancel ongoing video processing
    
    Response:
    {
        "success": true,
        "message": "Processing cancelled"
    }
    """
    try:
        service.cancel_video_processing(video_id)
        
        return jsonify({
            "success": True,
            "message": "Processing cancelled"
        }), 200
        
    except Exception as e:
        logger.error(f"Error cancelling video: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/v1/video/<video_id>/frame', methods=['GET'])
def get_frame_at_timestamp(video_id):
    """
    Extract and analyze frame at specific timestamp
    This is called when user pauses and video is already processed
    
    Query parameters:
    - timestamp: float (required) - timestamp in seconds
    
    Response:
    {
        "success": true,
        "code_content": "...",
        "segment_type": "code|learning"
    }
    """
    request_id = f"frame_{datetime.now().timestamp()}"
    logger.info(f"[{request_id}] ========== /api/v1/video/{video_id}/frame START ==========")
    
    try:
        logger.info(f"[{request_id}] Step 1: Parsing query parameters...")
        timestamp = request.args.get('timestamp', type=float)
        playlist_id = request.args.get('playlist_id', type=str)
        logger.info(f"[{request_id}] Step 2: Timestamp: {timestamp}, Playlist ID: {playlist_id}")
        
        if timestamp is None:
            logger.error(f"[{request_id}] ERROR - Missing timestamp parameter")
            return jsonify({
                "success": False,
                "error": "Missing timestamp parameter"
            }), 400
        
        logger.info(f"[{request_id}] Step 3: Calling service.extract_frame_and_analyze({video_id}, {timestamp}, {playlist_id})...")
        result = service.extract_frame_and_analyze(video_id, timestamp, playlist_id)
        logger.info(f"[{request_id}] Step 4: Frame analysis result: {result}")
        
        logger.info(f"[{request_id}] Step 5: Returning success response")
        return jsonify({
            "success": True,
            **result
        }), 200
        
    except Exception as e:
        logger.error(f"[{request_id}] EXCEPTION: {e}")
        logger.error(f"[{request_id}] Type: {type(e).__name__}")
        logger.error(f"[{request_id}] Traceback:")
        logger.error(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    finally:
        logger.info(f"[{request_id}] ========== /api/v1/video/{video_id}/frame END ==========\n")


# ============================================================================
# USER PLAYLIST AND PROGRESS ENDPOINTS
# ============================================================================



@app.route('/api/v1/auth/signup', methods=['POST'])
def auth_signup():
    """
    Create a new user account
    
    Request body:
    {
        "email": "newuser@codio.com",
        "name": "New User",
        "password": "securepassword123"
    }
    
    Response:
    {
        "success": true,
        "message": "Account created successfully"
    }
    """
    request_id = f"req_{datetime.now().timestamp()}"
    logger.info(f"[{request_id}] ========== POST /api/v1/auth/signup START ==========")
    
    try:
        data = request.get_json()
        
        # Validate required fields
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
        
        # Validate email format
        if '@' not in email or '.' not in email:
            return jsonify({
                "success": False,
                "error": "Invalid email format"
            }), 400
        
        # Validate password length
        if len(password) < 6:
            return jsonify({
                "success": False,
                "error": "Password must be at least 6 characters"
            }), 400
        
        # Validate name length
        if len(name) < 2:
            return jsonify({
                "success": False,
                "error": "Name must be at least 2 characters"
            }), 400
        
        logger.info(f"[{request_id}] Creating account for: {email}")
        
        # Create user in database
        result = db.create_user(email, name, password)
        
        if result['success']:
            logger.info(f"[{request_id}] Account created successfully")
            
            # Generate JWT tokens
            logger.info(f"[{request_id}] Generating JWT tokens for new user")
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
            # Return 409 for duplicate email, 400 for other errors
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


@app.route('/api/v1/auth/login', methods=['POST'])
def auth_login():
    """
    Authenticate user with email and password
    
    Request body:
    {
        "email": "student@codio.com",
        "password": "password123"
    }
    
    Response:
    {
        "success": true,
        "user": {
            "email": "student@codio.com",
            "name": "Muhammad Saleh"
        }
    }
    """
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
        
        # Authenticate user
        result = db.authenticate_user(email, password)
        
        if result['success']:
            user_data = result['user']
            logger.info(f"[{request_id}] Authentication successful for {email}")
            
            # Generate JWT tokens
            logger.info(f"[{request_id}] Generating JWT tokens for user")
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


@app.route('/api/v1/auth/refresh', methods=['POST'])
def auth_refresh():
    """
    Refresh access token using refresh token
    
    Request body:
    {
        "refresh_token": "<refresh_token>"
    }
    
    Response:
    {
        "success": true,
        "access_token": "<new_access_token>",
        "token_type": "Bearer"
    }
    """
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
        
        # Verify refresh token
        is_valid, payload, error = jwt_manager.verify_token(refresh_token, token_type='refresh')
        
        if not is_valid:
            logger.warning(f"[{request_id}] Invalid refresh token: {error}")
            return jsonify({
                "success": False,
                "error": "Invalid or expired refresh token"
            }), 401
        
        email = payload.get('email')
        logger.info(f"[{request_id}] Refresh token valid for user: {email}")
        
        # Get user info from database
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
        
        # Generate new access token
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


@app.route('/api/v1/user/<email>/playlists', methods=['GET'])
@token_required
def get_user_playlists(email):
    """
    Get all playlists for a specific user with progress
    
    Response:
    {
        "success": true,
        "playlists": [
            {
                "playlist_id": "abc123",
                "playlist_url": "https://...",
                "playlist_title": "Python Basics",
                "total_videos": 10,
                "completed_videos": 5,
                "progress_percentage": 50.0,
                "first_accessed": "2024-01-15T10:30:00",
                "last_accessed": "2024-01-16T14:20:00"
            }
        ]
    }
    """
    request_id = f"req_{datetime.now().timestamp()}"
    logger.info(f"[{request_id}] ========== GET /api/v1/user/{email}/playlists START ==========")
    
    try:
        # Verify user can only access their own data
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


@app.route('/api/v1/user/playlist', methods=['POST'])
@token_required
def save_user_playlist():
    """
    Save a playlist for a user
    
    Request body:
    {
        "user_email": "student@codio.com",
        "playlist_id": "abc123",
        "playlist_url": "https://...",
        "playlist_title": "Python Basics",
        "total_videos": 10
    }
    """
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
        
        # Save playlist
        success1 = db.add_or_update_playlist(playlist_id, playlist_url, playlist_title, total_videos)
        
        # Link user to playlist
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


@app.route('/api/v1/user/progress', methods=['POST'])
@token_required
def save_video_progress():
    """
    Save video watch progress for a user
    
    Request body:
    {
        "user_email": "student@codio.com",
        "playlist_id": "abc123",
        "video_id": "xyz789",
        "watched_seconds": 120.5,
        "duration": 300.0,
        "completed": false
    }
    """
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


@app.route('/api/v1/user/<email>/playlist/<playlist_id>/progress', methods=['GET'])
@token_required
def get_playlist_progress(email, playlist_id):
    """
    Get detailed progress for a specific playlist
    
    Response:
    {
        "success": true,
        "progress": {
            "video_id_1": {
                "watchedSeconds": 120.5,
                "duration": 300.0,
                "completed": false,
                "lastUpdated": "2024-01-15T10:30:00"
            },
            ...
        }
    }
    """
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


@app.route('/api/v1/user/<email>/playlist/<playlist_id>', methods=['DELETE'])
@token_required
def delete_user_playlist(email, playlist_id):
    """
    Delete a playlist from user's list (removes progress too)
    """
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


if __name__ == '__main__':
    logger.info("Starting Codio Pause-to-Code API Server")
    logger.info("API Documentation: http://localhost:8080/health")
    
    # Run the Flask app
    app.run(
        host='0.0.0.0',
        port=8080,
        debug=False,  # Set to True for development
        threaded=True
    )