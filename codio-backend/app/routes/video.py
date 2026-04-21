"""
Codio Backend - Video Routes
Handles video processing, status, playlist extraction, transcript, and concept detection.
Logic is unchanged from the original pause_to_code_api.py.
"""

import os
import logging
import traceback
from datetime import datetime
from pathlib import Path
from dataclasses import asdict

from flask import Blueprint, request, jsonify, send_file

from app.utils.helpers import sanitize_error_text

logger = logging.getLogger(__name__)

video_bp = Blueprint('video', __name__, url_prefix='/api/v1')

# Module-level request log (shared across requests in this blueprint)
request_log = []


def init_video_routes(service):
    """Register routes that depend on the shared PauseToCodeService instance."""

    # ------------------------------------------------------------------
    # Video processing
    # ------------------------------------------------------------------

    @video_bp.route('/video/process', methods=['POST'])
    def process_video():
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
            full_process = data.get('full_process', False)
            force_reprocess = data.get('force_reprocess', False)

            logger.info(f"[{request_id}] Step 3: URL={youtube_url}, full_process={full_process}")

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
                logger.info(f"[{request_id}] Step 6: Full processing mode")
                logger.info(f"[{request_id}] Step 7: Calling service.process_video()...")
                analysis = service.process_video(youtube_url, force_reprocess)
                processing_time = (datetime.now() - start_time).total_seconds()

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
                logger.info(f"[{request_id}] Step 6: Lazy loading mode (download only)")
                logger.info(f"[{request_id}] Step 7: Calling service.download_video_only()...")
                result = service.download_video_only(youtube_url)
                processing_time = (datetime.now() - start_time).total_seconds()
                logger.info(f"[{request_id}] Step 8: Download completed in {processing_time}s")
                logger.info(f"[{request_id}] Step 9: Result: {result}")

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
            raw_error = str(e)
            sanitized_error = sanitize_error_text(raw_error)
            logger.error(f"[{request_id}] EXCEPTION: {sanitized_error}")
            logger.error(f"[{request_id}] Type: {type(e).__name__}")
            logger.error(f"[{request_id}] Traceback:")
            logger.error(traceback.format_exc())

            anti_bot_markers = [
                "Sign in to confirm you're not a bot",
                "Sign in to confirm you\u2019re not a bot",
                "cookies-from-browser",
                "--cookies",
            ]

            if any(marker in sanitized_error for marker in anti_bot_markers):
                return jsonify({
                    "success": False,
                    "code": "YOUTUBE_AUTH_REQUIRED",
                    "error": "YouTube blocked automated video access for this video.",
                    "message": "Configure yt-dlp cookies by setting YTDLP_COOKIE_FILE in backend .env to an exported cookies.txt file."
                }), 502

            return jsonify({
                "success": False,
                "error": sanitized_error or "Failed to process video",
                "code": "VIDEO_PROCESS_FAILED",
                "message": "Failed to process video"
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== /api/v1/video/process END ==========\n")

    # ------------------------------------------------------------------
    # Code at timestamp
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/code', methods=['GET'])
    def get_code_at_timestamp(video_id):
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

    # ------------------------------------------------------------------
    # All segments
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/segments', methods=['GET'])
    def get_all_segments(video_id):
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

    # ------------------------------------------------------------------
    # Timeline export
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/timeline', methods=['GET'])
    def get_code_timeline(video_id):
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

    # ------------------------------------------------------------------
    # Video info
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/info', methods=['GET'])
    def get_video_info(video_id):
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

    # ------------------------------------------------------------------
    # List all processed videos
    # ------------------------------------------------------------------

    @video_bp.route('/videos', methods=['GET'])
    def list_processed_videos():
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

    # ------------------------------------------------------------------
    # Video status
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/status', methods=['GET'])
    def get_video_status(video_id):
        request_id = f"status_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== /api/v1/video/{video_id}/status START ==========")

        try:
            logger.info(f"[{request_id}] Step 1: Calling service.get_video_status({video_id})...")
            status = service.get_video_status(video_id)
            logger.info(f"[{request_id}] Step 2: Status retrieved: {status}")

            return jsonify({
                "success": True,
                **status
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] EXCEPTION: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== /api/v1/video/{video_id}/status END ==========\n")

    # ------------------------------------------------------------------
    # Cancel processing
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/cancel', methods=['POST'])
    def cancel_video_processing(video_id):
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

    # ------------------------------------------------------------------
    # Frame analysis (pause-to-code)
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/frame', methods=['GET'])
    def get_frame_at_timestamp(video_id):
        request_id = f"frame_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== /api/v1/video/{video_id}/frame START ==========")

        try:
            timestamp = request.args.get('timestamp', type=float)
            playlist_id = request.args.get('playlist_id', type=str)
            logger.info(f"[{request_id}] Timestamp: {timestamp}, Playlist ID: {playlist_id}")

            if timestamp is None:
                logger.error(f"[{request_id}] ERROR - Missing timestamp parameter")
                return jsonify({
                    "success": False,
                    "error": "Missing timestamp parameter"
                }), 400

            result = service.extract_frame_and_analyze(video_id, timestamp, playlist_id)
            logger.info(f"[{request_id}] Frame analysis result: {result}")

            return jsonify({
                "success": True,
                **result
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] EXCEPTION: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== /api/v1/video/{video_id}/frame END ==========\n")

    # ------------------------------------------------------------------
    # Playlist extraction
    # ------------------------------------------------------------------

    @video_bp.route('/playlist/videos', methods=['POST'])
    def get_playlist_videos():
        request_id = f"playlist_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== /api/v1/playlist/videos START ==========")

        try:
            data = request.get_json()

            if not data or 'playlist_url' not in data:
                logger.error(f"[{request_id}] ERROR - Missing playlist_url")
                return jsonify({
                    "success": False,
                    "error": "Missing playlist_url in request body"
                }), 400

            playlist_url = data['playlist_url']
            logger.info(f"[{request_id}] Playlist URL: {playlist_url}")
            result = service.get_playlist_videos(playlist_url)
            logger.info(f"[{request_id}] Retrieved {len(result['videos'])} videos")

            return jsonify({
                "success": True,
                "playlist_title": result['playlist_title'],
                "videos": result['videos']
            }), 200

        except Exception as e:
            raw_error = str(e)
            sanitized_error = sanitize_error_text(raw_error)
            logger.error(f"[{request_id}] EXCEPTION: {sanitized_error}")
            logger.error(traceback.format_exc())

            anti_bot_markers = [
                "Sign in to confirm you're not a bot",
                "Sign in to confirm you\u2019re not a bot",
                "cookies-from-browser",
                "--cookies"
            ]

            invalid_url_markers = [
                "Could not extract",
                "empty or unavailable",
                "could not be processed",
                "no valid videos"
            ]

            if any(marker in sanitized_error for marker in anti_bot_markers):
                return jsonify({
                    "success": False,
                    "code": "YOUTUBE_AUTH_REQUIRED",
                    "error": "YouTube blocked automated playlist access for this video or playlist.",
                    "message": "Configure yt-dlp cookies: set YTDLP_COOKIE_FILE (exported cookies.txt) or YTDLP_COOKIES_FROM_BROWSER (chrome/firefox)."
                }), 502

            if any(marker in sanitized_error.lower() for marker in invalid_url_markers):
                return jsonify({
                    "success": False,
                    "code": "INVALID_OR_UNAVAILABLE_URL",
                    "error": sanitized_error or "Could not extract videos from this URL",
                    "message": "This playlist/video may be private, deleted, age-restricted, or the URL format may be incorrect."
                }), 400

            return jsonify({
                "success": False,
                "error": sanitized_error or "Failed to extract playlist videos",
                "code": "EXTRACTION_FAILED"
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== /api/v1/playlist/videos END ==========\n")

    # ------------------------------------------------------------------
    # Transcript routes
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/transcript', methods=['GET'])
    def get_full_transcript(video_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/transcript START ==========")

        try:
            transcript_text = service.get_full_transcript_text(video_id)
            if not transcript_text:
                return jsonify({
                    "success": False,
                    "video_id": video_id,
                    "error": "Transcript not available for this video"
                }), 404

            return jsonify({
                "success": True,
                "video_id": video_id,
                "transcript": transcript_text
            }), 200
        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/transcript END ==========\n")

    @video_bp.route('/video/<video_id>/transcript/search', methods=['GET'])
    def search_transcript(video_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/transcript/search START ==========")

        try:
            query = request.args.get('query', '').strip()
            if not query:
                return jsonify({
                    "success": False,
                    "error": "Missing 'query' parameter"
                }), 400

            case_sensitive = request.args.get('case_sensitive', 'false').lower() == 'true'

            logger.info(f"[{request_id}] Searching transcript for: '{query}' (case_sensitive={case_sensitive})")

            matches = service.search_transcript(video_id, query, case_sensitive)

            if len(matches) == 0:
                return jsonify({
                    "success": True,
                    "video_id": video_id,
                    "query": query,
                    "matches_count": 0,
                    "matches": [],
                    "message": "No matches found. Video may not have transcript available. Try extracting transcript first."
                }), 200

            return jsonify({
                "success": True,
                "video_id": video_id,
                "query": query,
                "matches_count": len(matches),
                "matches": matches
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/transcript/search END ==========\n")

    @video_bp.route('/video/<video_id>/transcript/extract', methods=['POST'])
    def extract_transcript(video_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/video/{video_id}/transcript/extract START ==========")

        try:
            logger.info(f"[{request_id}] Extracting transcript for video {video_id}")

            success = service.extract_transcript_for_video(video_id)

            if success:
                return jsonify({
                    "success": True,
                    "video_id": video_id,
                    "message": "Transcript extracted successfully"
                }), 200
            else:
                return jsonify({
                    "success": False,
                    "video_id": video_id,
                    "error": "Failed to extract transcript. Video may not have captions/subtitles available."
                }), 400

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/video/{video_id}/transcript/extract END ==========\n")

    # ------------------------------------------------------------------
    # English transcript (translation) endpoints
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/transcript/english', methods=['GET'])
    def get_english_transcript(video_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/transcript/english START ==========")

        try:
            entries = service.get_english_transcript(video_id)
            if not entries:
                return jsonify({
                    "success": False,
                    "video_id": video_id,
                    "error": "English transcript not available for this video"
                }), 404

            full_text = service.get_full_english_transcript_text(video_id)
            return jsonify({
                "success": True,
                "video_id": video_id,
                "transcript": full_text,
                "entries_count": len(entries),
                "language": "en"
            }), 200
        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/transcript/english END ==========\n")

    @video_bp.route('/video/<video_id>/transcript/english/search', methods=['GET'])
    def search_english_transcript(video_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/transcript/english/search START ==========")

        try:
            query = request.args.get('query', '').strip()
            if not query:
                return jsonify({
                    "success": False,
                    "error": "Missing 'query' parameter"
                }), 400

            case_sensitive = request.args.get('case_sensitive', 'false').lower() == 'true'

            logger.info(f"[{request_id}] Searching English transcript for: '{query}'")

            matches = service.search_english_transcript(video_id, query, case_sensitive)

            return jsonify({
                "success": True,
                "video_id": video_id,
                "query": query,
                "matches_count": len(matches),
                "matches": matches,
                "language": "en",
                "message": "" if len(matches) > 0 else "No matches found in English transcript."
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/transcript/english/search END ==========\n")

    # ------------------------------------------------------------------
    # Concept detection
    # ------------------------------------------------------------------

    @video_bp.route('/video/<video_id>/concepts', methods=['GET'])
    def get_detected_concepts(video_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/concepts START ==========")

        try:
            concepts = service.get_detected_concepts(video_id)

            if len(concepts) == 0:
                return jsonify({
                    "success": True,
                    "video_id": video_id,
                    "concepts_count": 0,
                    "concepts": [],
                    "message": "No concepts detected yet. Use POST /concepts/detect to detect concepts."
                }), 200

            return jsonify({
                "success": True,
                "video_id": video_id,
                "concepts_count": len(concepts),
                "concepts": concepts
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/video/{video_id}/concepts END ==========\n")

    @video_bp.route('/video/<video_id>/concepts/detect', methods=['POST'])
    def detect_concepts(video_id):
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/video/{video_id}/concepts/detect START ==========")

        try:
            logger.info(f"[{request_id}] Starting concept detection for video {video_id}")

            detected_concepts = service.detect_and_store_concepts(video_id)

            if len(detected_concepts) == 0:
                return jsonify({
                    "success": True,
                    "video_id": video_id,
                    "concepts_count": 0,
                    "concepts": [],
                    "message": "No concepts detected. Video may not have transcript or code segments available."
                }), 200

            return jsonify({
                "success": True,
                "video_id": video_id,
                "concepts_count": len(detected_concepts),
                "concepts": [asdict(concept) for concept in detected_concepts],
                "message": f"Detected {len(detected_concepts)} concepts"
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/video/{video_id}/concepts/detect END ==========\n")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @video_bp.route('/stats', methods=['GET'])
    def get_stats():
        try:
            cache_dir = Path(service.cache_dir)

            total_size = sum(f.stat().st_size for f in cache_dir.rglob('*') if f.is_file())
            cache_size_mb = total_size / (1024 * 1024)

            analysis_files = list(cache_dir.glob("*_analysis.json"))

            return jsonify({
                "success": True,
                "total_requests": len(request_log),
                "total_videos_processed": len(analysis_files),
                "cache_size_mb": round(cache_size_mb, 2),
                "recent_requests": request_log[-10:]
            }), 200

        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    # ==================== YouTube Search ====================
    @video_bp.route('/youtube/search', methods=['GET'])
    def youtube_search():
        """Search YouTube for videos using yt-dlp (no API key needed)"""
        request_id = f"search_{datetime.now().timestamp()}"
        query = request.args.get('q', '').strip()
        max_results = min(int(request.args.get('max_results', 20)), 50)

        logger.info(f"[{request_id}] ========== GET /api/v1/youtube/search START ==========")
        logger.info(f"[{request_id}] Query: '{query}', Max results: {max_results}")

        if not query:
            return jsonify({"success": False, "error": "Query parameter 'q' is required"}), 400

        try:
            import yt_dlp

            ydl_opts = {
                'quiet': True,
                'no_warnings': True,
                'extract_flat': True,
                'skip_download': True,
                'default_search': f'ytsearch{max_results}',
                'ignoreerrors': True,
            }

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                result = ydl.extract_info(f"ytsearch{max_results}:{query}", download=False)

            videos = []
            if result and 'entries' in result:
                for entry in result['entries']:
                    if not entry:
                        continue
                    video_id = entry.get('id', '')
                    if not video_id:
                        continue

                    duration = entry.get('duration') or 0
                    view_count = entry.get('view_count') or 0

                    # Format views text
                    if view_count >= 1_000_000:
                        views_text = f"{view_count / 1_000_000:.1f}M views"
                    elif view_count >= 1_000:
                        views_text = f"{view_count / 1_000:.1f}K views"
                    else:
                        views_text = f"{view_count} views"

                    # Format published date
                    upload_date = entry.get('upload_date', '')
                    published = ''
                    if upload_date and len(upload_date) == 8:
                        try:
                            from datetime import datetime as dt
                            date_obj = dt.strptime(upload_date, '%Y%m%d')
                            now = dt.now()
                            diff = now - date_obj
                            if diff.days < 1:
                                published = "today"
                            elif diff.days < 7:
                                published = f"{diff.days} days ago"
                            elif diff.days < 30:
                                published = f"{diff.days // 7} weeks ago"
                            elif diff.days < 365:
                                published = f"{diff.days // 30} months ago"
                            else:
                                published = f"{diff.days // 365} years ago"
                        except:
                            published = upload_date

                    thumbnail = entry.get('thumbnail') or entry.get('thumbnails', [{}])[0].get('url', '') if entry.get('thumbnails') else ''
                    if not thumbnail and video_id:
                        thumbnail = f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"

                    videos.append({
                        'video_id': video_id,
                        'title': entry.get('title', 'Untitled'),
                        'channel': entry.get('channel', entry.get('uploader', 'Unknown')),
                        'channel_id': entry.get('channel_id', ''),
                        'thumbnail': thumbnail,
                        'duration': int(duration),
                        'views': int(view_count),
                        'views_text': views_text,
                        'published': published,
                        'description': (entry.get('description', '') or '')[:200],
                        'url': f"https://www.youtube.com/watch?v={video_id}",
                    })

            logger.info(f"[{request_id}] Found {len(videos)} video results for query '{query}'")
            return jsonify({
                "success": True,
                "query": query,
                "videos": videos,
                "total": len(videos)
            }), 200

        except Exception as e:
            logger.error(f"[{request_id}] YouTube search error: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": f"Search failed: {str(e)}"
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/youtube/search END ==========")
