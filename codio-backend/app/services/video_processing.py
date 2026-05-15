"""
Codio Backend - Video Processing Service
Handles YouTube video downloading, frame extraction, and transcript extraction.
Logic is unchanged from the original pause_to_code_service.py.
"""

import os
import re
import time
import json
import base64
import cv2
import logging
import tempfile
import requests
import yt_dlp
import numpy as np
import google.generativeai as genai
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

from dotenv import load_dotenv

# Load environment variables from backend-local .env regardless of process working directory.
load_dotenv(Path(__file__).resolve().parents[2] / '.env')

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cookie helper (unchanged)
# ---------------------------------------------------------------------------

def _resolve_valid_cookie_file() -> Optional[str]:
    """Return a valid Netscape cookie file path or None if invalid/missing."""
    cookie_file = os.getenv('YTDLP_COOKIE_FILE', '').strip()
    if not cookie_file:
        cookie_text = os.getenv('YTDLP_COOKIE_TEXT', '').strip()
        cookie_b64 = os.getenv('YTDLP_COOKIE_B64', '').strip()

        if not cookie_text and not cookie_b64:
            return None

        try:
            if cookie_b64:
                cookie_bytes = base64.b64decode(cookie_b64)
                cookie_text = cookie_bytes.decode('utf-8-sig', errors='ignore')
        except Exception as exc:
            logger.warning(f"Could not decode YTDLP_COOKIE_B64, skipping cookies: {exc}")
            return None

        if not cookie_text:
            return None

        temp_cookie_dir = Path(tempfile.gettempdir()) / 'codio_ytdlp_cookies'
        temp_cookie_dir.mkdir(exist_ok=True)
        temp_cookie_file = temp_cookie_dir / 'cookies.txt'

        try:
            temp_cookie_file.write_text(cookie_text, encoding='utf-8')
        except Exception as exc:
            logger.warning(f"Could not write cookie text to temp file, skipping cookies: {exc}")
            return None

        cookie_path = temp_cookie_file
    else:
        cookie_path = Path(cookie_file)

    if not cookie_path.is_file():
        logger.warning(f"YTDLP_COOKIE_FILE not found, skipping cookies: {cookie_file}")
        return None

    try:
        lines = cookie_path.read_text(encoding='utf-8-sig', errors='ignore').splitlines()
    except Exception as exc:
        logger.warning(f"Could not read cookie file, skipping cookies: {exc}")
        return None

    if not lines:
        logger.warning(f"Cookie file is empty, skipping cookies: {cookie_file}")
        return None

    if not lines[0].lstrip().startswith('# Netscape HTTP Cookie File'):
        logger.warning("Cookie file missing Netscape header, skipping cookies")
        return None

    valid_rows = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        parts = line.split('\t')
        if len(parts) != 7:
            continue

        domain, include_subdomains, cookie_path_val, secure, expires, name, _value = parts
        if not domain or not cookie_path_val or not name:
            continue
        if include_subdomains not in ('TRUE', 'FALSE'):
            continue
        if secure not in ('TRUE', 'FALSE'):
            continue
        if not expires.lstrip('-').isdigit():
            continue

        valid_rows += 1

    if valid_rows == 0:
        logger.warning("Cookie file has no valid Netscape cookie rows, skipping cookies")
        return None

    return str(cookie_path)


# ---------------------------------------------------------------------------
# Data classes (unchanged)
# ---------------------------------------------------------------------------

@dataclass
class CodeSegment:
    """Represents a code segment extracted from video"""
    timestamp: float
    frame_number: int
    segment_type: str  # 'code' or 'learning'
    code_content: Optional[str]
    learning_topic: Optional[str]
    confidence: float
    language: str
    code_complete: bool


@dataclass
class TranscriptEntry:
    """Represents a transcript entry with timestamp"""
    timestamp: float
    text: str
    duration: float  # Duration of this transcript segment


@dataclass
class DetectedConcept:
    """Represents a detected programming concept"""
    concept_name: str
    category: str
    timestamps: List[float]
    confidence: float
    description: Optional[str]


@dataclass
class VideoAnalysis:
    """Complete video analysis result"""
    video_id: str
    video_title: str
    duration: float
    total_frames_analyzed: int
    code_segments: List[CodeSegment]
    metadata: Dict
    extraction_date: str
    transcript: Optional[List[TranscriptEntry]] = None
    detected_concepts: Optional[List[DetectedConcept]] = None


# ---------------------------------------------------------------------------
# VideoProcessor (unchanged logic)
# ---------------------------------------------------------------------------

class VideoProcessor:
    """Process YouTube videos and extract frames"""

    def __init__(self, output_dir: str = "video_cache", service=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.service = service  # Reference to PauseToCodeService for progress tracking

    def download_video(self, youtube_url: str, video_id_for_progress: str = None, playlist_id: str = None) -> Tuple[str, Dict]:
        """Download YouTube video and return path + metadata"""
        try:
            logger.info(f"Downloading video from: {youtube_url}")

            # Extract video ID
            video_id = None
            if 'v=' in youtube_url:
                video_id = youtube_url.split('v=')[-1].split('&')[0]
            elif 'youtu.be/' in youtube_url:
                video_id = youtube_url.split('youtu.be/')[-1].split('?')[0]
            else:
                video_id = youtube_url.split('/')[-1].split('?')[0]

            if not video_id_for_progress:
                video_id_for_progress = video_id

            # First, get metadata to extract title for filename
            logger.info(f"Fetching video metadata...")
            meta_opts = {
                'quiet': True,
                'noplaylist': True,
                'socket_timeout': 20,
                'retries': 5,
                'js_runtimes': {'node': {}},
                'remote_components': ['ejs:github'],
            }

            validated_cookie_file = _resolve_valid_cookie_file()
            if validated_cookie_file:
                meta_opts['cookiefile'] = validated_cookie_file
            elif os.getenv('YTDLP_COOKIES_FROM_BROWSER', '').strip():
                browser = os.getenv('YTDLP_COOKIES_FROM_BROWSER', '').strip()
                profile = os.getenv('YTDLP_COOKIES_BROWSER_PROFILE', '').strip() or None
                meta_opts['cookiesfrombrowser'] = (browser, profile, None, None)

            with yt_dlp.YoutubeDL(meta_opts) as ydl:
                info = ydl.extract_info(youtube_url, download=False)

                if info.get('_type') == 'playlist' and info.get('entries'):
                    info = info['entries'][0]
                    video_id = info.get('id', video_id)

                title = info.get('title', 'Unknown')
                safe_title = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in title)
                safe_title = safe_title.strip()[:100]

                metadata = {
                    "title": title,
                    "duration": info.get('duration', 0),
                    "author": info.get('uploader', 'Unknown'),
                    "views": info.get('view_count', 0),
                    "video_id": video_id
                }

            playlist_folder = playlist_id[:20] if playlist_id else 'single'
            video_folder = self.output_dir.resolve() / playlist_folder / video_id
            video_folder.mkdir(parents=True, exist_ok=True)

            filename = "video.mp4"
            output_path = str(video_folder / filename)

            logger.info(f"📁 Folder structure:")
            logger.info(f"   Playlist folder: {playlist_folder}")
            logger.info(f"   Video folder: {video_id}")
            logger.info(f"   Full path: {output_path}")
            logger.info(f"   Folder created: {video_folder.exists()}")

            # Progress hook to update download status
            def progress_hook(d):
                if d['status'] == 'downloading':
                    try:
                        downloaded = d.get('downloaded_bytes', 0)
                        total = d.get('total_bytes') or d.get('total_bytes_estimate', 0)

                        progress_pct = None
                        if total > 0:
                            progress_pct = int((downloaded / total) * 100)
                        else:
                            percent_str = d.get('_percent_str')
                            if percent_str:
                                cleaned = str(percent_str).strip().replace('%', '')
                                try:
                                    progress_pct = int(float(cleaned))
                                except (ValueError, TypeError):
                                    progress_pct

                        if progress_pct is not None:
                            if hasattr(self, 'service') and self.service and video_id_for_progress in self.service.processing_progress:
                                self.service.processing_progress[video_id_for_progress].update({
                                    'progress': max(0, min(100, progress_pct)),
                                    'stage': f'Downloading: {progress_pct}%'
                                })

                            if total > 0:
                                logger.info(f"Download progress: {progress_pct}% ({downloaded}/{total} bytes)")
                            else:
                                logger.info(f"Download progress: {progress_pct}% (reported by yt-dlp)")
                    except Exception as e:
                        logger.error(f"Error in progress hook: {e}")

                elif d['status'] == 'finished':
                    logger.info(f"Download finished, now merging...")
                    if hasattr(self, 'service') and self.service and video_id_for_progress in self.service.processing_progress:
                        self.service.processing_progress[video_id_for_progress].update({
                            'progress': 100,
                            'stage': 'Download complete!'
                        })

            # Download with optimized settings
            ydl_opts = {
                'format': 'bestvideo[height<=720][ext=mp4]+bestaudio[ext=m4a]/best[height<=720][ext=mp4]/best',
                'outtmpl': output_path,
                'merge_output_format': 'mp4',
                'quiet': False,
                'no_warnings': False,
                'extract_flat': False,
                'noplaylist': True,
                'playlist_items': '1',
                'socket_timeout': 30,
                'retries': 5,
                'fragment_retries': 5,
                'extractor_args': {'youtube': {'player_client': ['android', 'web']}},
                'skip_unavailable_fragments': True,
                'progress_hooks': [progress_hook],
                'concurrent_fragment_downloads': 3,
                'http_chunk_size': 10485760,
            }

            cookie_file = _resolve_valid_cookie_file()
            cookies_browser = os.getenv('YTDLP_COOKIES_FROM_BROWSER', '').strip()

            if cookie_file:
                try:
                    ydl_opts['cookiefile'] = cookie_file
                    logger.info("Using YTDLP_COOKIE_FILE for video download")
                except Exception as e:
                    logger.warning(f"Cookie file error (continuing without): {e}")
            elif cookies_browser:
                try:
                    browser_profile = os.getenv('YTDLP_COOKIES_BROWSER_PROFILE', '').strip() or None
                    ydl_opts['cookiesfrombrowser'] = (cookies_browser, browser_profile, None, None)
                    logger.info(f"Using YTDLP_COOKIES_FROM_BROWSER for video download (browser={cookies_browser})")
                except Exception as e:
                    logger.warning(f"Browser cookie error (continuing without): {e}")

            logger.info(f"Starting download...")
            logger.info(f"yt-dlp will download to: {output_path}")
            try:
                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    ydl.download([youtube_url])
            except Exception as primary_error:
                logger.warning(f"Primary download options failed: {primary_error}")
                fallback_opts = {
                    'format': 'bestvideo[height<=720][ext=mp4]+bestaudio[ext=m4a]/best[height<=720][ext=mp4]/best',
                    'outtmpl': output_path,
                    'merge_output_format': 'mp4',
                    'quiet': False,
                    'no_warnings': False,
                    'noplaylist': True,
                    'socket_timeout': 30,
                    'retries': 5,
                    'extractor_args': {'youtube': {'player_client': ['android', 'web']}},
                    'progress_hooks': [progress_hook],
                    'concurrent_fragment_downloads': 3,
                    'http_chunk_size': 10485760,
                }
                if cookie_file:
                    try:
                        fallback_opts['cookiefile'] = cookie_file
                    except:
                        pass
                elif cookies_browser:
                    try:
                        browser_profile = os.getenv('YTDLP_COOKIES_BROWSER_PROFILE', '').strip() or None
                        fallback_opts['cookiesfrombrowser'] = (cookies_browser, browser_profile, None, None)
                    except:
                        pass

                logger.info("Retrying download with fallback yt-dlp options...")
                with yt_dlp.YoutubeDL(fallback_opts) as ydl:
                    ydl.download([youtube_url])

            # Verify file exists after download
            if os.path.exists(output_path):
                file_size = os.path.getsize(output_path) / (1024 * 1024)
                logger.info(f"✅ Video downloaded successfully: {output_path}")
                logger.info(f"✅ File size: {file_size:.2f} MB")
                logger.info(f"✅ File verified to exist on filesystem")
            else:
                logger.error(f"ERROR: Video file NOT found at expected path: {output_path}")
                logger.error(f"ERROR: Checking if file exists elsewhere...")
                try:
                    all_mp4s = list(self.output_dir.rglob("*.mp4"))
                    logger.error(f"ERROR: MP4 files found in directory: {[str(f) for f in all_mp4s[:5]]}")
                except Exception as e:
                    logger.error(f"ERROR: Could not search for MP4 files: {e}")
                raise FileNotFoundError(f"Downloaded video not found at {output_path}")

            return output_path, metadata

        except Exception as e:
            logger.error(f"Error downloading video: {e}")
            raise

    # ------------------------------------------------------------------
    # Transcript extraction
    # ------------------------------------------------------------------

    def extract_transcript(self, youtube_url: str, video_id: str = None) -> Optional[List[Dict]]:
        """Extract transcript/captions from YouTube video using multiple methods.
        
        Priority order:
        1. youtube-transcript-api (most reliable, no bot detection issues)
        2. yt-dlp subtitle download
        3. yt-dlp URL-based extraction
        4. Gemini AI fallback
        """

        logger.info(f"🔍 Attempting to extract transcript from: {youtube_url}")

        if not video_id:
            if 'v=' in youtube_url:
                video_id = youtube_url.split('v=')[-1].split('&')[0]
            elif 'youtu.be/' in youtube_url:
                video_id = youtube_url.split('youtu.be/')[-1].split('?')[0]
            else:
                video_id = youtube_url.split('/')[-1].split('?')[0]

        logger.info(f"📹 Video ID: {video_id}")

        # ============================================================
        # METHOD 1: youtube-transcript-api (PRIMARY - most reliable)
        # ============================================================
        if video_id:
            try:
                from youtube_transcript_api import YouTubeTranscriptApi
                logger.info(f"🔄 Method 1: Trying youtube-transcript-api for video {video_id}...")
                
                ytt_api = YouTubeTranscriptApi()
                
                # First, list available transcripts to find the best one
                available_langs = []
                try:
                    transcript_list = ytt_api.list(video_id=video_id)
                    for t in transcript_list:
                        available_langs.append(t.language_code)
                        logger.info(f"   Available: {t.language_code} (generated={t.is_generated})")
                except Exception as list_err:
                    logger.debug(f"   Could not list transcripts: {list_err}")
                
                # Try preferred languages first, then any available
                preferred_langs = ['en', 'en-US', 'en-GB', 'hi']
                langs_to_try = []
                
                # Add preferred languages that are available
                for lang in preferred_langs:
                    if lang in available_langs:
                        langs_to_try.append([lang])
                
                # Add all other available languages
                for lang in available_langs:
                    if lang not in preferred_langs:
                        langs_to_try.append([lang])
                
                # If we couldn't list, try common languages blindly
                if not langs_to_try:
                    langs_to_try = [['en'], ['en-US'], ['hi'], ['en-GB']]
                
                result = None
                for langs in langs_to_try:
                    try:
                        result = ytt_api.fetch(video_id=video_id, languages=langs)
                        if result and result.snippets:
                            break
                    except Exception:
                        continue
                
                if result and result.snippets:
                    entries = []
                    for snippet in result.snippets:
                        entries.append({
                            'start': float(snippet.start),
                            'end': float(snippet.start) + float(snippet.duration),
                            'text': snippet.text.strip() if snippet.text else ''
                        })
                    if entries:
                        logger.info(f"✅ Method 1 SUCCESS: Extracted {len(entries)} transcript entries via youtube-transcript-api (lang={result.language})")
                        return entries
                    
                logger.warning(f"⚠️  Method 1: youtube-transcript-api returned no usable results")
                    
            except ImportError:
                logger.warning("⚠️  Method 1: youtube-transcript-api not installed. Install with: pip install youtube-transcript-api")
            except Exception as yt_api_error:
                logger.warning(f"⚠️  Method 1: youtube-transcript-api failed: {yt_api_error}")

        # ============================================================
        # METHOD 2: yt-dlp subtitle download (fallback)
        # ============================================================
        try:
            logger.info(f"🔄 Method 2: Trying yt-dlp subtitle download for video {video_id}...")
            
            temp_dir = Path(tempfile.gettempdir()) / "codio_transcripts"
            temp_dir.mkdir(exist_ok=True)
            temp_subtitle_file = temp_dir / f"{video_id}.vtt"

            ydl_opts = {
                'quiet': False,
                'skip_download': True,
                'writesubtitles': True,
                'writeautomaticsub': True,
                'subtitleslangs': ['en', 'en-US', 'en-GB', 'hi'],
                'subtitlesformat': 'vtt',
                'outtmpl': str(temp_subtitle_file).replace('.vtt', ''),
            }

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                try:
                    ydl.download([youtube_url])
                except Exception as download_error:
                    logger.debug(f"yt-dlp download error (may be expected): {download_error}")

            subtitle_files = list(temp_dir.glob(f"{video_id}*.vtt"))
            if not subtitle_files:
                subtitle_files = list(temp_dir.glob(f"{video_id}*"))

            if subtitle_files:
                subtitle_file = subtitle_files[0]
                logger.info(f"Found subtitle file: {subtitle_file.name}")

                with open(subtitle_file, 'r', encoding='utf-8') as f:
                    transcript_text = f.read()

                transcript_entries = self._parse_vtt_transcript(transcript_text)

                try:
                    subtitle_file.unlink()
                except:
                    pass

                if transcript_entries and len(transcript_entries) > 0:
                    logger.info(f"✅ Method 2 SUCCESS: Extracted {len(transcript_entries)} transcript entries via yt-dlp")
                    return transcript_entries
            else:
                logger.warning(f"⚠️  Method 2: No subtitle files downloaded")

        except Exception as e:
            logger.warning(f"⚠️  Method 2: yt-dlp subtitle download failed: {e}")

        # ============================================================
        # METHOD 2.5: Direct json3 subtitle download (reliable for auto-captions)
        # ============================================================
        try:
            logger.info(f"🔄 Method 2.5: Trying direct json3 subtitle download for video {video_id}...")
            result = self._extract_transcript_via_json3(youtube_url, video_id)
            if result and len(result) > 0:
                logger.info(f"✅ Method 2.5 SUCCESS: Extracted {len(result)} entries via json3 format")
                return result
            logger.warning(f"⚠️  Method 2.5: json3 extraction returned no results")
        except Exception as e:
            logger.warning(f"⚠️  Method 2.5: json3 extraction failed: {e}")

        # ============================================================
        # METHOD 3: yt-dlp URL-based extraction (fallback)
        # ============================================================
        try:
            logger.info(f"🔄 Method 3: Trying yt-dlp URL-based extraction for video {video_id}...")
            vid = video_id if video_id else self._extract_video_id_from_url(youtube_url)
            result = self._extract_transcript_via_url(youtube_url, vid)
            if result and len(result) > 0:
                logger.info(f"✅ Method 3 SUCCESS: Extracted {len(result)} entries via URL method")
                return result
            logger.warning(f"⚠️  Method 3: URL-based extraction returned no results")
        except Exception as e:
            logger.warning(f"⚠️  Method 3: URL-based extraction failed: {e}")

        # ============================================================
        # METHOD 4: Gemini AI fallback (last resort)
        # ============================================================
        if video_id:
            logger.info(f"🔄 Method 4: Trying Gemini AI fallback for video {video_id}...")
            try:
                gemini_result = self._generate_transcript_with_gemini(video_id)
                if gemini_result:
                    logger.info(f"✅ Method 4 SUCCESS: Generated {len(gemini_result)} entries using Gemini AI")
                    return gemini_result
                else:
                    logger.warning(f"⚠️  Method 4: Gemini AI returned no results")
            except Exception as gemini_error:
                logger.error(f"⚠️  Method 4: Gemini AI failed: {gemini_error}")

        logger.warning(f"❌ No transcript available for video {video_id} - all 4 extraction methods failed")
        return None

    def _extract_transcript_via_json3(self, youtube_url: str, video_id: str) -> Optional[List[Dict]]:
        """Extract transcript using yt-dlp's json3 subtitle format directly.
        This is more reliable than VTT for auto-generated captions."""
        try:
            ydl_opts = {
                'quiet': True,
                'skip_download': True,
            }

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(youtube_url, download=False)

                if info.get('_type') == 'playlist' and info.get('entries'):
                    info = info['entries'][0]

                # Try manual subtitles first, then auto-captions
                all_subs = {}
                for source_key in ['subtitles', 'automatic_captions']:
                    source = info.get(source_key, {}) or {}
                    for lang_code in ['en', 'en-US', 'en-GB', 'hi']:
                        if lang_code in source and lang_code not in all_subs:
                            all_subs[lang_code] = (source_key, source[lang_code])
                    # Also try first available language
                    if not all_subs and source:
                        first_lang = list(source.keys())[0]
                        all_subs[first_lang] = (source_key, source[first_lang])

                if not all_subs:
                    logger.info(f"No subtitles found in json3 method for {video_id}")
                    return None

                # Try each language, prefer json3 format
                for lang_code, (source_key, formats) in all_subs.items():
                    json3_url = None
                    for fmt in formats:
                        if fmt.get('ext') == 'json3':
                            json3_url = fmt.get('url')
                            break

                    if not json3_url:
                        continue

                    logger.info(f"Downloading json3 transcript: lang={lang_code}, source={source_key}")
                    resp = requests.get(json3_url, timeout=15)
                    if resp.status_code != 200:
                        logger.warning(f"Failed to download json3: HTTP {resp.status_code}")
                        continue

                    data = json.loads(resp.text)
                    events = data.get('events', [])

                    entries = []
                    for ev in events:
                        segs = ev.get('segs', [])
                        text = ''.join(s.get('utf8', '') for s in segs).strip()
                        if not text or text == '\n':
                            continue

                        start_ms = ev.get('tStartMs', 0)
                        dur_ms = ev.get('dDurationMs', 0)
                        entries.append({
                            'timestamp': start_ms / 1000.0,
                            'text': text,
                            'duration': dur_ms / 1000.0
                        })

                    if entries:
                        logger.info(f"json3 extraction: {len(entries)} entries from {lang_code} ({source_key})")
                        return entries

            return None

        except Exception as e:
            logger.warning(f"json3 transcript extraction failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None

    def extract_english_transcript(self, youtube_url: str, video_id: str) -> Optional[List[Dict]]:
        """Extract English transcript from YouTube auto-translated captions.
        YouTube provides auto-translated captions in 150+ languages for most videos.
        This fetches the English version regardless of the original video language."""
        try:
            logger.info(f"Extracting English transcript for video {video_id}...")

            ydl_opts = {
                'quiet': True,
                'skip_download': True,
            }

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(youtube_url, download=False)

                if info.get('_type') == 'playlist' and info.get('entries'):
                    info = info['entries'][0]

                # Strategy: Try English from multiple sources in priority order
                # 1. Manual English subtitles (most accurate)
                # 2. Auto-generated English captions (YouTube auto-translate)
                en_formats = None
                source_desc = None

                for source_key in ['subtitles', 'automatic_captions']:
                    source = info.get(source_key, {}) or {}
                    for lang_code in ['en', 'en-US', 'en-GB']:
                        if lang_code in source:
                            en_formats = source[lang_code]
                            source_desc = f"{lang_code} from {source_key}"
                            break
                    if en_formats:
                        break

                if not en_formats:
                    logger.warning(f"No English captions available for video {video_id}")
                    return None

                # Get json3 format URL
                json3_url = None
                for fmt in en_formats:
                    if fmt.get('ext') == 'json3':
                        json3_url = fmt.get('url')
                        break

                if not json3_url:
                    logger.warning(f"No json3 format available for English captions of {video_id}")
                    return None

                logger.info(f"Downloading English transcript: {source_desc}")
                resp = requests.get(json3_url, timeout=15)
                if resp.status_code != 200:
                    logger.warning(f"Failed to download English json3: HTTP {resp.status_code}")
                    return None

                data = json.loads(resp.text)
                events = data.get('events', [])

                entries = []
                for ev in events:
                    segs = ev.get('segs', [])
                    text = ''.join(s.get('utf8', '') for s in segs).strip()
                    if not text or text == '\n':
                        continue

                    start_ms = ev.get('tStartMs', 0)
                    dur_ms = ev.get('dDurationMs', 0)
                    entries.append({
                        'timestamp': start_ms / 1000.0,
                        'text': text,
                        'duration': dur_ms / 1000.0
                    })

                if entries:
                    logger.info(f"English transcript: {len(entries)} entries from {source_desc}")
                    return entries

                logger.warning(f"English transcript extraction returned no entries for {video_id}")
                return None

        except Exception as e:
            logger.warning(f"English transcript extraction failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None

    def _extract_video_id_from_url(self, youtube_url: str) -> str:
        """Helper to extract video ID from URL"""
        if 'v=' in youtube_url:
            return youtube_url.split('v=')[-1].split('&')[0]
        elif 'youtu.be/' in youtube_url:
            return youtube_url.split('youtu.be/')[-1].split('?')[0]
        else:
            return youtube_url.split('/')[-1].split('?')[0]

    def _extract_transcript_via_url(self, youtube_url: str, video_id: str) -> Optional[List[Dict]]:
        """Alternative method: Extract transcript by getting subtitle URL directly"""
        try:
            logger.info(f"🔄 Trying alternative transcript extraction method for {video_id}")

            ydl_opts = {
                'quiet': True,
                'skip_download': True,
            }

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(youtube_url, download=False)

                if info.get('_type') == 'playlist' and info.get('entries'):
                    info = info['entries'][0]

                subtitles = info.get('subtitles', {}) or info.get('automatic_captions', {})

                if not subtitles:
                    logger.info(f"⚠️  No subtitles available in video metadata for {video_id}")
                    return None

                transcript_lang = None
                for lang_code in ['en', 'en-US', 'en-GB', 'hi']:
                    if lang_code in subtitles:
                        transcript_lang = lang_code
                        break

                if not transcript_lang and subtitles:
                    transcript_lang = list(subtitles.keys())[0]
                    logger.info(f"📝 Using available language: {transcript_lang}")

                if not transcript_lang:
                    logger.info(f"⚠️  No suitable subtitle language found for video {video_id}")
                    return None

                if transcript_lang in info.get('subtitles', {}):
                    sub_url = info['subtitles'][transcript_lang][0]['url']
                elif transcript_lang in info.get('automatic_captions', {}):
                    sub_url = info['automatic_captions'][transcript_lang][0]['url']
                else:
                    logger.warning(f"⚠️  No transcript URL found for language {transcript_lang}")
                    return None

                logger.info(f"📥 Downloading transcript in language: {transcript_lang}")
                response = requests.get(sub_url, timeout=15)
                if response.status_code == 200:
                    transcript_text = response.text
                    transcript_entries = self._parse_vtt_transcript(transcript_text)

                    if transcript_entries and len(transcript_entries) > 0:
                        logger.info(f"✅ Successfully extracted {len(transcript_entries)} transcript entries via URL method")
                        return transcript_entries
                    else:
                        logger.warning(f"⚠️  Failed to parse transcript for video {video_id} (empty result)")
                else:
                    logger.warning(f"⚠️  Failed to download transcript: HTTP {response.status_code}")

        except Exception as e:
            logger.warning(f"⚠️  Alternative transcript extraction failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())

        return None

    def _generate_transcript_with_gemini(self, video_id: str) -> Optional[List[Dict]]:
        """Generate transcript using Gemini 2.5 Flash by processing the video file/audio."""
        try:
            video_dir = self.output_dir
            video_files = list(video_dir.rglob(f"**/{video_id}/video.mp4"))

            if not video_files:
                logger.warning(f"⚠️  Cannot generate AI transcript: Video file for {video_id} not found locally.")
                logger.warning(f"   Searched in: {video_dir}")
                logger.info(f"💡 Tip: Make sure video has been downloaded first")
                return None

            video_path = video_files[0]
            logger.info(f"🤖 Uploading video {video_id} to Gemini for AI transcription...")
            logger.info(f"   Video path: {video_path}")

            video_file = genai.upload_file(path=str(video_path))

            max_wait_time = 60
            wait_start = time.time()
            while video_file.state.name == "PROCESSING":
                if time.time() - wait_start > max_wait_time:
                    logger.error(f"Gemini file processing timeout after {max_wait_time}s")
                    return None
                time.sleep(2)
                video_file = genai.get_file(video_file.name)

            if video_file.state.name == "FAILED":
                logger.error("Video processing failed in Gemini.")
                return None

            logger.info("Video processed by Gemini. Generating transcript...")

            model = genai.GenerativeModel('gemini-2.5-flash')

            prompt = """
            Listen to the audio of this video carefully and generate a complete transcript.
            Return the result as a raw JSON array of objects. 
            Do not use markdown code blocks. Just the raw JSON.
            Each object must have:
            - "timestamp": start time in seconds (float)
            - "text": the spoken text
            - "duration": approximate duration in seconds (float)
            
            Example format:
            [
                {"timestamp": 0.0, "text": "Hello world", "duration": 2.5},
                {"timestamp": 2.5, "text": "Welcome to Python", "duration": 3.0}
            ]
            """

            response = model.generate_content(
                [video_file, prompt],
                generation_config={"response_mime_type": "application/json"}
            )

            try:
                text = response.text.replace('```json', '').replace('```', '').strip()
                transcript_data = json.loads(text)

                entries = []
                for item in transcript_data:
                    entries.append({
                        "timestamp": float(item.get("timestamp", 0.0)),
                        "text": str(item.get("text", "")),
                        "duration": float(item.get("duration", 0.0))
                    })

                logger.info(f"AI Transcript generated: {len(entries)} entries")

                try:
                    genai.delete_file(video_file.name)
                except:
                    pass

                return entries

            except json.JSONDecodeError:
                logger.error(f"Failed to parse AI transcript JSON: {response.text[:100]}...")
                return None

        except Exception as e:
            logger.error(f"AI Transcript generation failed: {e}")
            return None

    def _parse_vtt_transcript(self, vtt_content: str) -> List[Dict]:
        """Parse VTT (WebVTT) subtitle format into structured entries"""
        entries = []
        lines = vtt_content.split('\n')

        timestamp_pattern = re.compile(r'(\d{2}):(\d{2}):(\d{2})\.(\d{3})\s*-->\s*(\d{2}):(\d{2}):(\d{2})\.(\d{3})')

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            match = timestamp_pattern.match(line)
            if match:
                start_h, start_m, start_s, start_ms = map(int, match.groups()[:4])
                end_h, end_m, end_s, end_ms = map(int, match.groups()[4:])

                start_time = start_h * 3600 + start_m * 60 + start_s + start_ms / 1000.0
                end_time = end_h * 3600 + end_m * 60 + end_s + end_ms / 1000.0
                duration = end_time - start_time

                text_lines = []
                i += 1
                while i < len(lines):
                    next_line = lines[i].strip()
                    if not next_line or timestamp_pattern.match(next_line):
                        break
                    if not next_line.startswith('<'):
                        text_lines.append(next_line)
                    i += 1

                text = ' '.join(text_lines).strip()

                if text:
                    entries.append({
                        'timestamp': start_time,
                        'text': text,
                        'duration': duration
                    })

                continue

            i += 1

        return entries

    # ------------------------------------------------------------------
    # Frame extraction
    # ------------------------------------------------------------------

    def extract_frame_at_timestamp(self, video_path: str, timestamp: float) -> Optional[np.ndarray]:
        """Extract a single frame at specific timestamp"""
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError("Cannot open video file")

        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        duration = total_frames / fps

        if timestamp > duration:
            logger.error(f"Timestamp {timestamp}s exceeds video duration {duration:.2f}s")
            cap.release()
            return None

        frame_number = int(timestamp * fps)
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_number)

        ret, frame = cap.read()
        cap.release()

        if ret:
            logger.info(f"Extracted frame at {timestamp}s (frame #{frame_number})")
            return frame
        else:
            logger.error(f"Failed to extract frame at {timestamp}s")
            return None

    def extract_frames_fixed_interval(
        self,
        video_path: str,
        interval_seconds: float = 2.0
    ) -> List[Tuple[np.ndarray, float, int]]:
        """Extract frames at fixed intervals (every N seconds)"""
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError("Cannot open video file")

        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        duration = total_frames / fps

        logger.info(f"Video info - FPS: {fps}, Duration: {duration:.2f}s, Total frames: {total_frames}")
        logger.info(f"Extracting frames every {interval_seconds}s")

        frames_data = []
        frame_interval = int(fps * interval_seconds)

        frame_count = 0
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            if frame_count % frame_interval == 0:
                frame_number = int(cap.get(cv2.CAP_PROP_POS_FRAMES))
                timestamp = cap.get(cv2.CAP_PROP_POS_MSEC) / 1000
                frames_data.append((frame.copy(), timestamp, frame_number))

            frame_count += 1

        cap.release()
        logger.info(f"Extracted {len(frames_data)} frames for analysis")
        return frames_data
