"""
Codio Backend - Pause-to-Code Orchestrator Service
Main service orchestrating the pause-to-code feature.
Logic is unchanged from the original pause_to_code_service.py.
"""

import os
import re
import time
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import asdict

from app.services.video_processing import (
    VideoProcessor,
    VideoAnalysis,
    CodeSegment,
    TranscriptEntry,
    DetectedConcept,
)
from app.services.gemini_extractor import GeminiCodeExtractor
from app.services.concept_detection import ConceptDetector

try:
    import yt_dlp
except ImportError:
    yt_dlp = None

logger = logging.getLogger(__name__)


def _make_transcript_entry(entry: dict) -> TranscriptEntry:
    """Create a TranscriptEntry from a dict that may use either field naming convention.
    Handles both {timestamp, text, duration} and {start, end, text} formats."""
    if 'timestamp' in entry:
        return TranscriptEntry(
            timestamp=float(entry.get('timestamp', 0)),
            text=str(entry.get('text', '')),
            duration=float(entry.get('duration', 0))
        )
    else:
        start = float(entry.get('start', 0))
        end = float(entry.get('end', start))
        return TranscriptEntry(
            timestamp=start,
            text=str(entry.get('text', '')),
            duration=end - start
        )


class PauseToCodeService:
    """Main service orchestrating the pause-to-code feature"""

    def __init__(self, cache_dir: str = "codio_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        self.extractor = GeminiCodeExtractor()
        self.processor = VideoProcessor(str(self.cache_dir / "videos"), service=self)
        self.concept_detector = ConceptDetector()

        # Progress tracking for each video
        self.processing_progress = {}
        # Cache for recent on-demand pause analyses
        self.realtime_analysis_cache = {}

    # ------------------------------------------------------------------
    # Full video processing
    # ------------------------------------------------------------------

    def process_video(
        self,
        youtube_url: str,
        force_reprocess: bool = False,
        frame_interval: float = 2.0
    ) -> VideoAnalysis:
        """Process entire video and extract all code segments"""
        video_id = self._extract_video_id(youtube_url)
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if cache_file.exists() and not force_reprocess:
            logger.info(f"Loading cached analysis for {video_id}")
            return self._load_cached_analysis(cache_file)

        self.processing_progress[video_id] = {
            'status': 'downloading',
            'progress': 0,
            'stage': 'Downloading video...',
            'total_frames': 0,
            'current_frame': 0
        }
        logger.info(f"STAGE 1/3: Downloading video {video_id}")

        try:
            playlist_id = self._extract_playlist_id(youtube_url)
            video_path, metadata = self.processor.download_video(youtube_url, video_id, playlist_id)

            self.processing_progress[video_id].update({
                'status': 'extracting',
                'progress': 15,
                'stage': 'Extracting frames...'
            })
            logger.info(f"STAGE 2/3: Extracting frames from video")

            frames_data = self.processor.extract_frames_fixed_interval(video_path, frame_interval)

            total_frames = len(frames_data)
            self.processing_progress[video_id].update({
                'status': 'analyzing',
                'progress': 20,
                'stage': f'Analyzing {total_frames} frames with AI...',
                'total_frames': total_frames,
                'current_frame': 0
            })
            logger.info(f"🤖 STAGE 3/3: Analyzing {total_frames} frames with Gemini AI")
            logger.info(f"{'='*60}")

            code_segments = []
            prev_code = None

            for idx, (frame, timestamp, frame_number) in enumerate(frames_data):
                current_frame = idx + 1
                progress = 20 + int((current_frame / total_frames) * 75)

                self.processing_progress[video_id].update({
                    'progress': progress,
                    'current_frame': current_frame,
                    'stage': f'Analyzing frame {current_frame}/{total_frames}'
                })

                minutes = int(timestamp // 60)
                seconds = int(timestamp % 60)
                logger.info(f"📊 Frame {current_frame}/{total_frames} ({progress}%) - Timestamp {minutes:02d}:{seconds:02d}")

                analysis = self.extractor.analyze_frame(frame, timestamp)

                segment = CodeSegment(
                    timestamp=timestamp,
                    frame_number=frame_number,
                    segment_type=analysis['segment_type'],
                    code_content=analysis.get('code_content'),
                    learning_topic=analysis.get('learning_topic'),
                    confidence=analysis.get('confidence', 0.0),
                    language=analysis.get('language', 'python'),
                    code_complete=analysis.get('code_complete', False)
                )

                code_segments.append(segment)
                if segment.code_content:
                    prev_code = segment.code_content

            # Extract transcript
            transcript_entries = None
            try:
                logger.info("📝 Extracting transcript...")
                video_id_for_transcript = self._extract_video_id(youtube_url)
                transcript_data = self.processor.extract_transcript(youtube_url, video_id_for_transcript)
                if transcript_data and len(transcript_data) > 0:
                    transcript_entries = [_make_transcript_entry(entry) for entry in transcript_data]
                    logger.info(f"✅ Transcript extracted: {len(transcript_entries)} entries")
                else:
                    logger.warning("⚠️  No transcript available for this video")
            except Exception as e:
                logger.error(f"❌ Transcript extraction failed: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                transcript_entries = None

            video_analysis = VideoAnalysis(
                video_id=video_id,
                video_title=metadata['title'],
                duration=metadata['duration'],
                total_frames_analyzed=len(frames_data),
                code_segments=code_segments,
                metadata=metadata,
                extraction_date=datetime.now().isoformat(),
                transcript=transcript_entries,
                detected_concepts=None
            )

            self.processing_progress[video_id].update({
                'status': 'completed',
                'progress': 95,
                'stage': 'Saving analysis...'
            })
            logger.info(f"Saving analysis to cache...")

            self._cache_analysis(video_analysis, cache_file)

            self.processing_progress[video_id].update({
                'status': 'completed',
                'progress': 100,
                'stage': 'Completed!'
            })
            logger.info(f"{'='*60}")
            logger.info(f"VIDEO PROCESSING COMPLETE!")
            logger.info(f"   Video ID: {video_id}")
            logger.info(f"   Title: {metadata['title']}")
            logger.info(f"   Duration: {int(metadata['duration']//60)}m {int(metadata['duration']%60)}s")
            logger.info(f"   Frames Analyzed: {len(frames_data)}")
            logger.info(f"   Code Segments Found: {sum(1 for s in code_segments if s.code_content)}")
            logger.info(f"{'='*60}")

            logger.info(f"Video file kept at: {video_path}")

            return video_analysis

        except Exception as e:
            logger.error(f"Video processing failed for {video_id}: {e}")
            if video_id in self.processing_progress:
                del self.processing_progress[video_id]
            raise

    # ------------------------------------------------------------------
    # Lazy download (no frame analysis)
    # ------------------------------------------------------------------

    def download_video_only(self, youtube_url: str) -> Dict:
        """Download video without processing (lazy loading approach)"""
        video_id = self._extract_video_id(youtube_url)
        playlist_id = self._extract_playlist_id(youtube_url)
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        playlist_folder = playlist_id[:20] if playlist_id else 'single'
        video_folder = self.cache_dir / "videos" / playlist_folder / video_id
        video_file = video_folder / "video.mp4"

        if video_file.exists() and cache_file.exists():
            logger.info(f"Video {video_id} already downloaded at {video_file}")
            analysis = self._load_cached_analysis(cache_file)
            transcript_available = bool(analysis.transcript and len(analysis.transcript) > 0)

            data_updated = False

            if not analysis.transcript:
                logger.info(f"📝 Backfilling missing transcript for {video_id}...")
                transcript_data = self.processor.extract_transcript(youtube_url, video_id)
                if transcript_data and len(transcript_data) > 0:
                    analysis.transcript = [_make_transcript_entry(entry) for entry in transcript_data]
                    logger.info(f"✅ Transcript backfilled: {len(analysis.transcript)} entries")
                    data_updated = True
                else:
                    logger.warning(f"⚠️  Failed to backfill transcript for {video_id}")

            if not analysis.detected_concepts and analysis.transcript:
                logger.info(f"Backfilling missing concepts for {video_id}...")
                detected_concepts = self.concept_detector.detect_concepts(
                    transcript=analysis.transcript,
                    code_segments=analysis.code_segments or []
                )
                if detected_concepts:
                    analysis.detected_concepts = detected_concepts
                    logger.info(f"Concepts backfilled: {len(detected_concepts)} concepts")
                    data_updated = True

            if data_updated:
                self._cache_analysis(analysis, cache_file)
                logger.info(f"Cache updated with backfilled data")

            return {
                'video_id': video_id,
                'status': 'completed',
                'title': analysis.video_title,
                'duration': analysis.duration,
                'message': 'Video downloaded successfully' if transcript_available else 'Video downloaded, but transcript is unavailable for this video',
                'transcript_available': transcript_available
            }

        self.processing_progress[video_id] = {
            'status': 'downloading',
            'progress': 0,
            'stage': 'Downloading video...',
            'total_frames': 0,
            'current_frame': 0
        }
        logger.info(f"Starting download for video {video_id}")

        try:
            playlist_id = self._extract_playlist_id(youtube_url)
            downloaded_path, metadata = self.processor.download_video(youtube_url, video_id, playlist_id)

            logger.info("📝 Extracting transcript...")
            self.processing_progress[video_id]['stage'] = 'Extracting transcript...'
            transcript_entries = None
            try:
                transcript_data = self.processor.extract_transcript(youtube_url, video_id)
                if transcript_data and len(transcript_data) > 0:
                    transcript_entries = [_make_transcript_entry(entry) for entry in transcript_data]
                    logger.info(f"✅ Transcript extracted: {len(transcript_entries)} entries")
                    logger.info(f"   First entry sample: {transcript_entries[0].text[:50] if transcript_entries else 'N/A'}...")
                else:
                    logger.warning(f"⚠️  No transcript data returned from extract_transcript()")
            except Exception as e:
                logger.error(f"❌ Transcript extraction failed: {e}")
                import traceback
                logger.error(traceback.format_exc())

            detected_concepts = None
            if transcript_entries:
                logger.info("Detecting concepts from transcript...")
                self.processing_progress[video_id]['stage'] = 'Detecting concepts...'
                try:
                    detected_concepts = self.concept_detector.detect_concepts(
                        transcript=transcript_entries,
                        code_segments=[]
                    )
                    logger.info(f"Concepts detected: {len(detected_concepts) if detected_concepts else 0}")
                except Exception as e:
                    logger.warning(f"Concept detection failed: {e}")

            video_analysis = VideoAnalysis(
                video_id=video_id,
                video_title=metadata['title'],
                duration=metadata['duration'],
                total_frames_analyzed=0,
                code_segments=[],
                metadata=metadata,
                extraction_date=datetime.now().isoformat(),
                transcript=transcript_entries,
                detected_concepts=detected_concepts
            )

            logger.info(f"💾 Saving analysis to cache:")
            logger.info(f"   Video ID: {video_id}")
            logger.info(f"   Transcript entries: {len(transcript_entries) if transcript_entries else 0}")
            logger.info(f"   Detected concepts: {len(detected_concepts) if detected_concepts else 0}")

            self._cache_analysis(video_analysis, cache_file)

            if cache_file.exists():
                logger.info(f"✅ Cache file saved: {cache_file}")
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        saved_data = json.load(f)
                        has_transcript = 'transcript' in saved_data and saved_data['transcript'] is not None
                        logger.info(f"   Transcript in saved file: {has_transcript}")
                        if has_transcript:
                            logger.info(f"   Saved transcript entries: {len(saved_data['transcript'])}")
                except Exception as e:
                    logger.warning(f"Could not verify saved transcript: {e}")

            transcript_available = bool(transcript_entries and len(transcript_entries) > 0)

            self.processing_progress[video_id].update({
                'status': 'completed',
                'progress': 100,
                'stage': 'Download complete!' if transcript_available else 'Download complete (no transcript available)'
            })
            logger.info(f"Video downloaded: {metadata['title']}")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Download failed for {video_id}: {error_msg}")
            import traceback
            logger.debug(traceback.format_exc())

            if video_id in self.processing_progress:
                self.processing_progress[video_id].update({
                    'status': 'failed',
                    'progress': 0,
                    'stage': f'Download failed'
                })

            raise ValueError(f"Failed to download video: {error_msg}")

        return {
            'video_id': video_id,
            'status': 'completed',
            'title': metadata['title'],
            'duration': metadata['duration'],
            'message': 'Video downloaded successfully' if transcript_available else 'Video downloaded, but transcript is unavailable for this video',
            'transcript_available': transcript_available
        }

    # ------------------------------------------------------------------
    # Timestamp queries
    # ------------------------------------------------------------------

    def get_code_at_timestamp(self, video_id: str, timestamp: float, tolerance: float = 1.0) -> Dict:
        """Get code at specific timestamp from pre-extracted data"""
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if not cache_file.exists():
            return {
                "error": "Video not processed yet",
                "video_id": video_id,
                "message": "Please process the video first using process_video()"
            }

        analysis = self._load_cached_analysis(cache_file)

        nearest_segment = None
        min_diff = float('inf')

        for segment in analysis.code_segments:
            diff = abs(segment.timestamp - timestamp)
            if diff < min_diff and diff <= tolerance:
                min_diff = diff
                nearest_segment = segment

        if nearest_segment is None:
            return {
                "found": False,
                "message": f"No segment found within {tolerance}s of {timestamp:.2f}s",
                "timestamp_requested": timestamp
            }

        if nearest_segment.segment_type == "learning":
            return {
                "found": True,
                "timestamp_requested": timestamp,
                "timestamp_actual": nearest_segment.timestamp,
                "time_difference": min_diff,
                "segment_type": "learning",
                "message": "Learning phase - No code at this timestamp",
                "learning_topic": nearest_segment.learning_topic,
                "confidence": nearest_segment.confidence
            }
        else:
            return {
                "found": True,
                "timestamp_requested": timestamp,
                "timestamp_actual": nearest_segment.timestamp,
                "time_difference": min_diff,
                "segment_type": "code",
                "code_content": nearest_segment.code_content,
                "confidence": nearest_segment.confidence,
                "language": nearest_segment.language,
                "code_complete": nearest_segment.code_complete
            }

    def get_all_code_segments(self, video_id: str) -> List[Dict]:
        """Get all code segments for a video"""
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if not cache_file.exists():
            return []

        analysis = self._load_cached_analysis(cache_file)
        return [asdict(seg) for seg in analysis.code_segments]

    def export_code_timeline(self, video_id: str, output_file: str):
        """Export all code in timeline format"""
        segments = self.get_all_code_segments(video_id)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Code Timeline for Video: {video_id}\n")
            f.write(f"# Generated: {datetime.now()}\n")
            f.write("=" * 80 + "\n\n")

            for segment in segments:
                timestamp = segment['timestamp']
                minutes = int(timestamp // 60)
                seconds = int(timestamp % 60)

                f.write(f"\n## Timestamp: {minutes:02d}:{seconds:02d} ({timestamp:.2f}s)\n")
                f.write(f"## Type: {segment['segment_type']}\n")
                f.write(f"## Confidence: {segment['confidence']:.2%}\n")

                if segment['code_content']:
                    f.write(f"## Code Complete: {segment['code_complete']}\n\n")
                    f.write("```python\n")
                    f.write(segment['code_content'])
                    f.write("\n```\n")

                if segment.get('learning_topic'):
                    f.write(f"\n### Learning Topic: {segment['learning_topic']}\n")

                f.write("\n" + "-" * 80 + "\n")

        logger.info(f"Code timeline exported to {output_file}")

    # ------------------------------------------------------------------
    # Transcript search
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_vtt_tags(text: str) -> str:
        """Remove VTT subtitle formatting tags like <00:00:02.320><c> word</c>"""
        if not text:
            return text
        # Remove timestamp tags like <00:00:02.320>
        cleaned = re.sub(r'<[\d:.]+>', '', text)
        # Remove <c> and </c> tags
        cleaned = re.sub(r'</?c>', '', cleaned)
        # Remove any other HTML-like tags
        cleaned = re.sub(r'<[^>]+>', '', cleaned)
        # Collapse multiple spaces
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned

    def search_transcript(self, video_id: str, query: str, case_sensitive: bool = False) -> List[Dict]:
        """Search transcript by keywords"""
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if not cache_file.exists():
            logger.warning(f"⚠️  Video {video_id} not found in cache for transcript search")
            return []

        analysis = self._load_cached_analysis(cache_file)

        if not analysis.transcript:
            logger.warning(f"⚠️  No transcript available for video {video_id}.")
            logger.info(f"💡 Tip: Try calling extract_transcript_for_video() to extract transcript manually")
            return []

        if len(analysis.transcript) == 0:
            logger.warning(f"⚠️  Transcript is empty for video {video_id}")
            return []

        if not query or not query.strip():
            logger.warning(f"⚠️  Empty search query provided")
            return []

        query = query.strip()
        query_words = query.lower().split() if not case_sensitive else query.split()

        matches = []
        for entry in analysis.transcript:
            if not entry.text or not entry.text.strip():
                continue

            # Clean VTT formatting tags from text before searching
            clean_text = self._clean_vtt_tags(entry.text)
            if not clean_text:
                continue

            text_to_search = clean_text if case_sensitive else clean_text.lower()

            query_matches = False
            match_start = -1

            if query.lower() in text_to_search:
                query_matches = True
                match_start = text_to_search.find(query.lower())
            elif all(word in text_to_search for word in query_words):
                query_matches = True
                match_start = text_to_search.find(query_words[0])

            if query_matches:
                matches.append({
                    'timestamp': entry.timestamp,
                    'text': clean_text,
                    'duration': entry.duration,
                    'match_start': match_start if match_start >= 0 else 0,
                    'match_length': len(query)
                })

        matches.sort(key=lambda x: x['timestamp'])

        logger.info(f"🔍 Found {len(matches)} transcript matches for query '{query}' in video {video_id}")
        return matches

    def get_full_transcript_text(self, video_id: str) -> str:
        """Return full transcript text for a processed video as a single string."""
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if not cache_file.exists():
            logger.warning(f"⚠️  Video {video_id} not found in cache for transcript retrieval")
            return ""

        analysis = self._load_cached_analysis(cache_file)
        if not analysis.transcript:
            logger.warning(f"⚠️  No transcript found for video {video_id}")
            return ""

        chunks = [self._clean_vtt_tags(entry.text) for entry in analysis.transcript if entry.text and entry.text.strip()]
        return " ".join(chunks).strip()

    # ------------------------------------------------------------------
    # Transcript extraction helper
    # ------------------------------------------------------------------

    def extract_transcript_for_video(self, video_id: str) -> bool:
        """Manually extract transcript for an existing video"""
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if not cache_file.exists():
            logger.error(f"Video {video_id} not found in cache")
            return False

        analysis = self._load_cached_analysis(cache_file)

        youtube_url = f"https://www.youtube.com/watch?v={video_id}"

        logger.info(f"📝 Extracting transcript for video {video_id}...")
        try:
            transcript_data = self.processor.extract_transcript(youtube_url, video_id)
            if transcript_data and len(transcript_data) > 0:
                transcript_entries = [_make_transcript_entry(entry) for entry in transcript_data]
                analysis.transcript = transcript_entries
                self._cache_analysis(analysis, cache_file)
                logger.info(f"✅ Successfully extracted and saved {len(transcript_entries)} transcript entries")
                return True
            else:
                logger.warning(f"⚠️  No transcript available for video {video_id}")
                logger.info(f"💡 Tip: Video may not have captions.")
                return False
        except Exception as e:
            logger.error(f"❌ Failed to extract transcript for video {video_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    # ------------------------------------------------------------------
    # English transcript (translation) support
    # ------------------------------------------------------------------

    def get_english_transcript(self, video_id: str) -> Optional[List[Dict]]:
        """Get English transcript for a video. First checks cache, then fetches from YouTube."""
        # Check if we have a cached English transcript
        en_cache_file = self.cache_dir / f"{video_id}_english_transcript.json"

        if en_cache_file.exists():
            try:
                with open(en_cache_file, 'r') as f:
                    data = json.load(f)
                if data and len(data) > 0:
                    logger.info(f"Loaded cached English transcript for {video_id}: {len(data)} entries")
                    return data
            except Exception as e:
                logger.warning(f"Failed to load cached English transcript: {e}")

        # Fetch from YouTube
        youtube_url = f"https://www.youtube.com/watch?v={video_id}"
        entries = self.processor.extract_english_transcript(youtube_url, video_id)

        if entries and len(entries) > 0:
            # Cache it
            try:
                with open(en_cache_file, 'w') as f:
                    json.dump(entries, f)
                logger.info(f"Cached English transcript for {video_id}: {len(entries)} entries")
            except Exception as e:
                logger.warning(f"Failed to cache English transcript: {e}")
            return entries

        return None

    def search_english_transcript(self, video_id: str, query: str, case_sensitive: bool = False) -> List[Dict]:
        """Search English transcript by keywords."""
        entries = self.get_english_transcript(video_id)

        if not entries:
            logger.warning(f"No English transcript available for video {video_id}")
            return []

        if not query or not query.strip():
            return []

        query = query.strip()
        query_words = query.lower().split() if not case_sensitive else query.split()

        matches = []
        for entry in entries:
            text = entry.get('text', '').strip()
            if not text:
                continue

            text_to_search = text if case_sensitive else text.lower()
            search_query = query if case_sensitive else query.lower()

            query_matches = False
            match_start = -1

            if search_query in text_to_search:
                query_matches = True
                match_start = text_to_search.find(search_query)
            elif all(word in text_to_search for word in query_words):
                query_matches = True
                match_start = text_to_search.find(query_words[0])

            if query_matches:
                matches.append({
                    'timestamp': entry.get('timestamp', 0),
                    'text': text,
                    'duration': entry.get('duration', 0),
                    'match_start': match_start if match_start >= 0 else 0,
                    'match_length': len(query)
                })

        matches.sort(key=lambda x: x['timestamp'])
        logger.info(f"Found {len(matches)} English transcript matches for '{query}' in video {video_id}")
        return matches

    def get_full_english_transcript_text(self, video_id: str) -> str:
        """Return full English transcript text as a single string."""
        entries = self.get_english_transcript(video_id)
        if not entries:
            return ""
        chunks = [entry.get('text', '').strip() for entry in entries if entry.get('text', '').strip()]
        return " ".join(chunks).strip()

    # ------------------------------------------------------------------
    # Concept detection
    # ------------------------------------------------------------------

    def detect_and_store_concepts(self, video_id: str) -> List[DetectedConcept]:
        """Detect concepts for a video and update cache"""
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if not cache_file.exists():
            logger.error(f"❌ Video {video_id} not found in cache")
            return []

        analysis = self._load_cached_analysis(cache_file)

        has_transcript = analysis.transcript and len(analysis.transcript) > 0
        has_code_segments = analysis.code_segments and len(analysis.code_segments) > 0

        if not has_transcript and not has_code_segments:
            logger.warning(f"⚠️  No transcript or code segments available for concept detection in video {video_id}")
            logger.info(f"   Transcript entries: {len(analysis.transcript) if analysis.transcript else 0}")
            logger.info(f"   Code segments: {len(analysis.code_segments) if analysis.code_segments else 0}")
            logger.info(f"💡 Tip: Extract transcript first using extract_transcript_for_video()")
            return []

        logger.info(f"🤖 Detecting concepts for video {video_id}...")
        logger.info(f"   📝 Transcript entries: {len(analysis.transcript) if analysis.transcript else 0}")
        logger.info(f"   💻 Code segments: {len(analysis.code_segments) if analysis.code_segments else 0}")

        try:
            detected_concepts = self.concept_detector.detect_concepts(
                transcript=analysis.transcript,
                code_segments=analysis.code_segments
            )

            if not detected_concepts:
                logger.warning(f"⚠️  Concept detection returned no results for video {video_id}")
                return []

            analysis.detected_concepts = detected_concepts
            self._cache_analysis(analysis, cache_file)

            logger.info(f"✅ Detected {len(detected_concepts)} concepts and updated cache")
            return detected_concepts

        except Exception as e:
            logger.error(f"❌ Error during concept detection for video {video_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []

    def get_detected_concepts(self, video_id: str) -> List[Dict]:
        """Get detected concepts for a video"""
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if not cache_file.exists():
            return []

        analysis = self._load_cached_analysis(cache_file)

        if not analysis.detected_concepts:
            return []

        return [asdict(concept) for concept in analysis.detected_concepts]

    # ------------------------------------------------------------------
    # Video status & management
    # ------------------------------------------------------------------

    def get_video_status(self, video_id: str) -> Dict:
        """Get processing status of a video"""
        cache_file = self.cache_dir / f"{video_id}_analysis.json"

        if cache_file.exists():
            transcript_available = False
            try:
                analysis = self._load_cached_analysis(cache_file)
                transcript_available = bool(analysis.transcript and len(analysis.transcript) > 0)
            except Exception as e:
                logger.warning(f"Could not read transcript availability for {video_id}: {e}")

            return {
                "video_id": video_id,
                "status": "completed",
                "progress": 100.0,
                "stage": "Ready for pause-to-code" if transcript_available else "Ready with limited features (no transcript)",
                "transcript_available": transcript_available
            }

        if video_id in self.processing_progress:
            progress_info = self.processing_progress[video_id]
            return {
                "video_id": video_id,
                "status": progress_info['status'],
                "progress": progress_info['progress'],
                "stage": progress_info['stage'],
                "current_frame": progress_info.get('current_frame', 0),
                "total_frames": progress_info.get('total_frames', 0)
            }

        video_dir = self.cache_dir / "videos"
        video_files = list(video_dir.rglob(f"*/{video_id}/video.mp4"))
        partial_files = list(video_dir.rglob(f"*/{video_id}/*.part")) + list(video_dir.rglob(f"*/{video_id}/*.ytdl"))

        if partial_files:
            return {
                "video_id": video_id,
                "status": "processing",
                "progress": 1.0,
                "stage": "Downloading video..."
            }

        if video_files:
            max_size = 0
            for vf in video_files:
                try:
                    max_size = max(max_size, vf.stat().st_size)
                except Exception:
                    pass

            if max_size < (1 * 1024 * 1024):
                return {
                    "video_id": video_id,
                    "status": "failed",
                    "progress": 0.0,
                    "stage": "Stale partial download detected. Retrying is required."
                }

            return {
                "video_id": video_id,
                "status": "not_found",
                "progress": 0.0,
                "stage": "Not started"
            }

        return {
            "video_id": video_id,
            "status": "not_found",
            "progress": 0.0,
            "stage": "Not started"
        }

    def cancel_video_processing(self, video_id: str):
        """Cancel ongoing video processing"""
        logger.info(f"🛑 Cancelling processing for video: {video_id}")

        if video_id in self.processing_progress:
            del self.processing_progress[video_id]
            logger.info(f"Removed from progress tracking")

        video_dir = self.cache_dir / "videos"
        for file_path in video_dir.rglob(f"*/{video_id}/*"):
            if file_path.is_file() and file_path.suffix.lower() in {".mp4", ".part", ".ytdl", ".m4a", ".webm"}:
                try:
                    file_path.unlink()
                    logger.info(f"Removed file: {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to remove file {file_path}: {e}")

    # ------------------------------------------------------------------
    # Real-time frame analysis
    # ------------------------------------------------------------------

    def extract_frame_and_analyze(self, video_id: str, timestamp: float, playlist_id: str = None) -> Dict:
        """Extract frame at specific timestamp and analyze with VLM"""
        try:
            precomputed = self.get_code_at_timestamp(video_id, timestamp, tolerance=1.0)
            if precomputed.get("found"):
                if precomputed.get("segment_type") == "code" and precomputed.get("code_content"):
                    return {
                        "timestamp": precomputed.get("timestamp_actual", timestamp),
                        "segment_type": "code",
                        "code_content": precomputed.get("code_content"),
                        "learning_topic": None,
                        "confidence": precomputed.get("confidence", 0.0),
                        "language": precomputed.get("language", "python"),
                        "code_complete": precomputed.get("code_complete", False),
                        "source": "precomputed"
                    }

                logger.debug("Precomputed learning segment ignored; running real-time frame analysis")

            cached_entries = self.realtime_analysis_cache.get(video_id, [])
            for entry in cached_entries:
                if abs(entry.get("timestamp", -9999.0) - timestamp) <= 1.0:
                    result = dict(entry.get("result", {}))
                    if result.get("confidence", 0.0) == 0.0 and result.get("learning_topic") == "Analysis failed":
                        continue
                    result["source"] = "realtime_cache"
                    return result

            video_dir = self.cache_dir / "videos"
            video_file = None

            if playlist_id:
                playlist_folder = playlist_id[:20] if playlist_id else 'single'
                potential_path = video_dir / playlist_folder / video_id / "video.mp4"
                if potential_path.exists():
                    video_file = potential_path
                    logger.info(f"Found video at: {potential_path}")

            if not video_file:
                potential_path = video_dir / "single" / video_id / "video.mp4"
                if potential_path.exists():
                    video_file = potential_path
                    logger.info(f"Found video in 'single' folder: {potential_path}")

            if not video_file:
                logger.info(f"Searching all playlist folders for video {video_id}...")
                for playlist_folder in video_dir.iterdir():
                    if playlist_folder.is_dir():
                        potential_path = playlist_folder / video_id / "video.mp4"
                        if potential_path.exists():
                            video_file = potential_path
                            logger.info(f"Found video at: {potential_path}")
                            break

            if not video_file:
                logger.error(f"ERROR: Video {video_id} not found in any folder")
                return {
                    "error": "Video not downloaded yet",
                    "message": "The video is still processing. Please wait."
                }

            video_path = video_file

            frame = self.processor.extract_frame_at_timestamp(str(video_path), timestamp)

            if frame is None:
                return {
                    "error": "Failed to extract frame",
                    "message": "Could not extract frame at this timestamp"
                }

            analysis = self.extractor.analyze_frame(frame, timestamp)

            if analysis.get("analysis_error_code"):
                if analysis.get("analysis_error_code") == "gemini_quota_exceeded":
                    return {
                        "error": "gemini_quota_exceeded",
                        "message": "Pause-to-code is temporarily unavailable: Gemini quota exceeded.",
                        "timestamp": timestamp,
                    }

                return {
                    "error": "frame_analysis_failed",
                    "message": "Pause-to-code frame analysis failed. Please try again.",
                    "timestamp": timestamp,
                }

            result = {
                "timestamp": timestamp,
                "segment_type": analysis.get('segment_type'),
                "code_content": analysis.get('code_content'),
                "learning_topic": analysis.get('learning_topic'),
                "confidence": analysis.get('confidence', 0.0),
                "language": analysis.get('language', 'python'),
                "code_complete": analysis.get('code_complete', False),
                "source": "realtime_gemini"
            }

            if not (result.get("confidence", 0.0) == 0.0 and result.get("learning_topic") == "Analysis failed"):
                entries = self.realtime_analysis_cache.setdefault(video_id, [])
                entries.append({"timestamp": timestamp, "result": result})
                if len(entries) > 30:
                    self.realtime_analysis_cache[video_id] = entries[-30:]

            return result

        except Exception as e:
            logger.error(f"Error extracting and analyzing frame: {e}")
            return {
                "error": str(e),
                "message": "Failed to analyze frame"
            }

    # ------------------------------------------------------------------
    # Playlist
    # ------------------------------------------------------------------

    def get_playlist_videos(self, playlist_url: str) -> Dict:
        """Extract list of videos from a YouTube playlist"""
        try:
            from app.services.video_processing import _resolve_valid_cookie_file

            cache_key = hashlib.md5(playlist_url.encode()).hexdigest()
            cache_file = self.cache_dir / f"playlist_{cache_key}.json"

            if cache_file.exists():
                cache_age = time.time() - cache_file.stat().st_mtime
                if cache_age < 300:
                    logger.info(f"Using cached playlist info (age: {cache_age:.1f}s)")
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            cached_data = json.load(f)
                            logger.info(f"Loaded {len(cached_data['videos'])} videos from cache")
                            return cached_data
                    except Exception as e:
                        logger.warning(f"Cache read failed, fetching fresh: {e}")

            logger.info(f"Extracting playlist info from: {playlist_url}")

            ydl_opts = {
                'extract_flat': 'in_playlist',
                'skip_download': True,
                'retries': 1,
                'fragment_retries': 1,
                'socket_timeout': 8,
                'quiet': True,
                'no_warnings': True,
                'http_headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
            }

            cookie_file = _resolve_valid_cookie_file()
            cookies_browser = os.getenv('YTDLP_COOKIES_FROM_BROWSER', '').strip()
            use_cookies = bool(cookie_file or cookies_browser)

            if cookie_file:
                ydl_opts['cookiefile'] = cookie_file
                logger.info("Using YTDLP_COOKIE_FILE for playlist extraction")
            elif cookies_browser:
                browser_profile = os.getenv('YTDLP_COOKIES_BROWSER_PROFILE', '').strip() or None
                ydl_opts['cookiesfrombrowser'] = (cookies_browser, browser_profile, None, None)
                logger.info(f"Using YTDLP_COOKIES_FROM_BROWSER for playlist extraction (browser={cookies_browser})")

            info = None
            try:
                logger.info(f"Attempting playlist extraction...")
                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    info = ydl.extract_info(playlist_url, download=False)
            except Exception as verbose_error:
                error_str = str(verbose_error).lower()
                logger.warning(f"Extraction failed on first attempt: {verbose_error}")

                if use_cookies and ('cookies' in error_str or 'load' in error_str):
                    logger.info("Cookie loading failed, retrying without cookies...")
                    ydl_opts.pop('cookiefile', None)
                    ydl_opts.pop('cookiesfrombrowser', None)

                    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                        info = ydl.extract_info(playlist_url, download=False)
                else:
                    logger.info(f"Retrying with ignoreerrors enabled...")
                    ydl_opts_quiet = {**ydl_opts, 'ignoreerrors': True}
                    with yt_dlp.YoutubeDL(ydl_opts_quiet) as ydl:
                        info = ydl.extract_info(playlist_url, download=False)

                    if info is None:
                        raise Exception(f"Extraction failed: {verbose_error}")

            if info is None:
                logger.error(f"Failed to extract playlist info: info is None after all attempts")
                raise ValueError("YouTube URL could not be processed. Verify the URL is valid and publicly accessible.")

            logger.info(f"Successfully extracted info, type: {info.get('_type', 'unknown')}")

            if info.get('_type') != 'playlist':
                video_title = info.get('title', 'Unknown')
                video_id = info.get('id')

                if not video_id:
                    logger.warning(f"Single video extracted but has no ID: {video_title}")
                    raise ValueError("Could not extract video ID from YouTube URL")

                logger.info(f"Extracted single video: {video_id} - {video_title}")
                return {
                    'playlist_title': video_title,
                    'videos': [{
                        'video_id': video_id,
                        'title': video_title,
                        'thumbnail': info.get('thumbnail', ''),
                        'duration': info.get('duration', 0),
                        'url': f"https://www.youtube.com/watch?v={video_id}"
                    }]
                }

            playlist_title = info.get('title', 'Unknown Playlist')
            videos = []
            entries = info.get('entries', [])

            if not entries:
                logger.warning(f"Playlist has no entries: {playlist_title}")
                raise ValueError(f"Playlist '{playlist_title}' is empty or unavailable")

            logger.info(f"Processing {len(entries)} entries from playlist...")
            for idx, entry in enumerate(entries):
                if entry:
                    video_id = entry.get('id')
                    if not video_id:
                        logger.debug(f"Entry {idx} has no ID, skipping")
                        continue

                    videos.append({
                        'video_id': video_id,
                        'title': entry.get('title', f'Video {idx + 1}'),
                        'thumbnail': entry.get('thumbnail', ''),
                        'duration': entry.get('duration', 0),
                        'url': f"https://www.youtube.com/watch?v={video_id}"
                    })

            if not videos:
                logger.error(f"No valid videos extracted from {len(entries)} entries")
                raise ValueError(f"No valid videos found in playlist '{playlist_title}'")

            logger.info(f"Successfully extracted {len(videos)} videos from playlist: {playlist_title}")

            result = {
                'playlist_title': playlist_title,
                'videos': videos
            }

            try:
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2)
                logger.info(f"Cached playlist info for future requests")
            except Exception as e:
                logger.warning(f"Failed to cache playlist info: {e}")

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error extracting playlist: {error_msg}")
            import traceback
            logger.debug(traceback.format_exc())
            raise

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_video_id(self, youtube_url: str) -> str:
        """Extract video ID from YouTube URL"""
        if 'youtu.be/' in youtube_url:
            return youtube_url.split('youtu.be/')[1].split('?')[0]
        elif 'v=' in youtube_url:
            return youtube_url.split('v=')[1].split('&')[0]
        else:
            return hashlib.md5(youtube_url.encode()).hexdigest()

    def _extract_playlist_id(self, youtube_url: str) -> Optional[str]:
        """Extract playlist ID from YouTube URL"""
        match = re.search(r'[?&]list=([^&]+)', youtube_url)
        if match:
            return match.group(1)
        return None

    def _cache_analysis(self, analysis: VideoAnalysis, cache_file: Path):
        """Save analysis to cache"""
        data = {
            'video_id': analysis.video_id,
            'video_title': analysis.video_title,
            'duration': analysis.duration,
            'total_frames_analyzed': analysis.total_frames_analyzed,
            'code_segments': [asdict(seg) for seg in analysis.code_segments],
            'metadata': analysis.metadata,
            'extraction_date': analysis.extraction_date
        }

        if analysis.transcript:
            data['transcript'] = [asdict(entry) for entry in analysis.transcript]
            logger.debug(f"Caching {len(analysis.transcript)} transcript entries")
        else:
            logger.debug("No transcript to cache")

        if analysis.detected_concepts:
            data['detected_concepts'] = [asdict(concept) for concept in analysis.detected_concepts]
            logger.debug(f"Caching {len(analysis.detected_concepts)} detected concepts")
        else:
            logger.debug("No detected concepts to cache")

        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Analysis cached to {cache_file}")

    def _load_cached_analysis(self, cache_file: Path) -> VideoAnalysis:
        """Load analysis from cache"""
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        segments = [CodeSegment(**seg) for seg in data['code_segments']]

        transcript = None
        if 'transcript' in data and data['transcript']:
            transcript = [_make_transcript_entry(entry) for entry in data['transcript']]

        detected_concepts = None
        if 'detected_concepts' in data and data['detected_concepts']:
            detected_concepts = [DetectedConcept(**concept) for concept in data['detected_concepts']]

        return VideoAnalysis(
            video_id=data['video_id'],
            video_title=data['video_title'],
            duration=data['duration'],
            total_frames_analyzed=data['total_frames_analyzed'],
            code_segments=segments,
            metadata=data['metadata'],
            extraction_date=data['extraction_date'],
            transcript=transcript,
            detected_concepts=detected_concepts
        )


# ---------------------------------------------------------------------------
# CLI entry point (unchanged)
# ---------------------------------------------------------------------------

def main():
    """Example usage of the Pause-to-Code service"""
    service = PauseToCodeService()

    youtube_url = "https://www.youtube.com/watch?v=YOUR_VIDEO_ID"

    print("Processing video...")
    analysis = service.process_video(youtube_url)

    print(f"\nVideo Analysis Complete:")
    print(f"Title: {analysis.video_title}")
    print(f"Duration: {analysis.duration}s")
    print(f"Code segments found: {len(analysis.code_segments)}")

    timestamp = 120.5
    result = service.get_code_at_timestamp(analysis.video_id, timestamp)

    print(f"\nCode at {timestamp}s:")
    print(json.dumps(result, indent=2))

    service.export_code_timeline(
        analysis.video_id,
        f"{analysis.video_id}_timeline.md"
    )


if __name__ == "__main__":
    main()
