"""
Codio Backend - Concept Detection Service
Detect programming concepts from video transcripts and code segments.
Uses OpenAI-compatible API (supports Gemini models via proxy).
"""

import os
import re
import json
import logging
import traceback
from typing import List, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from app.services.video_processing import (
    TranscriptEntry,
    CodeSegment,
    DetectedConcept,
)

logger = logging.getLogger(__name__)


def _extract_balanced_json_objects(array_text: str) -> List[dict]:
    """Extract valid top-level JSON objects from an array-like text, tolerating a broken tail."""
    objects = []
    depth = 0
    start_idx = None
    in_string = False
    escaped = False

    for i, ch in enumerate(array_text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue

        if ch == '{':
            if depth == 0:
                start_idx = i
            depth += 1
        elif ch == '}':
            if depth > 0:
                depth -= 1
                if depth == 0 and start_idx is not None:
                    candidate = array_text[start_idx:i + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict):
                            objects.append(obj)
                    except Exception:
                        pass
                    start_idx = None

    return objects


def _extract_json_string_field(block: str, key: str) -> Optional[str]:
    """Extract a JSON string field value from a possibly incomplete object block."""
    key_pat = f'"{key}"'
    key_idx = block.find(key_pat)
    if key_idx == -1:
        return None

    colon_idx = block.find(':', key_idx + len(key_pat))
    if colon_idx == -1:
        return None

    start_quote = block.find('"', colon_idx + 1)
    if start_quote == -1:
        return None

    out = []
    escaped = False
    for i in range(start_quote + 1, len(block)):
        ch = block[i]
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == '\\':
            escaped = True
            continue
        if ch == '"':
            return ''.join(out).strip()
        out.append(ch)

    return ''.join(out).strip() or None


def _extract_json_number_field(block: str, key: str) -> Optional[float]:
    """Extract a numeric field from a possibly incomplete object block."""
    match = re.search(rf'"{re.escape(key)}"\s*:\s*([-+]?\d+(?:\.\d+)?)', block)
    if not match:
        return None
    try:
        return float(match.group(1))
    except Exception:
        return None


def _extract_json_array_field(block: str, key: str) -> Optional[List[float]]:
    """Extract a numeric array field from a possibly incomplete object block."""
    match = re.search(rf'"{re.escape(key)}"\s*:\s*(\[[^\]]*\])', block, flags=re.DOTALL)
    if not match:
        return None

    raw = match.group(1)
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            vals = []
            for item in parsed:
                try:
                    vals.append(float(item))
                except Exception:
                    continue
            return vals
    except Exception:
        pass
    return None


def _extract_partial_concept_dicts(text: str) -> List[dict]:
    """Recover concept entries from truncated response text by field extraction."""
    concepts = []
    concept_mark = '"concept_name"'
    starts = [m.start() for m in re.finditer(re.escape(concept_mark), text)]

    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        block = text[start:end]

        concept_name = _extract_json_string_field(block, 'concept_name')
        if not concept_name:
            continue

        category = _extract_json_string_field(block, 'category') or 'general'
        timestamps = _extract_json_array_field(block, 'timestamps') or []
        confidence = _extract_json_number_field(block, 'confidence')
        description = _extract_json_string_field(block, 'overview') or _extract_json_string_field(block, 'description')

        concepts.append({
            'concept_name': concept_name,
            'category': category,
            'timestamps': timestamps,
            'confidence': confidence if confidence is not None else 0.7,
            'description': description or ''
        })

    return concepts


def _parse_concept_response_json(response_text: str) -> dict:
    """Parse LLM concept response robustly, returning at least {'concepts': [...]} when possible."""
    text = (response_text or "").strip()
    if not text:
        raise json.JSONDecodeError("Empty response", "", 0)

    # Strip markdown fences if present.
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text).strip()

    # Remove control characters that can break JSON parsing.
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", text)

    # Fast path: valid JSON.
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {"concepts": []}
    except json.JSONDecodeError:
        pass

    # Try extracting a full JSON object region.
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        candidate = match.group(0)
        candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else {"concepts": []}
        except json.JSONDecodeError:
            pass

    # Salvage path: collect all balanced objects inside the concepts array, ignoring broken tail.
    concepts_key = text.find('"concepts"')
    if concepts_key == -1:
        concepts_key = text.find("'concepts'")

    if concepts_key != -1:
        array_start = text.find('[', concepts_key)
        if array_start != -1:
            array_text = text[array_start:]
            recovered = _extract_balanced_json_objects(array_text)
            if recovered:
                return {"concepts": recovered}

    partial = _extract_partial_concept_dicts(text)
    if partial:
        return {"concepts": partial}

    raise json.JSONDecodeError("Unable to parse concept response", text, 0)


class ConceptDetector:
    """Detect programming concepts from video transcripts and code segments"""

    def __init__(self):
        self.client = None
        self.model = "gemini-2.5-flash"

        # Try OpenAI-compatible API first (works with Gemini proxy)
        openai_key = os.getenv("OPENAI_API_KEY", "")
        if openai_key and OpenAI:
            try:
                self.client = OpenAI()  # Uses OPENAI_API_KEY and OPENAI_BASE_URL env vars
                logger.info("✅ ConceptDetector initialized with OpenAI-compatible API")
            except Exception as e:
                logger.warning(f"⚠️  Failed to initialize OpenAI client: {e}")

        # Fallback to google.generativeai if available
        if not self.client:
            gemini_key = os.getenv("PAUSE_TO_CODE_GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
            if gemini_key and gemini_key != "placeholder":
                try:
                    import google.generativeai as genai
                    genai.configure(api_key=gemini_key)
                    self.gemini_model = genai.GenerativeModel('gemini-2.5-flash')
                    self.use_gemini_native = True
                    logger.info("✅ ConceptDetector initialized with native Gemini API")
                except Exception as e:
                    logger.warning(f"⚠️  Failed to initialize Gemini: {e}")
                    self.use_gemini_native = False
            else:
                self.use_gemini_native = False

    @staticmethod
    def _clean_vtt_tags(text: str) -> str:
        """Remove VTT subtitle formatting tags"""
        if not text:
            return text
        cleaned = re.sub(r'<[\d:.]+>', '', text)
        cleaned = re.sub(r'</?c>', '', cleaned)
        cleaned = re.sub(r'<[^>]+>', '', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned

    def detect_concepts(
        self,
        transcript: Optional[List[TranscriptEntry]],
        code_segments: List[CodeSegment]
    ) -> List[DetectedConcept]:
        """Detect programming concepts from transcript and code segments using LLM."""
        try:
            if not self.client and not getattr(self, 'use_gemini_native', False):
                logger.error("❌ No LLM API configured for concept detection. Set OPENAI_API_KEY or GEMINI_API_KEY.")
                return []

            # Prepare text content for analysis
            transcript_text = ""
            if transcript:
                transcript_parts = []
                for entry in transcript:
                    clean_text = self._clean_vtt_tags(entry.text)
                    if clean_text:
                        transcript_parts.append(f"[{entry.timestamp:.1f}s] {clean_text}")
                transcript_text = "\n".join(transcript_parts)

            code_examples = []
            code_timestamps = []
            for seg in code_segments:
                if seg.code_content and seg.segment_type == 'code':
                    code_examples.append(f"[{seg.timestamp:.1f}s]\n{seg.code_content}")
                    code_timestamps.append(seg.timestamp)

            combined_text = ""
            if transcript_text:
                combined_text = f"Video Transcript:\n{transcript_text[:12000]}\n\n"

            if code_examples:
                combined_text += f"Code Examples from Video:\n" + "\n---\n".join(code_examples[:15])

            if not combined_text.strip():
                logger.warning("⚠️  No content available for concept detection (empty transcript and code)")
                return []

            if len(combined_text.strip()) < 100:
                logger.warning(f"⚠️  Content too short for concept detection ({len(combined_text)} chars)")
                return []

            logger.info(f"📊 Concept detection input: {len(combined_text)} chars, {len(transcript or [])} transcript entries, {len(code_examples)} code examples")

            prompt = f"""You are an AI tutor analyzing a Python programming tutorial video. Your task is to identify and explain all the programming topics/concepts being taught, just like a helpful chatbot would summarize the video content.

Video Content:
{combined_text[:15000]}

Please analyze this video and provide a comprehensive overview of all programming topics discussed. For each topic:

1. **Identify the topic/concept** (e.g., "for loops", "list comprehensions", "error handling")
2. **Provide a brief overview** explaining what the video teaches about this topic (like you're explaining it to a student)
3. **Note when it appears** in the video (timestamps)
4. **Categorize it** (control_flow, data_structures, functions, algorithms, etc.)

Think of this like you're a chatbot giving a summary: "This video covers X, Y, and Z. Here's what you'll learn about each..."

Response format (JSON only, no markdown):
{{
    "concepts": [
        {{
            "concept_name": "for loops",
            "category": "control_flow",
            "timestamps": [45.5, 120.3, 180.0],
            "confidence": 0.95,
            "description": "The video teaches how to use for loops to iterate over lists and ranges. It explains the basic syntax, shows examples of iterating through different data types, and demonstrates nested loops.",
            "overview": "This section covers Python for loops, including basic iteration, range() function, and iterating over different data structures like lists and strings. The instructor demonstrates practical examples and common use cases."
        }}
    ]
}}

Focus on providing helpful, educational overviews for each topic. Include topics like: loops, conditionals, data structures (lists, dictionaries, sets), functions, classes, error handling, file operations, list comprehensions, decorators, generators, and any other Python concepts mentioned.
"""

            logger.info("🤖 Analyzing video content with LLM for topic overview...")

            response_text = self._call_llm(prompt)

            if not response_text:
                logger.error("❌ LLM returned empty response")
                return []

            logger.info(f"📝 Received LLM response: {len(response_text)} chars")

            result = _parse_concept_response_json(response_text)

            detected_concepts = []
            for concept_data in result.get('concepts', []):
                timestamps = concept_data.get('timestamps', [])

                if not timestamps and code_timestamps:
                    timestamps = code_timestamps[:3]

                overview = concept_data.get('overview') or concept_data.get('description', '')

                detected_concepts.append(DetectedConcept(
                    concept_name=concept_data.get('concept_name', 'unknown'),
                    category=concept_data.get('category', 'general'),
                    timestamps=timestamps,
                    confidence=concept_data.get('confidence', 0.5),
                    description=overview
                ))

            logger.info(f"✅ Detected {len(detected_concepts)} topics with LLM overview")
            return detected_concepts

        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse concept detection response: {e}")
            if 'response_text' in locals():
                logger.error(f"Response text: {response_text[:500]}")
            return []
        except Exception as e:
            logger.error(f"❌ Error detecting concepts: {e}")
            logger.error(traceback.format_exc())
            return []

    def _call_llm(self, prompt: str) -> str:
        """Call the LLM API (OpenAI-compatible or native Gemini)"""
        # Try OpenAI-compatible API first
        if self.client:
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are an AI tutor that analyzes programming tutorial videos and identifies concepts. Always respond with valid JSON only, no markdown formatting."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    max_tokens=4096,
                    response_format={"type": "json_object"},
                )
                if response.choices and response.choices[0].message.content:
                    return response.choices[0].message.content.strip()
            except Exception as e:
                logger.warning(f"⚠️  OpenAI API call failed: {e}")

        # Fallback to native Gemini
        if getattr(self, 'use_gemini_native', False):
            try:
                response = self.gemini_model.generate_content(
                    prompt,
                    generation_config={
                        "temperature": 0.2,
                        "top_p": 0.95,
                        "top_k": 40,
                        "max_output_tokens": 4096,
                        "response_mime_type": "application/json",
                    }
                )
                if response and response.text:
                    return response.text.strip()
            except Exception as e:
                logger.warning(f"⚠️  Gemini API call failed: {e}")

        return ""
