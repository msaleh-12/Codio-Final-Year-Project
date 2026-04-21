"""
Codio Backend - Gemini VLM Code Extractor
Core VLM-based code extraction using Gemini API.
Robust JSON parsing to handle Gemini's varied output formats.
"""

import os
import re
import json
import cv2
import base64
import logging
import numpy as np
import google.generativeai as genai
from typing import Dict

from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv(Path(__file__).resolve().parents[2] / '.env')

logger = logging.getLogger(__name__)

# Configure Gemini API
GEMINI_API_KEY = os.getenv("PAUSE_TO_CODE_GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
if not GEMINI_API_KEY or GEMINI_API_KEY == "placeholder":
    logger.error("CRITICAL: No Gemini API key set for pause-to-code!")
    logger.error("Set PAUSE_TO_CODE_GEMINI_API_KEY or GEMINI_API_KEY in .env")
else:
    genai.configure(api_key=GEMINI_API_KEY)
    logger.info("Gemini API configured successfully for pause-to-code")


def _robust_json_parse(text: str) -> dict:
    """Parse JSON robustly, handling common Gemini output quirks."""
    # Strip markdown code fences
    cleaned = text.strip()
    if cleaned.startswith('```'):
        lines = cleaned.split('\n')
        # Remove first line (```json or ```) and last line (```)
        start = 1
        end = len(lines)
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].strip().startswith('```'):
                end = i
                break
        cleaned = '\n'.join(lines[start:end]).strip()

    # Try direct parse first
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Extract JSON object from text
    match = re.search(r'\{[\s\S]*\}', cleaned)
    if match:
        json_str = match.group(0)

        # Try direct parse of extracted JSON
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Fix common issues:
        # 1. Replace JavaScript-style true/false/null
        fixed = json_str
        # 2. Remove trailing commas before } or ]
        fixed = re.sub(r',\s*([}\]])', r'\1', fixed)
        # 3. Fix unquoted property names (simple cases)
        fixed = re.sub(r'(\{|,)\s*(\w+)\s*:', r'\1 "\2":', fixed)
        # 4. Replace single quotes with double quotes (careful with code_content)
        # Only do this if there are no double quotes at all
        if '"' not in fixed:
            fixed = fixed.replace("'", '"')

        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass

        # Last resort: use ast.literal_eval for Python-style dicts
        try:
            import ast
            result = ast.literal_eval(json_str)
            if isinstance(result, dict):
                return result
        except (ValueError, SyntaxError):
            pass

    raise json.JSONDecodeError("Could not parse Gemini response as JSON", text, 0)


class GeminiCodeExtractor:
    """Core VLM-based code extraction using Gemini"""

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.generation_config = {
            "temperature": 0.1,
            "top_p": 0.9,
            "top_k": 20,
            "max_output_tokens": 1024,
            "response_mime_type": "application/json",
        }

    def encode_frame(self, frame: np.ndarray) -> str:
        """Encode frame to base64 for Gemini API"""
        _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
        return base64.b64encode(buffer).decode('utf-8')

    def analyze_frame(self, frame: np.ndarray, timestamp: float) -> Dict:
        """Analyze a single frame using Gemini VLM"""
        try:
            prompt = """Analyze this coding tutorial video frame.

Your task:
1. Detect if the frame shows CODE (code editor, terminal, IDE) or LEARNING (slides, talking head, diagrams)
2. If code is visible, extract ALL the code exactly as shown, preserving indentation
3. If it's a learning frame, describe the topic briefly

You MUST respond with valid JSON in this exact format:
{
    "segment_type": "code",
    "has_code": true,
    "code_content": "the extracted code here",
    "learning_topic": null,
    "confidence": 0.95,
    "language": "python",
    "code_complete": true
}

Or for learning frames:
{
    "segment_type": "learning",
    "has_code": false,
    "code_content": null,
    "learning_topic": "topic being explained",
    "confidence": 0.95,
    "language": "python",
    "code_complete": false
}

Important rules:
- Return ONLY valid JSON, no markdown, no explanation
- Use double quotes for all strings
- Use true/false (lowercase) for booleans
- Use null (lowercase) for null values
- Extract code EXACTLY as shown on screen including comments
- confidence should be between 0.0 and 1.0
"""

            import PIL.Image
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            h, w = frame_rgb.shape[:2]
            max_side = max(h, w)
            if max_side > 1280:
                scale = 1280 / max_side
                new_w = max(1, int(w * scale))
                new_h = max(1, int(h * scale))
                frame_rgb = cv2.resize(frame_rgb, (new_w, new_h), interpolation=cv2.INTER_AREA)
            pil_image = PIL.Image.fromarray(frame_rgb)

            response = self.model.generate_content(
                [prompt, pil_image],
                generation_config=self.generation_config
            )

            response_text = (response.text or "").strip()
            logger.info(f"Gemini raw response at {timestamp:.2f}s: {response_text[:300]}")

            result = _robust_json_parse(response_text)
            result['timestamp'] = timestamp

            logger.info(f"Frame analysis at {timestamp:.2f}s: type={result.get('segment_type')}, has_code={result.get('has_code')}, confidence={result.get('confidence')}")
            return result

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error at {timestamp:.2f}s: {e}")
            logger.error(f"Response text: {response_text[:500]}")
            return self._create_error_result(timestamp, f"JSON parse error: {e}")
        except Exception as e:
            logger.error(f"Error analyzing frame at {timestamp:.2f}s: {e}")
            return self._create_error_result(timestamp, str(e))

    def _create_error_result(self, timestamp: float, error_detail: str = "") -> Dict:
        """Create error result when analysis fails"""
        lowered = (error_detail or "").lower()
        error_code = "analysis_failed"
        if "429" in lowered or "quota" in lowered or "rate limit" in lowered:
            error_code = "gemini_quota_exceeded"

        return {
            "timestamp": timestamp,
            "segment_type": "learning",
            "has_code": False,
            "code_content": None,
            "learning_topic": "Analysis failed",
            "confidence": 0.0,
            "language": "python",
            "code_complete": False,
            "analysis_error_code": error_code,
            "analysis_error_detail": error_detail,
        }
