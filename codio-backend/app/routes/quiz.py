"""
Codio Backend - Quiz Routes
Handles adaptive quiz sessions: start, submit answer, get status, end session.
Logic is unchanged from the original pause_to_code_api.py.
"""

import uuid
import logging
import traceback
from datetime import datetime

from flask import Blueprint, request, jsonify

from config.settings import QUIZ_TOTAL_QUESTIONS
from app.utils.jwt_auth import token_required
from app.utils.helpers import normalize_question_text
from app.services.quiz_service import generate_quiz_question, calculate_next_level

logger = logging.getLogger(__name__)

quiz_bp = Blueprint('quiz', __name__, url_prefix='/api/v1/quiz')


def init_quiz_routes(db, service):
    """Register routes that depend on the shared database and service instances."""

    @quiz_bp.route('/start', methods=['POST'])
    @token_required
    def start_quiz_session():
        """Start a new quiz session from transcript text or from a video transcript."""
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/quiz/start START ==========")

        try:
            data = request.get_json() or {}
            current_user = request.current_user
            user_email = (data.get('user_email') or current_user['email']).strip().lower()

            if current_user['email'] != user_email:
                return jsonify({
                    "success": False,
                    "error": "Unauthorized: You can only start quiz sessions for your own account"
                }), 403

            transcript = (data.get('transcript') or '').strip()
            video_id = data.get('video_id')

            if not transcript and video_id:
                transcript = service.get_full_transcript_text(video_id)

            # Fallback: allow quiz to start even when transcript is unavailable.
            if not transcript and video_id:
                try:
                    cache_file = service.cache_dir / f"{video_id}_analysis.json"
                    if cache_file.exists():
                        analysis = service._load_cached_analysis(cache_file)
                        transcript = (
                            f"Video context: {analysis.video_title}. "
                            f"Duration: {int(analysis.duration)} seconds. "
                            "Generate beginner-friendly Python quiz questions based on likely concepts "
                            "such as variables, loops, conditionals, functions, and data structures."
                        )
                        logger.info(f"[{request_id}] Using metadata fallback context for quiz start (no transcript)")
                except Exception as fallback_error:
                    logger.warning(f"[{request_id}] Failed metadata fallback for quiz start: {fallback_error}")

            if not transcript:
                return jsonify({
                    "success": False,
                    "error": "Missing transcript. Provide transcript text or a video_id with an extracted transcript."
                }), 400

            session_id = str(uuid.uuid4())
            created = db.create_quiz_session(
                session_id=session_id,
                user_email=user_email,
                transcript_text=transcript,
                video_id=video_id
            )

            if not created:
                return jsonify({
                    "success": False,
                    "error": "Failed to create quiz session"
                }), 500

            existing_questions = db.get_quiz_session_question_texts(session_id)
            used_set = {normalize_question_text(q) for q in existing_questions}
            question = generate_quiz_question(transcript, difficulty=1, used_questions=existing_questions)
            for _ in range(4):
                if normalize_question_text(question.get('question', '')) not in used_set:
                    break
                question = generate_quiz_question(transcript, difficulty=1, used_questions=existing_questions)
            question_id = str(uuid.uuid4())
            db.add_quiz_question(
                question_id=question_id,
                session_id=session_id,
                question_type=question.get('type', 'multiple_choice'),
                difficulty=int(question.get('difficulty', 1)),
                question_text=question.get('question', 'Choose the correct answer.'),
                options=question.get('options', []),
                correct_answer=str(question.get('correctAnswer', 0)),
                explanation=question.get('explanation', '')
            )

            return jsonify({
                "success": True,
                "session_id": session_id,
                "first_question": {
                    "id": question_id,
                    "type": question.get('type', 'multiple_choice'),
                    "difficulty": int(question.get('difficulty', 1)),
                    "content": {
                        "question": question.get('question', ''),
                        "options": question.get('options', []),
                        "explanation": question.get('explanation', ''),
                        "codeTemplate": question.get('codeTemplate', ''),
                        "codeSnippet": question.get('codeSnippet', ''),
                    }
                },
                "questions_batch": [],
                "current_level": 1,
                "learning_rate": 0.0,
            }), 200
        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/quiz/start END ==========\n")

    @quiz_bp.route('/submit-answer', methods=['POST'])
    @token_required
    def submit_quiz_answer():
        """Submit answer, update adaptive progress, and return next question."""
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/quiz/submit-answer START ==========")

        try:
            data = request.get_json() or {}
            current_user = request.current_user

            session_id = data.get('session_id', '').strip()
            question_id = data.get('question_id', '').strip()
            answer = data.get('answer', None)
            time_taken = int(data.get('time_taken', 0) or 0)

            if not session_id or not question_id or answer is None:
                return jsonify({
                    "success": False,
                    "error": "session_id, question_id and answer are required"
                }), 400

            session = db.get_quiz_session(session_id)
            if not session:
                return jsonify({
                    "success": False,
                    "error": "Quiz session not found"
                }), 404

            if session['user_email'] != current_user['email']:
                return jsonify({
                    "success": False,
                    "error": "Unauthorized: You can only submit answers for your own quiz session"
                }), 403

            question = db.get_quiz_question(question_id)
            if not question:
                return jsonify({
                    "success": False,
                    "error": "Question not found"
                }), 404

            correct_answer = question['correct_answer']
            question_type = question.get('question_type', 'multiple_choice')

            # Type-aware answer comparison
            if question_type == 'fill_in_blank':
                # Case-insensitive comparison for fill-in-blank
                is_correct = str(answer).strip().lower() == str(correct_answer).strip().lower()
            elif question_type == 'true_false':
                # Normalize true/false comparison
                is_correct = str(answer).strip().lower() == str(correct_answer).strip().lower()
            else:
                # MCQ and output_prediction: compare as strings
                is_correct = str(answer).strip() == str(correct_answer).strip()

            db.record_quiz_attempt(
                session_id=session_id,
                question_id=question_id,
                user_answer=str(answer),
                is_correct=is_correct,
                time_taken=time_taken
            )

            questions_answered = int(session['questions_answered']) + 1
            correct_answers = int(session['correct_answers']) + (1 if is_correct else 0)
            learning_rate = round(correct_answers / questions_answered, 4)
            new_level = calculate_next_level(int(session['current_level']), questions_answered, correct_answers)

            db.update_quiz_session_progress(
                session_id=session_id,
                current_level=new_level,
                learning_rate=learning_rate,
                questions_answered=questions_answered,
                correct_answers=correct_answers,
            )

            should_continue = questions_answered < QUIZ_TOTAL_QUESTIONS
            next_question_payload = None

            if should_continue:
                existing_questions = db.get_quiz_session_question_texts(session_id)
                used_set = {normalize_question_text(q) for q in existing_questions}
                next_question = generate_quiz_question(
                    session['transcript_text'],
                    difficulty=new_level,
                    used_questions=existing_questions
                )
                for _ in range(4):
                    if normalize_question_text(next_question.get('question', '')) not in used_set:
                        break
                    next_question = generate_quiz_question(
                        session['transcript_text'],
                        difficulty=new_level,
                        used_questions=existing_questions
                    )
                next_question_id = str(uuid.uuid4())
                db.add_quiz_question(
                    question_id=next_question_id,
                    session_id=session_id,
                    question_type=next_question.get('type', 'multiple_choice'),
                    difficulty=int(next_question.get('difficulty', new_level)),
                    question_text=next_question.get('question', 'Choose the correct answer.'),
                    options=next_question.get('options', []),
                    correct_answer=str(next_question.get('correctAnswer', 0)),
                    explanation=next_question.get('explanation', '')
                )

                next_question_payload = {
                    "id": next_question_id,
                    "type": next_question.get('type', 'multiple_choice'),
                    "difficulty": int(next_question.get('difficulty', new_level)),
                    "content": {
                        "question": next_question.get('question', ''),
                        "options": next_question.get('options', []),
                        "explanation": next_question.get('explanation', ''),
                        "codeTemplate": next_question.get('codeTemplate', ''),
                        "codeSnippet": next_question.get('codeSnippet', ''),
                    }
                }

            return jsonify({
                "success": True,
                "is_correct": is_correct,
                "explanation": question.get('explanation', ''),
                "new_level": new_level,
                "learning_rate": learning_rate,
                "next_question": next_question_payload,
                "should_continue": should_continue,
                "progress": {
                    "questionsAnswered": questions_answered,
                    "correctAnswers": correct_answers,
                    "shouldContinue": should_continue,
                    "totalQuestions": QUIZ_TOTAL_QUESTIONS,
                }
            }), 200
        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/quiz/submit-answer END ==========\n")

    @quiz_bp.route('/session/<session_id>', methods=['GET'])
    @token_required
    def get_quiz_session_status(session_id):
        """Get current quiz session progress and status."""
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== GET /api/v1/quiz/session/{session_id} START ==========")

        try:
            current_user = request.current_user
            session = db.get_quiz_session(session_id)
            if not session:
                return jsonify({
                    "success": False,
                    "error": "Quiz session not found"
                }), 404

            if session['user_email'] != current_user['email']:
                return jsonify({
                    "success": False,
                    "error": "Unauthorized: You can only access your own quiz session"
                }), 403

            questions_answered = int(session.get('questions_answered', 0))
            progress = min(100.0, (questions_answered / QUIZ_TOTAL_QUESTIONS) * 100)

            return jsonify({
                "success": True,
                "session_id": session_id,
                "progress": progress,
                "questions_answered": questions_answered,
                "current_level": int(session.get('current_level', 1)),
                "learning_rate": float(session.get('learning_rate', 0.0)),
                "total_questions": QUIZ_TOTAL_QUESTIONS,
                "started_at": session.get('started_at'),
                "ended_at": session.get('ended_at')
            }), 200
        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== GET /api/v1/quiz/session/{session_id} END ==========\n")

    @quiz_bp.route('/end-session/<session_id>', methods=['POST'])
    @token_required
    def end_quiz_session(session_id):
        """End a quiz session and return final analytics."""
        request_id = f"req_{datetime.now().timestamp()}"
        logger.info(f"[{request_id}] ========== POST /api/v1/quiz/end-session/{session_id} START ==========")

        try:
            current_user = request.current_user
            session = db.get_quiz_session(session_id)
            if not session:
                return jsonify({
                    "success": False,
                    "error": "Quiz session not found"
                }), 404

            if session['user_email'] != current_user['email']:
                return jsonify({
                    "success": False,
                    "error": "Unauthorized: You can only end your own quiz session"
                }), 403

            db.end_quiz_session(session_id)
            stats = db.get_quiz_attempt_stats(session_id)
            final_score = 0.0
            if stats['total_attempts'] > 0:
                final_score = round((stats['correct_attempts'] / stats['total_attempts']) * 100, 2)

            return jsonify({
                "success": True,
                "session_id": session_id,
                "final_score": final_score,
                "questions_answered": stats['total_attempts'],
                "correct_answers": stats['correct_attempts'],
                "average_time_seconds": stats['average_time'],
                "learning_rate": float(session.get('learning_rate', 0.0)),
                "message": "Quiz session ended successfully"
            }), 200
        except Exception as e:
            logger.error(f"[{request_id}] Exception: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
        finally:
            logger.info(f"[{request_id}] ========== POST /api/v1/quiz/end-session/{session_id} END ==========\n")
