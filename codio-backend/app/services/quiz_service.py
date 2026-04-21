"""
Codio Backend - Quiz Service
Handles quiz question generation (Gemini + deterministic fallback) and difficulty logic.
Supports multiple question types: multiple_choice, true_false, fill_in_blank, output_prediction.
"""

import os
import json
import random
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

import google.generativeai as genai

from config.settings import QUIZ_USE_GEMINI, QUIZ_GEMINI_TIMEOUT_SECONDS
from app.utils.helpers import normalize_question_text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Question type constants
# ---------------------------------------------------------------------------
QUESTION_TYPES = ["multiple_choice", "true_false", "fill_in_blank", "output_prediction"]

# ---------------------------------------------------------------------------
# Fallback question templates (organized by type and topic)
# ---------------------------------------------------------------------------

_MCQ_TEMPLATES = {
    "loops": [
        {"question": "Which Python keyword is used to iterate over a sequence?", "options": ["for", "loop", "iterate", "repeat"], "correct": 0, "explanation": "Python uses the for keyword to iterate over iterables."},
        {"question": "What does range(3) produce in Python?", "options": ["0, 1, 2", "1, 2, 3", "0, 1, 2, 3", "3"], "correct": 0, "explanation": "range(3) yields 0 up to but not including 3."},
        {"question": "Which statement skips the current loop iteration?", "options": ["continue", "break", "pass", "return"], "correct": 0, "explanation": "continue skips the rest of the current iteration."},
        {"question": "Which statement exits a loop immediately?", "options": ["break", "continue", "stop", "exit"], "correct": 0, "explanation": "break terminates the nearest loop."},
        {"question": "In 'for x in items', what is 'x'?", "options": ["The current item", "The index only", "A list", "The loop length"], "correct": 0, "explanation": "x represents each current item from items."},
    ],
    "lists": [
        {"question": "Which of these creates an empty list in Python?", "options": ["[]", "{}", "()", "list{}"], "correct": 0, "explanation": "Square brackets create a list literal in Python."},
        {"question": "Which method adds one element to the end of a list?", "options": ["append", "add", "push", "insert_end"], "correct": 0, "explanation": "append adds one item to the list tail."},
        {"question": "What does nums[0] access?", "options": ["First element", "Last element", "Length", "A slice"], "correct": 0, "explanation": "Index 0 points to the first list element."},
        {"question": "Which operation returns list length?", "options": ["len(my_list)", "my_list.length()", "size(my_list)", "count(my_list)"], "correct": 0, "explanation": "len(...) returns the number of elements."},
        {"question": "Which slice gets first three elements?", "options": ["my_list[:3]", "my_list[3:]", "my_list[0:2]", "my_list[1:3]"], "correct": 0, "explanation": "[:3] includes indices 0,1,2."},
    ],
    "dictionaries": [
        {"question": "How do you access value for key 'x' in dictionary d?", "options": ["d['x']", "d.x", "d('x')", "x[d]"], "correct": 0, "explanation": "Dictionary values are accessed by key using bracket notation."},
        {"question": "Which method safely returns a value or default for a key?", "options": ["get", "find", "value", "lookup"], "correct": 0, "explanation": "dict.get(key, default) avoids KeyError."},
        {"question": "Which creates an empty dictionary?", "options": ["{}", "[]", "()", "set()"], "correct": 0, "explanation": "Curly braces create a dict literal."},
        {"question": "What does 'k in d' check for dictionary d?", "options": ["If key k exists", "If value k exists", "If d has length k", "If d is sorted"], "correct": 0, "explanation": "Membership checks keys by default."},
        {"question": "Which loop pattern iterates key and value together?", "options": ["for k, v in d.items()", "for k, v in d", "for k in d.values()", "for v in d.keys()"], "correct": 0, "explanation": "items() yields key-value pairs."},
    ],
    "functions": [
        {"question": "Which keyword starts a function definition in Python?", "options": ["def", "function", "fn", "define"], "correct": 0, "explanation": "Python uses def to define functions."},
        {"question": "How do you return a value from a function?", "options": ["return", "yield", "print", "break"], "correct": 0, "explanation": "return sends a value back to the caller."},
        {"question": "What is a function parameter?", "options": ["Input variable in function definition", "Only output value", "A class attribute", "A loop counter"], "correct": 0, "explanation": "Parameters receive input values."},
        {"question": "How do you call function greet with 'Ali'?", "options": ["greet('Ali')", "call greet('Ali')", "greet = 'Ali'", "greet{'Ali'}"], "correct": 0, "explanation": "Functions are called with parentheses."},
        {"question": "What happens if function has no return statement?", "options": ["Returns None", "Returns 0", "Raises error", "Returns empty string"], "correct": 0, "explanation": "Python functions return None by default."},
    ],
    "Python basics": [
        {"question": "Which function prints output to the Python console?", "options": ["print()", "echo()", "write()", "console.log()"], "correct": 0, "explanation": "print() sends text to standard output in Python."},
        {"question": "Which symbol is used for assignment in Python?", "options": ["=", "==", ":=", "->"], "correct": 0, "explanation": "Single equals assigns values."},
        {"question": "Which of these is a valid Python variable name?", "options": ["user_name", "2name", "user-name", "class"], "correct": 0, "explanation": "Variable names can include underscore and cannot start with a digit."},
        {"question": "Which type represents True/False values?", "options": ["bool", "int", "str", "float"], "correct": 0, "explanation": "bool stores logical truth values."},
        {"question": "Which built-in converts text to integer?", "options": ["int()", "str()", "float()", "bool()"], "correct": 0, "explanation": "int() parses compatible numeric strings."},
    ],
}

_TRUE_FALSE_TEMPLATES = {
    "loops": [
        {"question": "A 'for' loop in Python can iterate over strings.", "correctAnswer": "true", "explanation": "Strings are iterable in Python, so for loops can iterate character by character."},
        {"question": "The 'break' statement skips to the next iteration of a loop.", "correctAnswer": "false", "explanation": "break exits the loop entirely. 'continue' skips to the next iteration."},
        {"question": "range(5) generates numbers from 1 to 5.", "correctAnswer": "false", "explanation": "range(5) generates 0, 1, 2, 3, 4 — starting from 0 and excluding 5."},
        {"question": "A while loop runs as long as its condition is True.", "correctAnswer": "true", "explanation": "While loops check the condition before each iteration and continue while it's True."},
        {"question": "You can nest a for loop inside another for loop in Python.", "correctAnswer": "true", "explanation": "Python supports nested loops of any depth."},
    ],
    "lists": [
        {"question": "Lists in Python are immutable.", "correctAnswer": "false", "explanation": "Lists are mutable — you can change, add, and remove elements after creation."},
        {"question": "The append() method adds an element to the end of a list.", "correctAnswer": "true", "explanation": "append() adds a single element to the list's tail."},
        {"question": "List indices in Python start from 1.", "correctAnswer": "false", "explanation": "Python uses zero-based indexing, so the first element is at index 0."},
        {"question": "You can store different data types in the same Python list.", "correctAnswer": "true", "explanation": "Python lists can contain mixed types like integers, strings, and other lists."},
        {"question": "The len() function returns the last index of a list.", "correctAnswer": "false", "explanation": "len() returns the number of elements. The last index is len(list) - 1."},
    ],
    "dictionaries": [
        {"question": "Dictionary keys in Python must be unique.", "correctAnswer": "true", "explanation": "Each key in a dictionary must be unique. Duplicate keys overwrite previous values."},
        {"question": "Dictionaries maintain insertion order in Python 3.7+.", "correctAnswer": "true", "explanation": "Since Python 3.7, dictionaries are guaranteed to maintain insertion order."},
        {"question": "You can use a list as a dictionary key.", "correctAnswer": "false", "explanation": "Dictionary keys must be hashable. Lists are mutable and not hashable."},
    ],
    "functions": [
        {"question": "A Python function can return multiple values.", "correctAnswer": "true", "explanation": "Python functions can return multiple values as a tuple using comma separation."},
        {"question": "Functions must always have at least one parameter.", "correctAnswer": "false", "explanation": "Functions can be defined with no parameters at all, e.g., def greet(): ..."},
        {"question": "The 'def' keyword is used to define a function in Python.", "correctAnswer": "true", "explanation": "def is the keyword that starts a function definition."},
    ],
    "Python basics": [
        {"question": "Python is a statically typed language.", "correctAnswer": "false", "explanation": "Python is dynamically typed — variable types are determined at runtime."},
        {"question": "Indentation is significant in Python.", "correctAnswer": "true", "explanation": "Python uses indentation to define code blocks instead of braces."},
        {"question": "The '#' symbol is used for single-line comments in Python.", "correctAnswer": "true", "explanation": "Lines starting with # are treated as comments and ignored by the interpreter."},
        {"question": "In Python, '==' checks assignment while '=' checks equality.", "correctAnswer": "false", "explanation": "It's the opposite: '=' is assignment and '==' is equality comparison."},
        {"question": "Python strings are immutable.", "correctAnswer": "true", "explanation": "Once created, string characters cannot be changed in place."},
    ],
}

_FILL_IN_BLANK_TEMPLATES = {
    "loops": [
        {"question": "Complete the code to print numbers 0 to 4:", "codeTemplate": "for i in _____(5):\n    print(i)", "correctAnswer": "range", "explanation": "range(5) generates numbers from 0 to 4."},
        {"question": "Complete the code to exit the loop when i equals 3:", "codeTemplate": "for i in range(10):\n    if i == 3:\n        _____", "correctAnswer": "break", "explanation": "break exits the loop immediately."},
        {"question": "Complete the code to skip even numbers:", "codeTemplate": "for i in range(10):\n    if i % 2 == 0:\n        _____\n    print(i)", "correctAnswer": "continue", "explanation": "continue skips the rest of the current iteration."},
    ],
    "lists": [
        {"question": "Complete the code to add 'apple' to the fruits list:", "codeTemplate": "fruits = ['banana', 'cherry']\nfruits._____(\"apple\")", "correctAnswer": "append", "explanation": "append() adds an element to the end of a list."},
        {"question": "Complete the code to get the number of items in the list:", "codeTemplate": "items = [1, 2, 3, 4, 5]\ncount = _____(items)", "correctAnswer": "len", "explanation": "len() returns the number of elements in a sequence."},
        {"question": "Complete the code to remove the element at index 2:", "codeTemplate": "nums = [10, 20, 30, 40]\nnums._____(2)", "correctAnswer": "pop", "explanation": "pop(index) removes and returns the element at the given index."},
    ],
    "dictionaries": [
        {"question": "Complete the code to safely get a value with a default:", "codeTemplate": "data = {'name': 'Alice'}\nage = data._____(\"age\", 0)", "correctAnswer": "get", "explanation": "dict.get(key, default) returns the default if key is not found."},
        {"question": "Complete the code to get all keys from the dictionary:", "codeTemplate": "info = {'a': 1, 'b': 2}\nall_keys = info._____()", "correctAnswer": "keys", "explanation": "dict.keys() returns a view of all dictionary keys."},
    ],
    "functions": [
        {"question": "Complete the function definition:", "codeTemplate": "_____ greet(name):\n    return f\"Hello, {name}!\"", "correctAnswer": "def", "explanation": "The 'def' keyword is used to define functions in Python."},
        {"question": "Complete the code to send a value back from the function:", "codeTemplate": "def add(a, b):\n    _____ a + b", "correctAnswer": "return", "explanation": "return sends a value back to the caller."},
    ],
    "Python basics": [
        {"question": "Complete the code to display 'Hello World':", "codeTemplate": "_____('Hello World')", "correctAnswer": "print", "explanation": "print() outputs text to the console."},
        {"question": "Complete the code to convert the string to an integer:", "codeTemplate": "num_str = '42'\nnum = _____(num_str)", "correctAnswer": "int", "explanation": "int() converts a string to an integer."},
        {"question": "Complete the code to get the data type of a variable:", "codeTemplate": "x = 3.14\nresult = _____(x)", "correctAnswer": "type", "explanation": "type() returns the data type of an object."},
    ],
}

_OUTPUT_PREDICTION_TEMPLATES = {
    "loops": [
        {"question": "What will this code print?", "codeSnippet": "for i in range(3):\n    print(i, end=' ')", "options": ["0 1 2 ", "1 2 3 ", "0 1 2 3 ", "1 2 3 4 "], "correct": 0, "explanation": "range(3) produces 0, 1, 2. end=' ' keeps output on the same line with spaces."},
        {"question": "What will this code print?", "codeSnippet": "x = 0\nwhile x < 3:\n    x += 1\nprint(x)", "options": ["3", "2", "0", "4"], "correct": 0, "explanation": "The loop increments x until it reaches 3, then the condition fails and x (now 3) is printed."},
        {"question": "What will this code print?", "codeSnippet": "for i in range(5):\n    if i == 2:\n        break\n    print(i, end=' ')", "options": ["0 1 ", "0 1 2 ", "0 1 2 3 4 ", "2 "], "correct": 0, "explanation": "The loop prints 0 and 1, then breaks when i equals 2."},
    ],
    "lists": [
        {"question": "What will this code print?", "codeSnippet": "nums = [10, 20, 30]\nprint(nums[-1])", "options": ["30", "10", "20", "-1"], "correct": 0, "explanation": "Negative index -1 refers to the last element of the list."},
        {"question": "What will this code print?", "codeSnippet": "a = [1, 2, 3]\na.append(4)\nprint(len(a))", "options": ["4", "3", "5", "Error"], "correct": 0, "explanation": "After appending 4, the list has 4 elements."},
        {"question": "What will this code print?", "codeSnippet": "items = [1, 2, 3, 4, 5]\nprint(items[1:3])", "options": ["[2, 3]", "[1, 2, 3]", "[2, 3, 4]", "[1, 2]"], "correct": 0, "explanation": "Slice [1:3] includes indices 1 and 2 (elements 2 and 3)."},
    ],
    "dictionaries": [
        {"question": "What will this code print?", "codeSnippet": "d = {'a': 1, 'b': 2}\nprint(d.get('c', 0))", "options": ["0", "None", "Error", "c"], "correct": 0, "explanation": "get() returns the default value (0) when key 'c' is not found."},
        {"question": "What will this code print?", "codeSnippet": "d = {'x': 10, 'y': 20}\nprint(len(d))", "options": ["2", "30", "1", "Error"], "correct": 0, "explanation": "len() on a dictionary returns the number of key-value pairs."},
    ],
    "functions": [
        {"question": "What will this code print?", "codeSnippet": "def double(n):\n    return n * 2\n\nprint(double(5))", "options": ["10", "5", "25", "55"], "correct": 0, "explanation": "double(5) returns 5 * 2 = 10."},
        {"question": "What will this code print?", "codeSnippet": "def greet():\n    pass\n\nresult = greet()\nprint(result)", "options": ["None", "Error", "pass", "''"], "correct": 0, "explanation": "A function with only pass returns None implicitly."},
    ],
    "Python basics": [
        {"question": "What will this code print?", "codeSnippet": "x = 5\ny = 2\nprint(x // y)", "options": ["2", "2.5", "3", "1"], "correct": 0, "explanation": "// is integer (floor) division. 5 // 2 = 2."},
        {"question": "What will this code print?", "codeSnippet": "name = 'Python'\nprint(name[0])", "options": ["P", "Python", "p", "Error"], "correct": 0, "explanation": "String indexing at 0 returns the first character 'P'."},
        {"question": "What will this code print?", "codeSnippet": "print(type(3.14).__name__)", "options": ["float", "int", "str", "number"], "correct": 0, "explanation": "3.14 is a float literal, so type().__name__ returns 'float'."},
    ],
}


# ---------------------------------------------------------------------------
# Topic detection
# ---------------------------------------------------------------------------

def _detect_topic(transcript_text: str) -> str:
    """Detect quiz topic from transcript text."""
    lowered = transcript_text.lower()
    if "loop" in lowered:
        return "loops"
    if "list" in lowered:
        return "lists"
    if "dictionary" in lowered or "dict" in lowered:
        return "dictionaries"
    if "function" in lowered:
        return "functions"
    return "Python basics"


# ---------------------------------------------------------------------------
# Question type selection based on difficulty
# ---------------------------------------------------------------------------

def _select_question_type(difficulty: int, questions_answered: int) -> str:
    """Select question type based on difficulty and progress.
    
    Progressive difficulty:
    - Level 1-2: Mostly MCQ and True/False (easier types)
    - Level 3: Mix of all types
    - Level 4-5: More fill-in-blank and output prediction (harder types)
    """
    if difficulty <= 2:
        # Beginner: 50% MCQ, 30% True/False, 10% Output Prediction, 10% Fill-in-blank
        weights = [0.50, 0.30, 0.10, 0.10]
    elif difficulty == 3:
        # Intermediate: equal mix
        weights = [0.25, 0.25, 0.25, 0.25]
    else:
        # Advanced: 20% MCQ, 10% True/False, 35% Fill-in-blank, 35% Output Prediction
        weights = [0.20, 0.10, 0.35, 0.35]

    return random.choices(QUESTION_TYPES, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Fallback question generators per type
# ---------------------------------------------------------------------------

def _create_fallback_mcq(topic: str, difficulty: int, used_set: set) -> dict:
    """Create a fallback multiple-choice question."""
    pool = _MCQ_TEMPLATES.get(topic, _MCQ_TEMPLATES["Python basics"])
    selected = None
    for candidate in pool:
        if normalize_question_text(candidate["question"]) not in used_set:
            selected = candidate
            break
    if selected is None:
        selected = pool[(max(1, difficulty) - 1) % len(pool)]

    return {
        "type": "multiple_choice",
        "difficulty": difficulty,
        "question": selected["question"],
        "options": selected["options"],
        "correctAnswer": selected["correct"],
        "explanation": selected["explanation"],
    }


def _create_fallback_true_false(topic: str, difficulty: int, used_set: set) -> dict:
    """Create a fallback true/false question."""
    pool = _TRUE_FALSE_TEMPLATES.get(topic, _TRUE_FALSE_TEMPLATES["Python basics"])
    selected = None
    for candidate in pool:
        if normalize_question_text(candidate["question"]) not in used_set:
            selected = candidate
            break
    if selected is None:
        selected = pool[(max(1, difficulty) - 1) % len(pool)]

    return {
        "type": "true_false",
        "difficulty": difficulty,
        "question": selected["question"],
        "options": ["True", "False"],
        "correctAnswer": selected["correctAnswer"],
        "explanation": selected["explanation"],
    }


def _create_fallback_fill_in_blank(topic: str, difficulty: int, used_set: set) -> dict:
    """Create a fallback fill-in-the-blank question."""
    pool = _FILL_IN_BLANK_TEMPLATES.get(topic, _FILL_IN_BLANK_TEMPLATES["Python basics"])
    selected = None
    for candidate in pool:
        if normalize_question_text(candidate["question"]) not in used_set:
            selected = candidate
            break
    if selected is None:
        selected = pool[(max(1, difficulty) - 1) % len(pool)]

    return {
        "type": "fill_in_blank",
        "difficulty": difficulty,
        "question": selected["question"],
        "options": [],
        "codeTemplate": selected["codeTemplate"],
        "correctAnswer": selected["correctAnswer"],
        "explanation": selected["explanation"],
    }


def _create_fallback_output_prediction(topic: str, difficulty: int, used_set: set) -> dict:
    """Create a fallback output prediction question."""
    pool = _OUTPUT_PREDICTION_TEMPLATES.get(topic, _OUTPUT_PREDICTION_TEMPLATES["Python basics"])
    selected = None
    for candidate in pool:
        if normalize_question_text(candidate["question"]) not in used_set:
            selected = candidate
            break
    if selected is None:
        selected = pool[(max(1, difficulty) - 1) % len(pool)]

    return {
        "type": "output_prediction",
        "difficulty": difficulty,
        "question": selected["question"],
        "options": selected["options"],
        "codeSnippet": selected["codeSnippet"],
        "correctAnswer": selected["correct"],
        "explanation": selected["explanation"],
    }


def create_fallback_question(transcript_text: str, difficulty: int,
                             used_questions: list[str] | None = None,
                             question_type: str | None = None) -> dict:
    """Create a deterministic non-repeating fallback question of the specified type."""
    used_set = {normalize_question_text(q) for q in (used_questions or [])}
    topic = _detect_topic(transcript_text)

    if question_type is None:
        question_type = _select_question_type(difficulty, len(used_questions or []))

    if question_type == "true_false":
        return _create_fallback_true_false(topic, difficulty, used_set)
    elif question_type == "fill_in_blank":
        return _create_fallback_fill_in_blank(topic, difficulty, used_set)
    elif question_type == "output_prediction":
        return _create_fallback_output_prediction(topic, difficulty, used_set)
    else:
        return _create_fallback_mcq(topic, difficulty, used_set)


# ---------------------------------------------------------------------------
# Gemini-powered question generator
# ---------------------------------------------------------------------------

def generate_quiz_question(transcript_text: str, difficulty: int,
                           used_questions: list[str] | None = None) -> dict:
    """Generate one quiz question from transcript text using Gemini with fallback.
    Supports multiple question types with progressive difficulty."""
    try:
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key or not QUIZ_USE_GEMINI:
            return create_fallback_question(transcript_text, difficulty, used_questions)

        used_questions = used_questions or []
        used_block = "\n".join(f"- {q}" for q in used_questions[:30])

        # Select question type based on difficulty
        question_type = _select_question_type(difficulty, len(used_questions))

        model = genai.GenerativeModel("gemini-2.5-flash")

        # Build type-specific prompt
        if question_type == "true_false":
            type_instructions = """Create a TRUE/FALSE question.
Return STRICT JSON only in this exact shape:
{
  "type": "true_false",
  "difficulty": DIFFICULTY,
  "question": "A statement that is either true or false about Python",
  "options": ["True", "False"],
  "correctAnswer": "true" or "false",
  "explanation": "Why this statement is true or false"
}"""
        elif question_type == "fill_in_blank":
            type_instructions = """Create a FILL-IN-THE-BLANK question where the student must type the missing Python keyword or function name.
Return STRICT JSON only in this exact shape:
{
  "type": "fill_in_blank",
  "difficulty": DIFFICULTY,
  "question": "Description of what to complete",
  "options": [],
  "codeTemplate": "Python code with _____ marking the blank",
  "correctAnswer": "the_missing_word",
  "explanation": "Why this is the correct answer"
}
Rules for fill_in_blank:
- Use _____ (5 underscores) to mark the blank
- The answer should be a single word or short phrase
- The code template should be valid Python when the blank is filled"""
        elif question_type == "output_prediction":
            type_instructions = """Create an OUTPUT PREDICTION question where the student must predict what a code snippet prints.
Return STRICT JSON only in this exact shape:
{
  "type": "output_prediction",
  "difficulty": DIFFICULTY,
  "question": "What will this code print?",
  "options": ["option1", "option2", "option3", "option4"],
  "codeSnippet": "the Python code to analyze",
  "correctAnswer": 0,
  "explanation": "Step-by-step explanation of the output"
}
Rules for output_prediction:
- Exactly 4 options
- correctAnswer is the index (0-3) of the correct option
- The code snippet should be 2-5 lines
- Make the output deterministic (no random, no input)"""
        else:
            type_instructions = """Create a MULTIPLE CHOICE question.
Return STRICT JSON only in this exact shape:
{
  "type": "multiple_choice",
  "difficulty": DIFFICULTY,
  "question": "...",
  "options": ["...", "...", "...", "..."],
  "correctAnswer": 0,
  "explanation": "..."
}
Rules:
- Exactly 4 options
- One correct answer index from 0 to 3"""

        prompt = f"""You are creating one quiz question for a Python learner.

Transcript context:
{transcript_text[:5000]}

Create a single question at difficulty {difficulty} (1 beginner to 5 advanced).

{type_instructions.replace('DIFFICULTY', str(difficulty))}

General rules:
- Keep question grounded in transcript context and Python
- DO NOT repeat any of these previous questions:
{used_block if used_block else '- (none)'}
"""

        def _generate_text() -> str:
            response = model.generate_content(prompt)
            return response.text.strip()

        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_generate_text)
        try:
            text = future.result(timeout=QUIZ_GEMINI_TIMEOUT_SECONDS)
        except FutureTimeoutError:
            logger.warning("Quiz generation timed out, using fallback question")
            future.cancel()
            return create_fallback_question(transcript_text, difficulty, used_questions, question_type)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]).strip()

        parsed = json.loads(text)

        # Validate based on question type
        parsed_type = parsed.get("type", question_type)

        new_question_text = str(parsed.get("question", "")).strip()
        if normalize_question_text(new_question_text) in {normalize_question_text(q) for q in used_questions}:
            logger.warning("Generated duplicate quiz question, switching to fallback")
            return create_fallback_question(transcript_text, difficulty, used_questions, question_type)

        if parsed_type == "true_false":
            correct = str(parsed.get("correctAnswer", "true")).lower()
            if correct not in ("true", "false"):
                correct = "true"
            return {
                "type": "true_false",
                "difficulty": int(parsed.get("difficulty", difficulty)),
                "question": new_question_text or "Is this statement true or false?",
                "options": ["True", "False"],
                "correctAnswer": correct,
                "explanation": str(parsed.get("explanation", "")),
            }

        elif parsed_type == "fill_in_blank":
            return {
                "type": "fill_in_blank",
                "difficulty": int(parsed.get("difficulty", difficulty)),
                "question": new_question_text or "Fill in the blank:",
                "options": [],
                "codeTemplate": str(parsed.get("codeTemplate", "")),
                "correctAnswer": str(parsed.get("correctAnswer", "")),
                "explanation": str(parsed.get("explanation", "")),
            }

        elif parsed_type == "output_prediction":
            if not isinstance(parsed.get("options"), list) or len(parsed["options"]) != 4:
                return create_fallback_question(transcript_text, difficulty, used_questions, "output_prediction")
            answer_index = int(parsed.get("correctAnswer", 0))
            if answer_index < 0 or answer_index > 3:
                answer_index = 0
            return {
                "type": "output_prediction",
                "difficulty": int(parsed.get("difficulty", difficulty)),
                "question": new_question_text or "What will this code print?",
                "options": [str(o) for o in parsed["options"]],
                "codeSnippet": str(parsed.get("codeSnippet", "")),
                "correctAnswer": answer_index,
                "explanation": str(parsed.get("explanation", "")),
            }

        else:
            # multiple_choice
            if not isinstance(parsed.get("options"), list) or len(parsed["options"]) != 4:
                return create_fallback_question(transcript_text, difficulty, used_questions, "multiple_choice")
            answer_index = int(parsed.get("correctAnswer", 0))
            if answer_index < 0 or answer_index > 3:
                answer_index = 0
            return {
                "type": "multiple_choice",
                "difficulty": int(parsed.get("difficulty", difficulty)),
                "question": new_question_text or "Choose the correct answer.",
                "options": [str(o) for o in parsed["options"]],
                "correctAnswer": answer_index,
                "explanation": str(parsed.get("explanation", "")),
            }

    except Exception as e:
        logger.warning(f"Quiz question generation fallback used: {e}")
        return create_fallback_question(transcript_text, difficulty, used_questions)


# ---------------------------------------------------------------------------
# Difficulty calculator (progressive, performance-based)
# ---------------------------------------------------------------------------

def calculate_next_level(current_level: int, questions_answered: int, correct_answers: int) -> int:
    """Calculate next difficulty level based on performance.
    
    Progressive difficulty logic:
    - If accuracy >= 80%: increase level
    - If accuracy >= 50%: maintain level
    - If accuracy < 50%: decrease level (but never below 1)
    - After first question, always go to at least level 2 if correct
    """
    if questions_answered == 0:
        return current_level

    accuracy = correct_answers / questions_answered

    if questions_answered == 1:
        # After first question: go up if correct, stay if wrong
        return min(5, current_level + 1) if accuracy >= 1.0 else current_level

    if accuracy >= 0.80:
        return min(5, current_level + 1)
    elif accuracy >= 0.50:
        return current_level
    else:
        return max(1, current_level - 1)
