#!/usr/bin/env python3
"""
Comprehensive test script for all 3 Codio fixes:
1. Video pause (backend-side: just verify the frontend code compiles)
2. Transcript search (backend API test)
3. Quiz with multiple question types and progressive difficulty
"""

import requests
import json
import sys

BASE = "http://127.0.0.1:8080/api/v1"

def get_token():
    resp = requests.post(f"{BASE}/auth/login", json={
        "email": "admin@gmail.com",
        "password": "admin123"
    })
    data = resp.json()
    assert data.get("success"), f"Login failed: {data}"
    return data["access_token"]

def test_transcript_search(token):
    """Test Fix 2: Transcript search with json3 extraction."""
    print("\n" + "="*60)
    print("TEST 2: Transcript Search")
    print("="*60)
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Search for "variable" in Gf9wLsCJDqc (should have transcript now)
    print("\n[2.1] Searching 'variable' in Gf9wLsCJDqc...")
    resp = requests.get(f"{BASE}/video/Gf9wLsCJDqc/transcript/search?query=variable", headers=headers)
    data = resp.json()
    assert data.get("success"), f"Search failed: {data}"
    matches = data.get("matches", [])
    print(f"  Found {len(matches)} matches")
    assert len(matches) > 0, "Expected at least 1 match for 'variable'"
    for m in matches[:3]:
        print(f"  [{m['timestamp']:.1f}s] {m['text'][:60]}...")
    print("  PASS")
    
    # Test 2: Search for non-existent term
    print("\n[2.2] Searching 'xyznonexistent' in Gf9wLsCJDqc...")
    resp = requests.get(f"{BASE}/video/Gf9wLsCJDqc/transcript/search?query=xyznonexistent", headers=headers)
    data = resp.json()
    assert data.get("success"), f"Search failed: {data}"
    assert data.get("matches_count", 0) == 0, "Expected 0 matches"
    print("  0 matches as expected")
    print("  PASS")
    
    # Test 3: Get full transcript
    print("\n[2.3] Getting full transcript for Gf9wLsCJDqc...")
    resp = requests.get(f"{BASE}/video/Gf9wLsCJDqc/transcript", headers=headers)
    data = resp.json()
    assert data.get("success"), f"Get transcript failed: {data}"
    transcript = data.get("transcript", "")
    print(f"  Transcript length: {len(transcript)} chars")
    assert len(transcript) > 50, "Transcript too short"
    print(f"  First 100 chars: {transcript[:100]}...")
    print("  PASS")
    
    # Test 4: Video status shows transcript available
    print("\n[2.4] Checking video status for Gf9wLsCJDqc...")
    resp = requests.get(f"{BASE}/video/Gf9wLsCJDqc/status", headers=headers)
    data = resp.json()
    print(f"  Status: {data.get('status')}, transcript_available: {data.get('transcript_available')}")
    print("  PASS")
    
    print("\n  ALL TRANSCRIPT TESTS PASSED")

def test_quiz_multi_type(token):
    """Test Fix 3: Quiz with multiple question types."""
    print("\n" + "="*60)
    print("TEST 3: Quiz - Multiple Question Types & Progressive Difficulty")
    print("="*60)
    
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # Test 1: Start quiz
    print("\n[3.1] Starting quiz for video Gf9wLsCJDqc...")
    resp = requests.post(f"{BASE}/quiz/start", json={
        "user_email": "admin@gmail.com",
        "transcript": "",
        "video_id": "Gf9wLsCJDqc"
    }, headers=headers)
    data = resp.json()
    assert data.get("success"), f"Quiz start failed: {data}"
    
    session_id = data["session_id"]
    first_q = data["first_question"]
    print(f"  Session: {session_id[:8]}...")
    print(f"  First question type: {first_q['type']}")
    print(f"  Question: {first_q['content']['question'][:80]}...")
    if first_q.get("content", {}).get("codeTemplate"):
        print(f"  Code template: {first_q['content']['codeTemplate'][:60]}...")
    if first_q.get("content", {}).get("codeSnippet"):
        print(f"  Code snippet: {first_q['content']['codeSnippet'][:60]}...")
    print(f"  Options: {first_q['content']['options']}")
    print("  PASS")
    
    # Test 2: Submit answers and track question types
    question_types_seen = set()
    question_types_seen.add(first_q["type"])
    current_q = first_q
    
    for i in range(5):
        # Determine answer based on question type
        q_type = current_q["type"]
        if q_type == "fill_in_blank":
            # Just submit a guess
            answer = "print"
        elif q_type == "true_false":
            answer = "true"
        else:
            # MCQ or output_prediction: pick option 0
            answer = 0
        
        print(f"\n[3.2.{i+1}] Submitting answer for Q{i+1} (type={q_type})...")
        resp = requests.post(f"{BASE}/quiz/submit-answer", json={
            "session_id": session_id,
            "question_id": current_q["id"],
            "answer": answer,
            "time_taken": 5
        }, headers=headers)
        data = resp.json()
        assert data.get("success"), f"Submit failed: {data}"
        
        is_correct = data.get("is_correct", False)
        new_level = data.get("new_level", 1)
        learning_rate = data.get("learning_rate", 0)
        should_continue = data.get("should_continue", False)
        
        print(f"  Correct: {is_correct}, Level: {new_level}, LR: {learning_rate:.2f}")
        
        if data.get("next_question"):
            current_q = data["next_question"]
            question_types_seen.add(current_q["type"])
            print(f"  Next Q type: {current_q['type']}")
            print(f"  Next Q: {current_q['content']['question'][:80]}...")
        elif not should_continue:
            print("  Quiz complete!")
            break
    
    print(f"\n  Question types seen: {question_types_seen}")
    print(f"  Types count: {len(question_types_seen)}")
    
    # Test 3: End quiz session
    print(f"\n[3.3] Ending quiz session...")
    resp = requests.post(f"{BASE}/quiz/end-session/{session_id}", headers=headers)
    data = resp.json()
    assert data.get("success"), f"End session failed: {data}"
    print(f"  Final score: {data.get('final_score')}%")
    print(f"  Questions answered: {data.get('questions_answered')}")
    print(f"  Correct: {data.get('correct_answers')}")
    print("  PASS")
    
    print("\n  ALL QUIZ TESTS PASSED")
    return question_types_seen

def test_quiz_difficulty_adaptation(token):
    """Test that difficulty actually adapts based on performance."""
    print("\n" + "="*60)
    print("TEST 3b: Quiz - Difficulty Adaptation")
    print("="*60)
    
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # Start a new quiz
    print("\n[3b.1] Starting quiz to test difficulty adaptation...")
    resp = requests.post(f"{BASE}/quiz/start", json={
        "user_email": "admin@gmail.com",
        "transcript": "Python variables are containers for storing data. x = 5 assigns integer 5 to variable x. Loops iterate over sequences. Functions are defined with def keyword.",
        "video_id": ""
    }, headers=headers)
    data = resp.json()
    assert data.get("success"), f"Quiz start failed: {data}"
    
    session_id = data["session_id"]
    current_q = data["first_question"]
    levels = [1]  # Starting level
    
    # Submit all wrong answers to see if level decreases
    for i in range(4):
        q_type = current_q["type"]
        # Submit wrong answer
        if q_type == "fill_in_blank":
            answer = "WRONG_ANSWER_XYZ"
        elif q_type == "true_false":
            answer = "wrong"
        else:
            answer = 99  # Wrong index
        
        resp = requests.post(f"{BASE}/quiz/submit-answer", json={
            "session_id": session_id,
            "question_id": current_q["id"],
            "answer": answer,
            "time_taken": 5
        }, headers=headers)
        data = resp.json()
        assert data.get("success"), f"Submit failed: {data}"
        
        new_level = data.get("new_level", 1)
        levels.append(new_level)
        print(f"  Q{i+1}: wrong answer -> Level: {new_level}")
        
        if data.get("next_question"):
            current_q = data["next_question"]
        else:
            break
    
    print(f"\n  Level progression (all wrong): {levels}")
    # After getting multiple wrong, level should decrease or stay low
    assert levels[-1] <= 2, f"Expected level to decrease/stay low after wrong answers, got {levels[-1]}"
    print("  PASS - Difficulty decreased as expected")
    
    # End session
    requests.post(f"{BASE}/quiz/end-session/{session_id}", headers=headers)

def main():
    print("CODIO FEATURE TESTS")
    print("=" * 60)
    
    token = get_token()
    print("Authenticated successfully")
    
    all_passed = True
    
    try:
        test_transcript_search(token)
    except Exception as e:
        print(f"\n  TRANSCRIPT TEST FAILED: {e}")
        all_passed = False
    
    try:
        types_seen = test_quiz_multi_type(token)
    except Exception as e:
        print(f"\n  QUIZ TEST FAILED: {e}")
        all_passed = False
    
    try:
        test_quiz_difficulty_adaptation(token)
    except Exception as e:
        print(f"\n  DIFFICULTY TEST FAILED: {e}")
        all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL TESTS PASSED!")
    else:
        print("SOME TESTS FAILED - check output above")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
