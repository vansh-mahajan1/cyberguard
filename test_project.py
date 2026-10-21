
import json

import pytest

from project import (
    password_report,
    analyze_url,
    analyze_message,
    save_history,
)


def test_password_report():
    result = password_report("abc")
    assert result["level"] == "Weak"
    assert result["score"] <= 2
    assert result["suggestions"]

    result = password_report("Strong!Password9x")
    assert result["level"] == "Strong"
    assert result["score"] == 6


def test_common_password():
    result = password_report("password123")
    assert result["level"] == "Weak"
    assert "Avoid common passwords." in result["suggestions"]


def test_analyze_url():
    result = analyze_url("https://example.com")
    assert result["risk_level"] == "Low"
    assert "No warning signs from this basic check were detected." in result["findings"]


def test_suspicious_url():
    result = analyze_url("http://192.0.2.1/login")
    assert result["risk_level"] == "High"
    assert len(result["findings"]) >= 3


def test_invalid_url():
    result = analyze_url("")
    assert result["risk_level"] == "Invalid"


def test_analyze_message():
    result = analyze_message("Hello, how are you?")
    assert result["risk_level"] == "Low"

    result = analyze_message(
        "URGENT! Your account suspended. "
        "Click here and enter your password immediately."
    )
    assert result["risk_level"] == "High"


def test_save_history(tmp_path):
    history_file = tmp_path / "history.json"

    count = save_history(
        "url",
        "Medium",
        ["The URL uses a link-shortening service."],
        filename=str(history_file),
    )

    assert count == 1

    with history_file.open(encoding="utf-8") as file:
        history = json.load(file)

    assert len(history) == 1
    assert history[0]["scan_type"] == "url"
    assert history[0]["risk_level"] == "Medium"


def test_save_history_appends(tmp_path):
    history_file = tmp_path / "history.json"

    save_history("url", "Low", ["No warnings."], str(history_file))
    count = save_history(
        "message", "High", ["Suspicious phrases."], str(history_file)
    )

    assert count == 2

    with history_file.open(encoding="utf-8") as file:
        history = json.load(file)

    assert len(history) == 2
    assert history[1]["scan_type"] == "message"
