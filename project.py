
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


def password_report(password):
    """Evaluate basic password characteristics without storing the password."""
    score = 0
    suggestions = []

    if len(password) >= 12:
        score += 1
    else:
        suggestions.append("Use at least 12 characters.")

    if len(password) >= 16:
        score += 1

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Consider including numbers.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Consider including symbols.")

    common_passwords = {
        "password", "password123", "12345678",
        "qwerty123", "admin123"
    }

    if password.lower() in common_passwords:
        score = 0
        suggestions.append("Avoid common passwords.")

    if score <= 2:
        level = "Weak"
    elif score <= 4:
        level = "Moderate"
    else:
        level = "Strong"

    return {
        "score": score,
        "level": level,
        "suggestions": suggestions,
    }


def analyze_url(url):
    """Flag common URL warning signs. This is not a malware detector."""
    url = url.strip()
    findings = []

    if not url:
        return {
            "risk_level": "Invalid",
            "findings": ["No URL was provided."],
        }

    # Permit users to enter example.com without typing a scheme.
    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname

        # Accessing .port can raise ValueError for malformed ports.
        port = parsed.port
    except ValueError:
        return {
            "risk_level": "Invalid",
            "findings": ["The URL contains an invalid address or port."],
        }

    if parsed.scheme.lower() not in {"http", "https"}:
        findings.append("The URL uses an unusual or unsafe scheme.")

    if not host:
        return {
            "risk_level": "Invalid",
            "findings": ["A valid hostname could not be found."],
        }

    if parsed.username is not None or parsed.password is not None:
        findings.append("The URL contains credentials before the hostname.")

    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd",
        "shorturl.at", "ow.ly"
    }

    if host.lower() in shorteners:
        findings.append("The URL uses a link-shortening service.")

    try:
        ipaddress.ip_address(host)
        findings.append("The hostname is an IP address instead of a domain.")
    except ValueError:
        pass

    if "xn--" in host.lower():
        findings.append("The hostname contains an internationalized domain label.")

    if parsed.scheme.lower() == "http":
        findings.append("The connection does not use HTTPS.")

    if port is not None and port not in {80, 443}:
        findings.append("The URL uses a nonstandard web port.")

    suspicious_terms = {
        "login", "verify", "account", "secure",
        "update", "password", "confirm"
    }
    combined = (host + parsed.path).lower()
    found_terms = sorted(
        term for term in suspicious_terms
        if term in combined
    )

    if found_terms:
        findings.append(
            "The URL contains potentially sensitive keywords: "
            + ", ".join(found_terms)
            + "."
        )

    if not findings:
        findings.append("No warning signs from this basic check were detected.")

    warning_count = sum(
        finding != "No warning signs from this basic check were detected."
        for finding in findings
    )

    if warning_count >= 3:
        level = "High"
    elif warning_count >= 1:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_level": level,
        "findings": findings,
    }


def analyze_message(message):
    """Identify common phishing-like phrases in user-provided text."""
    text = message.lower()
    indicators = [
        "urgent",
        "immediately",
        "account suspended",
        "verify your account",
        "confirm your account",
        "click here",
        "click the link",
        "enter your password",
        "send your password",
        "gift card",
        "social security number",
    ]

    found = [phrase for phrase in indicators if phrase in text]

    if len(found) >= 3:
        level = "High"
    elif len(found) >= 1:
        level = "Medium"
    else:
        level = "Low"

    if found:
        findings = [
            "Potential warning phrases found: " + ", ".join(found) + "."
        ]
    else:
        findings = [
            "No phrases from this basic warning list were found."
        ]

    return {
        "risk_level": level,
        "findings": findings,
    }


def save_history(scan_type, risk_level, findings,
                 filename="cyberguard_history.json"):
    """Save a scan summary, not the original password or message."""
    path = Path(filename)

    record = {
        "timestamp": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "scan_type": scan_type,
        "risk_level": risk_level,
        "findings": findings,
    }

    if path.exists():
        with path.open("r", encoding="utf-8") as file:
            history = json.load(file)
        if not isinstance(history, list):
            raise ValueError("History file must contain a JSON list.")
    else:
        history = []

    history.append(record)

    with path.open("w", encoding="utf-8") as file:
        json.dump(history, file, indent=2)

    return len(history)


def main():
    print("\n=== CyberGuard Security Toolkit ===")

    while True:
        print("\n1. Password strength checker")
        print("2. Suspicious URL analyzer")
        print("3. Message warning checker")
        print("4. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            password = input("Enter a password to evaluate: ")
            result = password_report(password)

            print(f"\nStrength: {result['level']}")
            print(f"Score: {result['score']}/6")

            for suggestion in result["suggestions"]:
                print(f"- {suggestion}")

            print("The password itself is not saved.")

            save_history(
                "password",
                result["level"],
                result["suggestions"],
            )

        elif choice == "2":
            url = input("Enter a URL: ")
            result = analyze_url(url)

            print(f"\nWarning level: {result['risk_level']}")
            for finding in result["findings"]:
                print(f"- {finding}")

            save_history(
                "url",
                result["risk_level"],
                result["findings"],
            )

        elif choice == "3":
            message = input("Paste the message to check: ")
            result = analyze_message(message)

            print(f"\nWarning level: {result['risk_level']}")
            for finding in result["findings"]:
                print(f"- {finding}")

            save_history(
                "message",
                result["risk_level"],
                result["findings"],
            )

        elif choice == "4":
            print("Thank you for using CyberGuard!")
            break

        else:
            print("Invalid choice. Enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
