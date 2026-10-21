# CyberGuard — A Python-Based Cybersecurity Toolkit

#### Video Demo: https://youtu.be/SfmTRtEgdhU

#### Description:

CyberGuard is a beginner-friendly Python cybersecurity toolkit created
as my final project for Harvard's CS50P: Introduction to Programming
with Python. The purpose of this project is to demonstrate fundamental
Python programming skills through a practical security-related application.

CyberGuard runs in a terminal and provides three analysis tools:
a password strength checker, a suspicious URL analyzer, and a message
warning checker. It also maintains a local history of analysis results.

| | |
|---|---|
| **Author** | Vansh Mahajan |
| **Location** | Delhi, India |
| **edX username** | vanshmahajan1601 |
| **GitHub** | [vansh-mahajan1](https://github.com/vansh-mahajan1) |
| **Course** | CS50P — Introduction to Programming with Python |
| **Demo video** | [Watch on YouTube](https://youtu.be/SfmTRtEgdhU) |

---

## Quick Start

CyberGuard uses only Python's standard library. `pytest` is needed only to run the tests.

```bash
git clone https://github.com/vansh-mahajan1/cyberguard.git
cd cyberguard
pip install -r requirements.txt
python project.py
```

Run the test suite:

```bash
pytest -v test_project.py
```

## Example Session

```text
=== CyberGuard Security Toolkit ===

1. Password strength checker
2. Suspicious URL analyzer
3. Message warning checker
4. Exit
Choose an option: 1
Enter a password to evaluate: hello

Strength: Weak
Score: 1/6
- Use at least 12 characters.
- Add uppercase letters.
- Consider including numbers.
- Consider including symbols.
The password itself is not saved.

Choose an option: 2
Enter a URL: http://192.0.2.1/login

Warning level: High
- The hostname is an IP address instead of a domain.
- The connection does not use HTTPS.
- The URL contains potentially sensitive keywords: login.

Choose an option: 3
Paste the message to check: URGENT! Your account suspended. Click here and enter your password immediately.

Warning level: High
- Potential warning phrases found: urgent, immediately, account suspended, click here, enter your password.
```

*(The menu repeats between scans; it is shown once here for brevity.)*

## Password Strength Checker

The password checker evaluates basic password characteristics,
including length, lowercase letters, uppercase letters, digits,
and special characters. It assigns a score out of 6 and a strength
category (Weak, Moderate, or Strong), and it gives suggestions for improvement.
Passwords that appear in a small list of very common passwords
receive a score of 0.

The checker uses regular expressions to identify different character
types. It is an educational heuristic and does not guarantee that
a password is secure. The original password is not saved in history.

## Suspicious URL Analyzer

The URL analyzer examines an address for common warning signs.
These include the use of link-shortening services, IP-address
hostnames, unusual URL schemes, credentials embedded in a URL,
internationalized (punycode) domain labels, HTTP instead of HTTPS,
nonstandard ports, and potentially sensitive keywords.

The analyzer uses Python's `urllib.parse` module to parse URLs and
`ipaddress` to identify IP-address hostnames. It does not visit URLs,
download files, or verify whether a website is malicious.
It reports a Low, Medium, or High warning level depending on how many
warning signs it finds, or Invalid if the URL cannot be parsed.

## Message Warning Checker

The message checker looks for phrases frequently associated with
phishing attempts, such as urgent account threats, requests for
passwords, and instructions to click links. It assigns a warning
level according to the number of indicators detected.

This approach is intentionally simple. Legitimate messages may
contain these phrases, and malicious messages may not. The results
should therefore be treated as indicators rather than definitive
classifications.

## Scan History

CyberGuard stores summaries of previous analyses in a JSON file
(`cyberguard_history.json`, created on first use).
Each record includes a timestamp, analysis type, warning level,
and findings. JSON provides a convenient structured format that
Python can read and write using its standard library.

The history is designed to avoid storing the original password or
message text. Users should still treat the history file as potentially
sensitive because it may contain information about analyzed URLs
and security findings. For that reason, it is excluded from version
control by `.gitignore`.

## Files

- `project.py` contains the main menu and all analysis and history functions:
  `password_report`, `analyze_url`, `analyze_message`, and `save_history`.
- `test_project.py` contains automated tests for the custom functions.
- `requirements.txt` lists pytest, which is used to run the tests.
- `README.md` documents the project and its design.

## Design Decisions and Testing

I chose a terminal interface because it keeps the application
lightweight and allows the main programming logic to remain the focus.
The project uses Python's standard library for regular expressions,
URL parsing, IP-address validation, timestamps, file handling, and
JSON storage.

The application separates each analysis task into its own function.
This improves readability and makes it possible to test individual
features independently. Eight pytest tests cover normal inputs, warning
conditions, invalid inputs, and history-file operations. The history
tests use pytest's `tmp_path` fixture so that they never modify the
real history file.

## Disclaimer

CyberGuard is an educational project, not a replacement for professional
security tools. It performs basic local checks and does not guarantee
that a password, URL, or message is safe.

## License

Released under the [MIT License](LICENSE).
