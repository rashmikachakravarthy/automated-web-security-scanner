# Automated Website Security Header and Basic CORS Checker

A beginner-friendly Python project that checks selected HTTP security headers and observes basic CORS-related response headers.

## Features
- Accepts a website URL (adds `https://` if no scheme is supplied).
- Checks five response headers:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
- Sends one basic `OPTIONS` request to observe CORS response headers.
- Prints results and handles common connection/input errors.

## Requirements
- Python 3.9 or newer recommended.
- Internet connection for testing public sites.
- No third-party Python packages are required.

## Run on Windows
1. Install Python from https://www.python.org/downloads/ if needed. During installation, enable **Add Python to PATH**.
2. Open Command Prompt in this project folder.
3. Run:

   ```bash
   python scanner.py
   ```

   If `python` is not recognized, try `py scanner.py`.
4. Enter a URL, for example `https://example.com`.

## Run on macOS/Linux
```bash
python3 scanner.py
```

## Example
The exact output depends on the target server. The program displays an HTTP status, each header as PRESENT or MISSING, and a basic CORS observation. A missing header is not, by itself, proof of a vulnerability.

## Project structure
```text
automated_web_security_scanner/
├── scanner.py
├── requirements.txt
├── README.md
└── PROJECT_REPORT.docx
```

## Limitations
- This is an educational checker, not a complete vulnerability assessment.
- It does not crawl a site, authenticate, test business logic, or verify exploitability.
- CORS can vary by route, request method, and request headers; this single test may be inconclusive.
- Header recommendations depend on application design and deployment.
- Do not scan websites unless you own them or have explicit permission.

## Author
Student project — edit this section to add your name, institution, and bootcamp details before submission.
