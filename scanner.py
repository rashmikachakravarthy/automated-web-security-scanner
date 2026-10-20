"""
Automated Website Security Header and Basic CORS Checker
Educational project for authorized, non-invasive testing only.

This tool checks selected HTTP response headers and makes one basic OPTIONS
request to observe CORS-related response headers. It is not a vulnerability
scanner and does not prove that a website is secure or insecure.
"""

import urllib.error
import urllib.request
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps restrict allowed content sources.",
    "Strict-Transport-Security": "Tells browsers to prefer HTTPS.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Can help reduce clickjacking risks.",
    "Referrer-Policy": "Controls referrer information shared by browsers.",
}


def request_url(url, method="GET", extra_headers=None):
    """Send a simple HTTP request and return the response, including HTTP errors."""
    headers = {"User-Agent": "Student-WebSecurityScanner/1.0"}
    if extra_headers:
        headers.update(extra_headers)

    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        return urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as error:
        # HTTP error responses may still contain useful headers.
        return error


def normalize_url(raw_url):
    """Validate the URL scheme and host; add HTTPS when no scheme is provided."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL cannot be empty.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid URL, such as https://example.com.")
    return raw_url


def scan_website(url):
    """Check selected security headers and make a basic CORS OPTIONS request."""
    print("\n" + "=" * 60)
    print(" AUTOMATED WEBSITE SECURITY HEADER & CORS CHECKER")
    print("=" * 60)
    print("Target:", url)

    try:
        response = request_url(url)
        headers = response.headers
        print("HTTP status:", getattr(response, "status", "unknown"))

        print("\n--- SECURITY HEADER CHECK ---")
        for header, purpose in SECURITY_HEADERS.items():
            value = headers.get(header)
            if value:
                print(f"[PRESENT] {header}: {value}")
            else:
                print(f"[MISSING] {header}")
                print(f"          Purpose: {purpose}")

        print("\n--- BASIC CORS CHECK ---")
        print("Sending a single OPTIONS request with a test Origin...")
        cors_response = request_url(
            url,
            method="OPTIONS",
            extra_headers={
                "Origin": "https://scanner-test.invalid",
                "Access-Control-Request-Method": "GET",
            },
        )

        cors_headers = cors_response.headers
        allow_origin = cors_headers.get("Access-Control-Allow-Origin")
        allow_credentials = cors_headers.get(
            "Access-Control-Allow-Credentials", ""
        ).lower()

        if allow_origin == "*":
            print("[REVIEW] Access-Control-Allow-Origin is '*'.")
            if allow_credentials == "true":
                print("[WARNING] Wildcard origin and credentials were both "
                      "returned; review this configuration carefully.")
            else:
                print("A wildcard is not automatically a vulnerability; "
                      "review the endpoint and data sensitivity.")
        elif allow_origin == "https://scanner-test.invalid":
            print("[REVIEW] The test Origin was reflected/allowed.")
            print("Confirm whether this origin should be trusted.")
        elif allow_origin:
            print("[INFO] Access-Control-Allow-Origin:", allow_origin)
            print("The test Origin was not explicitly reflected.")
        else:
            print("[INFO] No Access-Control-Allow-Origin header was observed.")
            print("This result is inconclusive; CORS behavior may vary by route.")

        print("\nScan completed.")
        print("LIMITATION: This is a basic check, not a full security assessment.")

    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print("\nCould not complete the scan:", error)
        print("Check the URL and your internet connection.")
    except Exception as error:
        print("\nUnexpected error:", error)


def main():
    print("Use only on websites you own or are explicitly authorized to test.")
    raw_url = input("Enter a website URL (e.g. https://example.com): ")
    try:
        url = normalize_url(raw_url)
    except ValueError as error:
        print("Input error:", error)
        return
    scan_website(url)


if __name__ == "__main__":
    main()
