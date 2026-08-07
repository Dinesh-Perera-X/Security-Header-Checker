import argparse
import requests
import sys
import urllib3

# Suppress SSL warnings for self-signed or unverified certificates during testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Core Security Headers to Audit
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS).",
    "Content-Security-Policy": "Prevents XSS, data injection, and malicious scripts.",
    "X-Frame-Options": "Protects against Clickjacking attacks.",
    "X-Content-Type-Options": "Prevents MIME-sniffing vulnerabilities.",
    "Referrer-Policy": "Controls how much referrer info is sent with requests.",
    "Permissions-Policy": "Restricts browser features (camera, microphone, geolocation)."
}

def format_url(url):
    """
    Ensures the URL includes an explicit HTTP or HTTPS scheme.
    """
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url

def audit_headers(target_url):
    """
    Fetches HTTP response headers and compares them against standard security headers.
    """
    formatted_url = format_url(target_url)
    print("=" * 70)
    print(f"[*] Auditing Target : {formatted_url}")
    print("=" * 70)

    try:
        response = requests.get(
            formatted_url,
            timeout=10,
            verify=False,
            allow_redirects=True
        )
        headers = response.headers

        present_count = 0
        missing_count = 0

        print(f"\n[+] HTTP Status Code : {response.status_code}\n")

        for header, description in SECURITY_HEADERS.items():
            # Dictionary lookup in requests.headers is case-insensitive
            if header in headers:
                present_count += 1
                value = headers[header]
                display_val = (value[:50] + "...") if len(value) > 50 else value
                print(f"[✓] PRESENT : {header}")
                print(f"    └─ Value: {display_val}")
            else:
                missing_count += 1
                print(f"[✗] MISSING : {header}")
                print(f"    └─ Purpose: {description}")

        print("\n" + "=" * 70)
        print(f"[*] Summary: {present_count} Present | {missing_count} Missing")
        print("=" * 70)

    except requests.exceptions.RequestException as e:
        print(f"[!] Network Error connecting to {formatted_url}: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Web Security Header Checker - Day 1 Core Audit"
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL or domain (e.g., example.com or https://example.com)"
    )
    args = parser.parse_args()

    audit_headers(args.url)

if __name__ == "__main__":
    main()
