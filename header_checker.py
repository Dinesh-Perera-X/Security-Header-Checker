import argparse
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Core Security Headers and their maximum point weights
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"weight": 25, "desc": "Enforces HTTPS connections (HSTS)."},
    "Content-Security-Policy": {"weight": 25, "desc": "Prevents XSS and data injection attacks."},
    "X-Frame-Options": {"weight": 15, "desc": "Protects against Clickjacking attacks."},
    "X-Content-Type-Options": {"weight": 15, "desc": "Prevents MIME-sniffing vulnerabilities."},
    "Referrer-Policy": {"weight": 10, "desc": "Controls referrer information exposure."},
    "Permissions-Policy": {"weight": 10, "desc": "Restricts browser feature access."}
}

# Headers that reveal sensitive server implementation details
DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Runtime"
]

def format_url(url):
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url

def calculate_grade(score):
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"

def audit_headers(target_url):
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
        total_score = 0
        present_count = 0
        missing_count = 0

        print(f"\n[+] HTTP Status Code : {response.status_code}\n")
        print("--- [ Security Headers Audit ] ---")

        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                present_count += 1
                total_score += info["weight"]
                val = headers[header]
                display_val = (val[:55] + "...") if len(val) > 55 else val
                print(f"[✓] PRESENT ({info['weight']} pts) : {header}")
                print(f"    └─ Value: {display_val}")
            else:
                missing_count += 1
                print(f"[✗] MISSING (0 pts)  : {header}")
                print(f"    └─ Purpose: {info['desc']}")

        print("\n--- [ Information Disclosure Check ] ---")
        disclosure_found = False
        for disc_header in DISCLOSURE_HEADERS:
            if disc_header in headers:
                disclosure_found = True
                print(f"[!] WARNING : '{disc_header}' header exposed -> {headers[disc_header]}")
                # Deduct 5 points per exposed tech header
                total_score = max(0, total_score - 5)

        if not disclosure_found:
            print("[✓] PASS : No server technology disclosure headers detected.")

        grade = calculate_grade(total_score)

        print("\n" + "=" * 70)
        print(f"[*] Score Summary: {total_score}/100 | Grade: [{grade}]")
        print(f"[*] Details      : {present_count} Present | {missing_count} Missing")
        print("=" * 70)

    except requests.exceptions.RequestException as e:
        print(f"[!] Network Error connecting to {formatted_url}: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Web Security Header Checker - Day 2 Value Analysis & Scoring"
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL or domain (e.g., github.com)"
    )
    args = parser.parse_args()

    audit_headers(args.url)

if __name__ == "__main__":
    main()
