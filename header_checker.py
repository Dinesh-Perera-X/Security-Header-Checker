import argparse
import concurrent.futures
import csv
import json
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"weight": 25, "desc": "Enforces HTTPS connections (HSTS)."},
    "Content-Security-Policy": {"weight": 25, "desc": "Prevents XSS and data injection attacks."},
    "X-Frame-Options": {"weight": 15, "desc": "Protects against Clickjacking attacks."},
    "X-Content-Type-Options": {"weight": 15, "desc": "Prevents MIME-sniffing vulnerabilities."},
    "Referrer-Policy": {"weight": 10, "desc": "Controls referrer information exposure."},
    "Permissions-Policy": {"weight": 10, "desc": "Restricts browser feature access."}
}

DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]

def format_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url

def calculate_grade(score):
    if score >= 90: return "A+"
    elif score >= 80: return "A"
    elif score >= 70: return "B"
    elif score >= 60: return "C"
    elif score >= 50: return "D"
    else: return "F"

def audit_target(target_url):
    formatted_url = format_url(target_url)
    result = {
        "target": formatted_url,
        "status_code": None,
        "score": 0,
        "grade": "F",
        "present_headers": {},
        "missing_headers": [],
        "disclosures": [],
        "error": None
    }

    try:
        response = requests.get(formatted_url, timeout=10, verify=False, allow_redirects=True)
        result["status_code"] = response.status_code
        headers = response.headers
        total_score = 0

        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                total_score += info["weight"]
                result["present_headers"][header] = headers[header]
            else:
                result["missing_headers"].append(header)

        for disc_header in DISCLOSURE_HEADERS:
            if disc_header in headers:
                result["disclosures"].append(f"{disc_header}: {headers[disc_header]}")
                total_score = max(0, total_score - 5)

        result["score"] = total_score
        result["grade"] = calculate_grade(total_score)

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result

def print_result(res):
    print("=" * 70)
    print(f"[*] Target: {res['target']}")
    print("=" * 70)
    if res["error"]:
        print(f"[!] Error: {res['error']}\n")
        return

    print(f"[+] Status Code : {res['status_code']}")
    print(f"[+] Score       : {res['score']}/100 | Grade: [{res['grade']}]")
    print(f"[✓] Present     : {len(res['present_headers'])} headers")
    print(f"[✗] Missing     : {len(res['missing_headers'])} headers")
    if res["disclosures"]:
        print(f"[!] Disclosures : {', '.join(res['disclosures'])}")
    print()

def export_json(results, output_file):
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"[+] Results successfully saved to {output_file} (JSON)")

def export_csv(results, output_file):
    fieldnames = ["target", "status_code", "score", "grade", "present_count", "missing_count", "disclosures", "error"]
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for res in results:
            writer.writerow({
                "target": res["target"],
                "status_code": res["status_code"],
                "score": res["score"],
                "grade": res["grade"],
                "present_count": len(res["present_headers"]),
                "missing_count": len(res["missing_headers"]),
                "disclosures": "; ".join(res["disclosures"]),
                "error": res["error"]
            })
    print(f"[+] Results successfully saved to {output_file} (CSV)")

def main():
    parser = argparse.ArgumentParser(description="Web Security Header Checker - Day 3 Batch Processing")
    parser.add_argument("-u", "--url", help="Single target URL or domain")
    parser.add_argument("-f", "--file", help="File containing list of domains (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("-o", "--output", help="Output file path (.json or .csv)")
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error("Please specify a target using -u/--url or a file using -f/--file.")

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"[!] Target file '{args.file}' not found.")
            sys.exit(1)

    print(f"[*] Starting audit for {len(targets)} target(s)...\n")
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        completed = executor.map(audit_target, targets)
        for res in completed:
            print_result(res)
            results.append(res)

    if args.output:
        if args.output.endswith('.json'):
            export_json(results, args.output)
        elif args.output.endswith('.csv'):
            export_csv(results, args.output)
        else:
            print("[!] Unsupported output format. Please use .json or .csv extension.")

if __name__ == "__main__":
    main()
