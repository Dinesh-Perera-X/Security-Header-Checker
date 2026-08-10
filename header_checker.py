import argparse
import concurrent.futures
import csv
import json
import requests
import sys
import urllib3
from datetime import datetime

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

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

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

def audit_target(target_info):
    target_url, user_agent, timeout = target_info
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

    headers_req = {"User-Agent": user_agent}

    try:
        response = requests.get(
            formatted_url, 
            timeout=timeout, 
            verify=False, 
            allow_redirects=True, 
            headers=headers_req,
            proxies={"http": None, "https": None}
        )
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
    print(f"[+] Results saved to {output_file} (JSON)")

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
    print(f"[+] Results saved to {output_file} (CSV)")

def export_html(results, output_file):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    for res in results:
        status = res["status_code"] if res["status_code"] else "ERROR"
        grade = res["grade"]
        grade_class = f"grade-{grade.replace('+', 'plus')}"
        disclosures = "<br>".join(res["disclosures"]) if res["disclosures"] else "None"
        error = res["error"] if res["error"] else "None"

        rows += f"""
        <tr>
            <td><strong>{res['target']}</strong></td>
            <td>{status}</td>
            <td>{res['score']}/100</td>
            <td><span class="badge {grade_class}">{grade}</span></td>
            <td>{len(res['present_headers'])} / {len(res['missing_headers'])}</td>
            <td>{disclosures}</td>
            <td class="error-col">{error}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Web Security Header Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px; }}
        h1 {{ color: #38bdf8; text-align: center; font-size: 28px; }}
        .meta {{ text-align: center; color: #94a3b8; margin-bottom: 30px; }}
        table {{ width: 100%; border-collapse: collapse; background-color: #1e293b; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5); }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }}
        th {{ background-color: #0284c7; color: #ffffff; text-transform: uppercase; font-size: 12px; letter-spacing: 1px; }}
        tr:hover {{ background-color: #334155; }}
        .badge {{ padding: 4px 10px; border-radius: 12px; font-weight: bold; font-size: 12px; color: #fff; display: inline-block; }}
        .grade-Aplus, .grade-A {{ background-color: #16a34a; }}
        .grade-B {{ background-color: #ca8a04; }}
        .grade-C, .grade-D {{ background-color: #ea580c; }}
        .grade-F {{ background-color: #dc2626; }}
        .error-col {{ color: #f87171; }}
    </style>
</head>
<body>
    <h1>🛡️ Web Security Header Audit Report</h1>
    <div class="meta">Generated on: {now} | Total Targets Audited: {len(results)}</div>
    <table>
        <thead>
            <tr>
                <th>Target Domain</th>
                <th>Status</th>
                <th>Score</th>
                <th>Grade</th>
                <th>Present/Missing</th>
                <th>Disclosures</th>
                <th>Error</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>
"""
    with open(output_file, 'w') as f:
        f.write(html_content)
    print(f"[+] Results saved to {output_file} (HTML)")

def main():
    parser = argparse.ArgumentParser(description="Web Security Header Checker - Day 4 HTML & User-Agent Upgrade")
    parser.add_argument("-u", "--url", help="Single target URL or domain")
    parser.add_argument("-f", "--file", help="File containing list of domains (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("-o", "--output", help="Output file path (.json, .csv, or .html)")
    parser.add_argument("-A", "--user-agent", default=DEFAULT_USER_AGENT, help="Custom User-Agent header string")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
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

    target_tuples = [(t, args.user_agent, args.timeout) for t in targets]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        completed = executor.map(audit_target, target_tuples)
        for res in completed:
            print_result(res)
            results.append(res)

    if args.output:
        if args.output.endswith('.json'):
            export_json(results, args.output)
        elif args.output.endswith('.csv'):
            export_csv(results, args.output)
        elif args.output.endswith('.html'):
            export_html(results, args.output)
        else:
            print("[!] Unsupported output format. Use .json, .csv, or .html extension.")

if __name__ == "__main__":
    main()
