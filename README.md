# Web Security Header Checker

A lightweight Python CLI tool to audit HTTP security headers, analyze server disclosure risks, run concurrent multi-target batch scans, and export structured reports.

## Features

- **HTTP/HTTPS Fetcher:** Automatically handles scheme formatting and redirects.
- **Security Header Audit:** Checks for 6 essential security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
- **Value Analysis & Scoring:** Assigns security scores (0–100) and letter grades (A+ to F).
- **Information Disclosure Detection:** Flags server technology disclosure headers (`Server`, `X-Powered-By`, etc.) with penalties.
- **Batch Processing & Multithreading:** Concurrently audits multiple target domains from a text file using thread pools.
- **Report Exporting:** Exports comprehensive audit results directly to `.json` or `.csv` files.

## Prerequisites

- Python 3.x
- `requests` library

```bash
pip install requests
