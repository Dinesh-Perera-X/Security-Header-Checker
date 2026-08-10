# Web Security Header Checker

A lightweight Python CLI tool to audit HTTP security headers, analyze server disclosure risks, run concurrent multi-target batch scans, and export structured reports (CSV, JSON, HTML).

## Features

- **HTTP/HTTPS Fetcher:** Automatically handles scheme formatting, custom User-Agents, and redirects.
- **Security Header Audit:** Checks for 6 essential security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
- **Value Analysis & Scoring:** Assigns security scores (0–100) and letter grades (A+ to F).
- **Information Disclosure Detection:** Flags server technology disclosure headers (`Server`, `X-Powered-By`, etc.) with penalties.
- **Batch Processing & Multithreading:** Concurrently audits multiple target domains from a text file using thread pools.
- **Multi-Format Reporting:** Exports comprehensive audit results directly to `.json`, `.csv`, or styled `.html` web reports.

## Prerequisites

- Python 3.x
- `requests` library

```bash
pip install requests
