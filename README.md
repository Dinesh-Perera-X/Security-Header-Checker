# Web Security Header Checker

A lightweight, multi-threaded Python CLI tool to audit HTTP security headers, detect server technology disclosure risks, run batch scans, and generate structured reports (CSV, JSON, HTML).

## Features

- **HTTP/HTTPS Fetcher:** Handles scheme formatting, custom User-Agents, and redirects.
- **Security Header Audit:** Checks for 6 essential security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
- **Value Analysis & Scoring:** Assigns security scores (0–100) and letter grades (A+ to F).
- **Information Disclosure Detection:** Flags server technology disclosure headers (`Server`, `X-Powered-By`, etc.) with penalties.
- **Batch Processing & Multithreading:** Concurrently audits multiple target domains from a text file using thread pools.
- **Multi-Format Reporting:** Exports audit results directly to `.json`, `.csv`, or styled `.html` web reports.
- **Unit Tested & Packaged:** Includes automated test suites and pip-installable setup configuration.

## Installation

Install locally in editable mode:

```bash
pip install -e . --break-system-packages
