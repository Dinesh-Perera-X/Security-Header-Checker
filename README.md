# Web Security Header Checker

A lightweight Python CLI tool to audit HTTP security headers, analyze server disclosure risks, and calculate security scores for target domains.

## Features

- **HTTP/HTTPS Fetcher:** Automatically handles URL formatting and redirects.
- **Security Header Audit:** Checks for the presence of 6 essential headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- **Value Analysis & Scoring:** Assigns a security score out of 100 based on weighted security header presence and calculates a letter grade (A+, A, B, C, D, F).
- **Information Disclosure Detection:** Flags exposed technology headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`) and applies penalties.

## Prerequisites

- Python 3.x
- `requests` library

```bash
pip install requests
