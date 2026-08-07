# Web Security Header Checker - Day 1

A lightweight Python CLI tool to fetch HTTP response headers from a target domain and audit them against standard security headers.

## Features
- **HTTP/HTTPS Fetcher:** Automatically handles scheme formatting and redirects.
- **Security Header Audit:** Checks for the presence of 6 essential headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- **Console Summary:** Displays present/missing header status alongside status codes and descriptions.

## Prerequisites
- Python 3.x
- `requests` library

```bash
pip install requests
