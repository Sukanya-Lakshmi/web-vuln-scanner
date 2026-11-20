# Web Vulnerability Scanner

A modular web vulnerability scanner built with **Python**, **Flask**, and **SQLite** featuring a configurable web crawler, passive HTTP security header checks, benign reflected XSS reflection detection, a dark SOC-style web dashboard, severity filtering, CLI mode, and JSON report export.

> **Disclaimer:** Use this tool strictly on systems you own or have explicit authorization to test. Do not run automated scans against unauthorized targets.

## Key Features
- **Configurable Crawler:** Discovers internal links, parameterized URLs, and HTML forms up to a user-defined crawl depth, tracking crawled URL counts per scan.
- **Security Header Checks (`HeaderScanner`):** Audits HTTP responses for missing or weak headers such as `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and HTTPS `Strict-Transport-Security`.
- **Reflected XSS Detection (`XSSScanner`):** Sends harmless marker payloads to query parameters and forms to detect unencoded reflection in responses.
- **SQLite Persistence & Web Dashboard:** Stores scan history and findings in SQLite with severity filtering (`ALL`, `HIGH`, `MEDIUM`, `LOW`) and one-click JSON export.
- **CLI Support:** Run scans directly from the terminal with custom depth, severity filters, and optional JSON report output.

## Project Structure
- `app.py` — Flask web dashboard & JSON export route
- `cli.py` — Command-line interface runner
- `database.py` — SQLite schema, auto-migration & queries
- `vuln_lab_app.py` — Local vulnerable test app for safe practice
- `core/requester.py` — HTTP request wrapper with timeout & delay
- `core/crawler.py` — Depth-limited link & form crawler
- `core/engine.py` — Scan orchestration & DB updates
- `scanners/base.py` — Base scanner interface
- `scanners/headers.py` — HTTP security header checks
- `scanners/xss.py` — Benign reflected XSS reflection probe
- `templates/index.html` — Dashboard & scan history view
- `templates/scan_detail.html` — Findings view, filters & JSON export

## Setup & Installation

```bash
git clone https://github.com/Sukanya-Lakshmi/web-vuln-scanner.git
cd web-vuln-scanner

python3 -m venv venv
source venv/bin/activate
pip install flask requests beautifulsoup4
```

## Usage

### 1. Local Practice Lab & Web Dashboard
Start the local test target in one terminal:

```bash
python3 vuln_lab_app.py
```

Start the Flask dashboard in a second terminal:

```bash
python3 app.py
```

Open `[http://127.0.0.1:5000](http://127.0.0.1:5000)` in your browser to launch scans, filter by severity, and export JSON reports.

### 2. CLI Mode

```bash
python3 cli.py http://127.0.0.1:5001 --depth 2 --severity ALL --output report.json
```

## Limitations & Scope
- Designed as a lightweight educational and hands-on security tool rather than a replacement for full enterprise DAST scanners.
- Does not exploit vulnerabilities maliciously; uses non-intrusive probing and passive inspection.
