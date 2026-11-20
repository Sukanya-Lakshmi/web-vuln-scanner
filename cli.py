import argparse
import json
from core.engine import ScanEngine
from database import ScannerDatabase


def main():
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner CLI (Authorized Targets Only)"
    )
    parser.add_argument("target_url", help="Target URL (e.g., http://127.0.0.1:5001)")
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum crawl depth (default: 2)",
    )
    parser.add_argument(
        "--severity",
        choices=["ALL", "HIGH", "MEDIUM", "LOW"],
        default="ALL",
        help="Filter displayed findings by severity (default: ALL)",
    )
    parser.add_argument(
        "--output",
        help="Optional path to save JSON report (e.g., report.json)",
    )
    parser.add_argument(
        "--db",
        default="scanner.db",
        help="SQLite database path (default: scanner.db)",
    )

    args = parser.parse_args()
    db = ScannerDatabase(args.db)
    engine = ScanEngine(db=db)

    scan_id = engine.run_scan(target_url=args.target_url, max_depth=args.depth)
    scan = db.get_scan(scan_id)
    findings = db.get_findings(scan_id, severity=args.severity)

    print(f"\n[+] Scan #{scan_id} finished | Status: {scan['status']} | Crawled URLs: {scan['visited_count']}")
    print(f"[+] Findings ({args.severity}): {len(findings)}\n")

    for f in findings:
        print(f"[{f['severity'].upper()}] {f['vulnerability']} ({f['scanner']})")
        print(f"    URL         : {f['url']}")
        print(f"    Evidence    : {f['evidence']}")
        print(f"    Remediation : {f['remediation']}\n")

    if args.output:
        report_payload = {
            "scan": scan,
            "severity_filter": args.severity,
            "findings": findings,
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report_payload, fh, indent=2)
        print(f"[+] JSON report saved to {args.output}")


if __name__ == "__main__":
    main()
