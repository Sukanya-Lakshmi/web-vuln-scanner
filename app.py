from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from core.engine import ScanEngine
from database import ScannerDatabase

app = Flask(__name__)
app.secret_key = "dev-secret-change-in-production"

db = ScannerDatabase("scanner.db")
engine = ScanEngine(db=db, timeout=8, delay=0.1)


@app.route("/", methods=["GET"])
def index():
    scans = db.list_scans()
    return render_template("index.html", scans=scans)


@app.route("/scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("target_url", "").strip()
    try:
        max_depth = int(request.form.get("max_depth", 2))
        max_depth = max(0, min(max_depth, 4))
    except ValueError:
        max_depth = 2

    try:
        scan_id = engine.run_scan(target_url=target_url, max_depth=max_depth)
        flash(f"Scan #{scan_id} completed.", "success")
        return redirect(url_for("scan_detail", scan_id=scan_id))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))
    except Exception as exc:
        flash(f"Scan failed: {exc}", "error")
        return redirect(url_for("index"))


@app.route("/scans/<int:scan_id>", methods=["GET"])
def scan_detail(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        flash(f"Scan #{scan_id} was not found.", "error")
        return redirect(url_for("index"))

    severity = request.args.get("severity", "ALL").upper()
    if severity not in ("ALL", "HIGH", "MEDIUM", "LOW"):
        severity = "ALL"

    findings = db.get_findings(scan_id, severity=severity)
    return render_template(
        "scan_detail.html",
        scan=scan,
        findings=findings,
        active_severity=severity,
    )

@app.route("/scans/<int:scan_id>/export.json", methods=["GET"])
def export_scan_json(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan #{scan_id} not found"}), 404

    severity = request.args.get("severity", "ALL").upper()
    if severity not in ("ALL", "HIGH", "MEDIUM", "LOW"):
        severity = "ALL"

    findings = db.get_findings(scan_id, severity=severity)
    payload = {
        "scan": scan,
        "severity_filter": severity,
        "total_findings": len(findings),
        "findings": findings,
    }
    response = jsonify(payload)
    response.headers["Content-Disposition"] = (
        f"attachment; filename=scan_{scan_id}_{severity.lower()}.json"
    )
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
