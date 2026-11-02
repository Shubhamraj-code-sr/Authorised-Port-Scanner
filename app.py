import csv
import io
import os
from datetime import datetime, timezone

from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from scanner import scan_tcp_ports, validate_target, validate_ports
from database import init_db, save_scan, get_scans, get_scan

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-development-secret")
app.config["DATABASE"] = os.environ.get("DATABASE_PATH", os.path.join(app.root_path, "scanner.db"))
app.config["ALLOWED_TARGETS"] = os.environ.get("ALLOWED_TARGETS", "127.0.0.1,::1")

with app.app_context():
    init_db(app.config["DATABASE"])


def allowed_targets():
    return [item.strip() for item in app.config["ALLOWED_TARGETS"].split(",") if item.strip()]


@app.get("/")
def index():
    scans = get_scans(app.config["DATABASE"], limit=10)
    return render_template("index.html", scans=scans, allowed_targets=allowed_targets())


@app.post("/scan")
def run_scan():
    target = request.form.get("target", "").strip()
    ports_text = request.form.get("ports", "").strip()
    try:
        validate_target(target, allowed_targets())
        ports = validate_ports(ports_text)
        results = scan_tcp_ports(target, ports, timeout=0.5)
        scan_id = save_scan(
            app.config["DATABASE"],
            target=target,
            ports_requested=len(ports),
            results=results,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        return redirect(url_for("scan_detail", scan_id=scan_id))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))


@app.get("/scan/<int:scan_id>")
def scan_detail(scan_id):
    scan = get_scan(app.config["DATABASE"], scan_id)
    if not scan:
        flash("Scan record not found.", "error")
        return redirect(url_for("index"))
    return render_template("results.html", scan=scan)


@app.get("/scan/<int:scan_id>/export")
def export_scan(scan_id):
    scan = get_scan(app.config["DATABASE"], scan_id)
    if not scan:
        flash("Scan record not found.", "error")
        return redirect(url_for("index"))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID", "Target", "Scan Date (UTC)", "Port", "Status", "Service"])
    for result in scan["results"]:
        writer.writerow([
            scan["id"], scan["target"], scan["created_at"],
            result["port"], result["status"], result["service"]
        ])
    memory_file = io.BytesIO(output.getvalue().encode("utf-8"))
    memory_file.seek(0)
    return send_file(
        memory_file,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"port-scan-{scan_id}.csv",
    )


if __name__ == "__main__":
    # Debug mode is for local development only.
   app.run(host="0.0.0.0", port=5000, debug=True)
