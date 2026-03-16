"""Flask REST API server for Cerberus."""

import json
import logging
import threading

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from api import db
from api.scheduler import start_scheduler, run_scan_for_target
from core.config import Config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("cerberus.api")

app = Flask(__name__, static_folder="../ui", static_url_path="/")
app.secret_key = Config.SECRET_KEY
CORS(app)


# --- Static UI ---

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# --- Health ---

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "cerberus"})


# --- Dashboard ---

@app.route("/api/dashboard")
def dashboard():
    target_id = request.args.get("target_id", type=int)
    stats = db.get_dashboard_stats(target_id)
    return jsonify(stats)


# --- Targets ---

@app.route("/api/targets", methods=["GET"])
def list_targets():
    targets = db.get_targets()
    return jsonify(targets)


@app.route("/api/targets", methods=["POST"])
def add_target():
    data = request.get_json()
    if not data or not data.get("domain"):
        return jsonify({"error": "domain is required"}), 400

    target_id = db.create_target(
        name=data.get("name", data["domain"]),
        domain=data["domain"],
        target_type=data.get("target_type", "domain"),
        emails=data.get("emails", []),
        tags=data.get("tags", []),
    )
    return jsonify({"id": target_id, "message": "Target added"}), 201


# --- Scans ---

@app.route("/api/scans", methods=["GET"])
def list_scans():
    target_id = request.args.get("target_id", type=int)
    scans = db.get_scans(target_id=target_id)
    return jsonify(scans)


@app.route("/api/scans", methods=["POST"])
def trigger_scan():
    data = request.get_json()
    if not data or not data.get("target_id"):
        return jsonify({"error": "target_id is required"}), 400

    target_id = data["target_id"]
    target = db.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found"}), 404

    # Run scan in background thread
    thread = threading.Thread(target=run_scan_for_target, args=(target_id,))
    thread.daemon = True
    thread.start()

    return jsonify({"message": f"Scan started for {target['domain']}", "target_id": target_id}), 202


# --- Findings ---

@app.route("/api/findings")
def list_findings():
    target_id = request.args.get("target_id", type=int)
    severity = request.args.get("severity")
    status = request.args.get("status")
    findings = db.get_findings(target_id=target_id, severity=severity, status=status)
    return jsonify(findings)


@app.route("/api/findings/<int:finding_id>/status", methods=["PATCH"])
def update_finding(finding_id):
    data = request.get_json()
    if not data or not data.get("status"):
        return jsonify({"error": "status is required"}), 400
    db.update_finding_status(finding_id, data["status"])
    return jsonify({"message": "Finding updated"})


# --- Compliance ---

@app.route("/api/compliance")
def compliance_scores():
    target_id = request.args.get("target_id", type=int)
    scores = db.get_compliance_scores(target_id=target_id)
    return jsonify(scores)


# --- Breaches ---

@app.route("/api/breaches")
def list_breaches():
    target_id = request.args.get("target_id", type=int)
    status = request.args.get("status")
    breaches = db.get_breaches(target_id=target_id, status=status)
    return jsonify(breaches)


# --- Reports ---

@app.route("/api/reports")
def list_reports():
    target_id = request.args.get("target_id", type=int)
    reports = db.get_reports(target_id=target_id)
    return jsonify(reports)


# --- Initialize and run ---

def create_app():
    db.init_db()
    return app


if __name__ == "__main__":
    create_app()
    start_scheduler()
    app.run(host="0.0.0.0", port=5000, debug=False)
