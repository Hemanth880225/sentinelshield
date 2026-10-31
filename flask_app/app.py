"""
SentinelShield — Flask Dashboard Application
Serves SOC dashboard UI and bridges communication to the FastAPI backend.
"""
from __future__ import annotations
import os
import urllib.request
import urllib.error
import json
from flask import Flask, render_template, jsonify, request, Response

from app.database import init_database
from flask_app.backend import models
from app.services.security_engine import engine_instance
from app.services.honeypot_service import honeypot_service

app = Flask(__name__)

# Initialize unified database on startup
init_database()

FASTAPI_URL = os.environ.get("FASTAPI_URL", "http://127.0.0.1:8000")


# ==================================================
# PAGE ROUTES (Preserved exactly as designed)
# ==================================================

@app.route("/")
def logo():
    return render_template("logo.html")


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@app.route("/traffic")
def traffic():
    return render_template("traffic.html")


@app.route("/threats")
def threats():
    return render_template("threats.html")


@app.route("/honeypots")
def honeypots():
    return render_template("honeypots.html")


@app.route("/agent_logs")
def agent_logs():
    return render_template("agent_logs.html")


# ==================================================
# API PROXY & UNIFIED ENDPOINTS
# ==================================================

@app.route("/api/<path:endpoint>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy_to_fastapi(endpoint):
    """
    Reverse proxy to FastAPI backend with zero-latency local fallback.
    Maintains same-origin simplicity for the frontend while using FastAPI.
    """
    target_url = f"{FASTAPI_URL}/api/{endpoint}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"

    try:
        req_data = request.get_data() if request.method in ["POST", "PUT"] else None
        headers = {k: v for k, v in request.headers if k.lower() not in ["host", "content-length"]}
        
        req = urllib.request.Request(
            target_url,
            data=req_data,
            headers=headers,
            method=request.method
        )
        
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            content = resp.read()
            return Response(content, status=resp.status, content_type=resp.headers.get("content-type", "application/json"))

    except Exception:
        # Fallback to local service directly if FastAPI is not yet listening
        return local_api_fallback(endpoint)


def local_api_fallback(endpoint: str):
    """Fallback handler that uses the Python backend services directly."""
    if endpoint == "status":
        return jsonify(models.get_dashboard_status())
    elif endpoint == "traffic":
        return jsonify(models.get_traffic())
    elif endpoint == "threats":
        return jsonify(models.get_threats())
    elif endpoint == "honeypots":
        return jsonify(models.get_honeypots())
    elif endpoint == "logs":
        return jsonify(models.get_agent_logs())
    elif endpoint.startswith("decisions/") and endpoint.endswith("/approve") and request.method == "POST":
        parts = endpoint.split("/")
        try:
            d_id = int(parts[1])
            res = engine_instance.approve_decision(d_id, reviewer="admin")
            return jsonify({"status": "approved", "enforcement": res})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif endpoint.startswith("decisions/") and endpoint.endswith("/deny") and request.method == "POST":
        parts = endpoint.split("/")
        try:
            d_id = int(parts[1])
            res = engine_instance.deny_decision(d_id, reviewer="admin")
            return jsonify({"status": "denied", "result": res})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif endpoint == "honeypots/interact" and request.method == "POST":
        data = request.get_json() or {}
        code = data.get("honeypot_code", "HP-1")
        ip = data.get("attacker_ip", "198.51.100.23")
        res = honeypot_service.record_interaction(code, ip)
        return jsonify({"status": "interaction_captured", "trap": res})

    return jsonify({"error": f"Endpoint /api/{endpoint} not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
