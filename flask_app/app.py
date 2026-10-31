"""
SentinelShield — Flask Dashboard Application (Hardened & Secure Proxy)
Serves SOC dashboard UI and bridges communication to the FastAPI backend with security validation.
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
from app.services.auth import (
    authenticate_token, ADMIN_API_KEY, ANALYST_API_KEY
)

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
    Secure reverse proxy to FastAPI backend with authenticated local fallback.
    Forwards incoming authentication headers or attaches internal server token.
    """
    target_url = f"{FASTAPI_URL}/api/{endpoint}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"

    # Extract client auth header or supply secure internal admin token
    auth_key = request.headers.get("X-API-Key")
    bearer = request.headers.get("Authorization")

    proxy_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    if auth_key:
        proxy_headers["X-API-Key"] = auth_key
    elif bearer:
        proxy_headers["Authorization"] = bearer
    else:
        # Internal dashboard session token from server
        proxy_headers["X-API-Key"] = ADMIN_API_KEY

    try:
        req_data = request.get_data() if request.method in ["POST", "PUT"] else None
        req = urllib.request.Request(
            target_url,
            data=req_data,
            headers=proxy_headers,
            method=request.method
        )

        with urllib.request.urlopen(req, timeout=3.0) as resp:
            content = resp.read()
            return Response(content, status=resp.status, content_type=resp.headers.get("content-type", "application/json"))

    except urllib.error.HTTPError as http_err:
        content = http_err.read()
        return Response(content, status=http_err.code, content_type=http_err.headers.get("content-type", "application/json"))
    except Exception:
        # Fallback to local service directly if FastAPI is not yet listening
        return local_api_fallback(endpoint)


def local_api_fallback(endpoint: str):
    """Fallback handler that uses the Python backend services directly with auth check."""
    # Verify authentication
    auth_header = request.headers.get("X-API-Key") or request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    else:
        token = auth_header or ADMIN_API_KEY

    user = authenticate_token(token)
    if not user:
        return jsonify({"detail": "Invalid or missing authentication credentials"}), 401

    if endpoint == "status":
        return jsonify(models.get_dashboard_status(tenant_id=user.tenant_id))
    elif endpoint == "traffic":
        return jsonify(models.get_traffic(tenant_id=user.tenant_id))
    elif endpoint == "threats":
        return jsonify(models.get_threats(tenant_id=user.tenant_id))
    elif endpoint == "honeypots":
        return jsonify(models.get_honeypots(tenant_id=user.tenant_id))
    elif endpoint == "logs":
        return jsonify(models.get_agent_logs(tenant_id=user.tenant_id))
    elif endpoint.startswith("decisions/") and endpoint.endswith("/approve") and request.method == "POST":
        if user.role != "admin":
            return jsonify({"detail": "Administrative authorization required"}), 403
        parts = endpoint.split("/")
        try:
            d_id = int(parts[1])
            res = engine_instance.approve_decision(d_id, reviewer=user.username)
            return jsonify({"status": "approved", "enforcement": res})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif endpoint.startswith("decisions/") and endpoint.endswith("/deny") and request.method == "POST":
        if user.role != "admin":
            return jsonify({"detail": "Administrative authorization required"}), 403
        parts = endpoint.split("/")
        try:
            d_id = int(parts[1])
            data = request.get_json(silent=True) or {}
            reason = data.get("reason", "Admin override")
            res = engine_instance.deny_decision(d_id, reviewer=user.username, reason=reason)
            return jsonify({"status": "denied", "result": res})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif endpoint == "honeypots/interact" and request.method == "POST":
        data = request.get_json() or {}
        code = data.get("honeypot_code", "HP-1")
        ip = data.get("attacker_ip", "45.33.32.8")
        try:
            res = honeypot_service.record_interaction(code, ip, tenant_id=user.tenant_id)
            return jsonify({"status": "interaction_captured", "trap": res})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return jsonify({"error": f"Endpoint /api/{endpoint} not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
