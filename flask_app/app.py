from flask import Flask, render_template, jsonify

app = Flask(__name__)


# --------------------------------------------------
# Initialize SQLite Database on startup
# --------------------------------------------------

from flask_app.backend.database import init_db
init_db()


# ==================================================
# PAGE ROUTES (existing — unchanged)
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
# JSON API ROUTES (new — SQLite-backed)
# ==================================================

from flask_app.backend import models


@app.route("/api/status")
def api_status():
    """Dashboard summary cards data."""
    return jsonify(models.get_dashboard_status())


@app.route("/api/traffic")
def api_traffic():
    """Simulated network traffic using DB device pool."""
    return jsonify(models.get_traffic())


@app.route("/api/threats")
def api_threats():
    """All threat records from the database."""
    return jsonify(models.get_threats())


@app.route("/api/honeypots")
def api_honeypots():
    """All honeypot records from the database."""
    return jsonify(models.get_honeypots())


@app.route("/api/logs")
def api_logs():
    """AI agent decision logs from the database."""
    return jsonify(models.get_agent_logs())


# --------------------------------------------------
# Run Flask alone (for testing)
# --------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)