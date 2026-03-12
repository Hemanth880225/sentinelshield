"""
SentinelShield — Data Access Layer
Query functions for all dashboard pages.
"""

import random
import datetime
from flask_app.backend.database import get_connection


# ------------------------------------------------------------------
# Dashboard Status
# ------------------------------------------------------------------

def get_dashboard_status():
    """Aggregate stats for the main dashboard cards."""
    conn = get_connection()
    devices_online = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE status = 'online'"
    ).fetchone()[0]

    threats_detected = conn.execute(
        "SELECT COUNT(*) FROM threats"
    ).fetchone()[0]

    honeypots_active = conn.execute(
        "SELECT COUNT(*) FROM honeypots"
    ).fetchone()[0]

    return {
        "devices_online": devices_online,
        "threats_detected": threats_detected,
        "honeypots_active": honeypots_active,
        "network_status": "Secure",
    }


# ------------------------------------------------------------------
# Traffic (simulated from device pool)
# ------------------------------------------------------------------

def get_traffic():
    """Generate realistic traffic entries using devices from the DB."""
    conn = get_connection()
    rows = conn.execute("SELECT ip_address FROM devices WHERE status = 'online'").fetchall()
    ips = [r["ip_address"] for r in rows] if rows else ["192.168.1.1"]

    protocols = ["TCP", "UDP", "HTTP", "HTTPS"]
    now = datetime.datetime.now()
    packets = []
    for _ in range(10):
        packets.append({
            "time": now.strftime("%H:%M:%S"),
            "source": random.choice(ips),
            "destination": random.choice(ips),
            "protocol": random.choice(protocols),
            "size": random.randint(60, 1500),
        })
    return packets


# ------------------------------------------------------------------
# Threats
# ------------------------------------------------------------------

def get_threats():
    """Return all threat records."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM threats ORDER BY timestamp DESC"
    ).fetchall()
    return [
        {
            "time": r["timestamp"],
            "ip": r["source_ip"],
            "type": r["threat_type"],
            "target": r["target_device"],
            "severity": r["severity"],
        }
        for r in rows
    ]


# ------------------------------------------------------------------
# Honeypots
# ------------------------------------------------------------------

def get_honeypots():
    """Return all honeypot records."""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM honeypots").fetchall()
    return [
        {
            "id": f"HP-{r['honeypot_id']}",
            "service": r["service"],
            "status": r["status"],
            "interactions": r["interactions"],
            "last_trigger": r["interaction_time"] or "—",
        }
        for r in rows
    ]


# ------------------------------------------------------------------
# Agent Logs
# ------------------------------------------------------------------

def get_agent_logs():
    """Return all AI agent log entries."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM agent_logs ORDER BY timestamp ASC"
    ).fetchall()
    return [
        {
            "timestamp": r["timestamp"],
            "event_type": r["event_type"],
            "message": r["decision"],
        }
        for r in rows
    ]
