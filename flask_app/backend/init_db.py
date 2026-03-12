"""
SentinelShield — Database Seed Script
Inserts realistic sample data for hackathon demo.
"""

from datetime import datetime, timedelta
import random


def seed_data(conn):
    """Populate all tables with sample data."""
    _seed_devices(conn)
    _seed_threats(conn)
    _seed_honeypots(conn)
    _seed_agent_logs(conn)
    conn.commit()


# ------------------------------------------------------------------
# Devices
# ------------------------------------------------------------------

def _seed_devices(conn):
    devices = [
        ("Smart Camera – Front Door",  "192.168.1.10",  "online"),
        ("Smart Camera – Garage",      "192.168.1.11",  "online"),
        ("Smart Thermostat",           "192.168.1.20",  "online"),
        ("Smart Speaker – Living Room","192.168.1.30",  "online"),
        ("Smart Bulb – Bedroom",       "192.168.1.40",  "online"),
        ("Smart Lock – Main Door",     "192.168.1.50",  "online"),
        ("Smart TV – Den",             "192.168.1.60",  "online"),
        ("Router – Primary",           "192.168.1.1",   "online"),
        ("Smart Plug – Office",        "192.168.1.70",  "offline"),
        ("Baby Monitor",               "192.168.1.80",  "online"),
    ]
    now = datetime.now()
    for name, ip, status in devices:
        last = (now - timedelta(minutes=random.randint(0, 30))).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO devices (device_name, ip_address, status, last_seen) VALUES (?, ?, ?, ?)",
            (name, ip, status, last),
        )


# ------------------------------------------------------------------
# Threats
# ------------------------------------------------------------------

def _seed_threats(conn):
    threat_types = ["Port Scan", "Brute Force", "Malware Attempt", "Suspicious Login"]
    severities   = ["Low", "Medium", "High"]
    targets      = [
        "Smart Camera", "Smart Speaker", "Router",
        "Smart Bulb", "Smart Lock", "Smart TV", "Baby Monitor",
    ]
    now = datetime.now()
    for i in range(18):
        ts = (now - timedelta(minutes=random.randint(1, 120))).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO threats (source_ip, target_device, threat_type, severity, timestamp) VALUES (?,?,?,?,?)",
            (
                f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                random.choice(targets),
                random.choice(threat_types),
                random.choice(severities),
                ts,
            ),
        )


# ------------------------------------------------------------------
# Honeypots
# ------------------------------------------------------------------

def _seed_honeypots(conn):
    honeypots = [
        ("Fake SSH",    "Active",    None,                   0),
        ("Fake FTP",    "Triggered", "10.42.88.12",         7),
        ("Fake Telnet", "Active",    None,                   2),
        ("Fake HTTP",   "Triggered", "10.99.14.201",        14),
        ("Fake SMTP",   "Active",    None,                   0),
    ]
    now = datetime.now()
    for service, status, attacker, interactions in honeypots:
        ts = (now - timedelta(minutes=random.randint(0, 60))).strftime("%Y-%m-%d %H:%M:%S") if interactions else None
        conn.execute(
            "INSERT INTO honeypots (service, status, attacker_ip, interactions, interaction_time) VALUES (?,?,?,?,?)",
            (service, status, attacker, interactions, ts),
        )


# ------------------------------------------------------------------
# AI Agent Logs
# ------------------------------------------------------------------

def _seed_agent_logs(conn):
    logs = [
        ("monitoring",    "Scanning IoT network for anomalous traffic patterns"),
        ("detection",     "Packet anomaly detected — abnormal SYN flood from 10.42.88.12"),
        ("detection",     "Port scan detected from 10.99.14.201 targeting ports 22, 23, 80"),
        ("deployment",    "Deploying SSH honeypot on port 2222 to lure attacker"),
        ("interaction",   "Attacker 10.42.88.12 connected to Fake FTP honeypot"),
        ("analysis",      "AI model classified traffic as Brute Force — confidence 94.7%"),
        ("blocking",      "Firewall rule added: DROP all from 10.42.88.12"),
        ("monitoring",    "Resuming baseline traffic analysis on 10 IoT endpoints"),
        ("detection",     "Suspicious login attempt on Smart Camera from 10.55.77.3"),
        ("blocking",      "Quarantined Smart Camera – Front Door pending review"),
        ("resolution",    "Threat neutralized — network secured successfully"),
        ("monitoring",    "All modules operational — continuous defense posture active"),
        ("analysis",      "AI model retrained with latest threat signatures"),
        ("deployment",    "Fake HTTP honeypot deployed on port 8080"),
        ("interaction",   "Attacker 10.99.14.201 probing Fake HTTP — captured payload"),
    ]
    now = datetime.now()
    for i, (event_type, decision) in enumerate(logs):
        ts = (now - timedelta(minutes=(len(logs) - i) * 3)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO agent_logs (event_type, decision, timestamp) VALUES (?,?,?)",
            (event_type, decision, ts),
        )
