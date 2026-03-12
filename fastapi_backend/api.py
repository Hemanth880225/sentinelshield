from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import random

# Import security modules
from fastapi_backend.modules.packet_sniffer import capture_packets
from fastapi_backend.modules.threat_detector import detect_threats
from fastapi_backend.modules.honeypot_controller import get_honeypots
from fastapi_backend.modules.ai_decision import get_agent_logs
app = FastAPI()


# --------------------------------------------------
# Enable CORS so Flask frontend can access FastAPI
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# SYSTEM STATUS API
# --------------------------------------------------

@app.get("/status")
def get_status():

    threats = detect_threats()
    honeypots = get_honeypots()

    return {

        "devices_online": random.randint(5,12),

        "network_status": "Secure",

        "threats_detected": len(threats),

        "honeypots_active": len(honeypots)

    }


# --------------------------------------------------
# NETWORK TRAFFIC API
# --------------------------------------------------

@app.get("/traffic")
def get_traffic():

    packets = capture_packets()

    return packets


# --------------------------------------------------
# THREAT MONITORING API
# --------------------------------------------------

@app.get("/threats")
def get_threats():

    threats = detect_threats()

    return threats


# --------------------------------------------------
# HONEYPOT STATUS API
# --------------------------------------------------

@app.get("/honeypots")
def get_honeypots_status():

    honeypots = get_honeypots()

    return honeypots


# --------------------------------------------------
# AI AGENT LOGS API
# --------------------------------------------------

@app.get("/logs")
def get_logs():

    logs = get_agent_logs()

    return logs