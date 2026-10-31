"""
SentinelShield — Unified Runner
Launches the Flask SOC Dashboard and FastAPI Backend in parallel.
"""
import sys
import time
import threading
import uvicorn

from app.database import init_database
from flask_app.app import app as flask_app
from fastapi_backend.api import app as fastapi_app


def run_flask():
    """Starts the Flask dashboard server (Port 5000)."""
    flask_app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )


def run_fastapi():
    """Starts the FastAPI backend server (Port 8000)."""
    uvicorn.run(
        fastapi_app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )


if __name__ == "__main__":
    print("=" * 60)
    print("  SentinelShield — Agentic Deception Security Platform v2.0")
    print("  'Don't Just Block Attackers — Deceive Them'")
    print("=" * 60)
    
    # 1. Initialize DB and seeds
    print("[*] Initializing unified database and security policies...")
    init_database()

    # 2. Start services in parallel
    print("[*] Starting FastAPI Backend on http://0.0.0.0:8000 ...")
    fastapi_thread = threading.Thread(target=run_fastapi, daemon=True)
    fastapi_thread.start()

    time.sleep(1)

    print("[*] Starting Flask SOC Dashboard on http://0.0.0.0:5000 ...")
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    print("[+] All SentinelShield services running:")
    print("    - Web Dashboard:     http://localhost:5000")
    print("    - FastAPI Swagger:   http://localhost:8000/docs")
    print("    - Real-Time WS:      ws://localhost:8000/ws/dashboard")
    print("=" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down SentinelShield gracefully...")
        sys.exit(0)
