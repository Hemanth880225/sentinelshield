"""
SentinelShield — Telemetry Generator & Collector Simulator
Simulates a lightweight collector forwarding telemetry into the pipeline.
"""
from __future__ import annotations
import time
import random
import threading
import datetime
from app.core.telemetry import FlowEvent, DnsEvent, DeviceEvent
from app.services.security_engine import engine_instance
from app.database import SessionLocal, DeviceModel

EXTERNAL_BENIGN_IPS = [
    "1.1.1.1", "8.8.8.8", "142.250.190.46", "104.16.132.229",
    "151.101.1.140", "13.107.42.14"
]

BENIGN_DOMAINS = [
    "api.weather.com", "pool.ntp.org", "time.google.com",
    "mqtt.iotcloud.io", "updates.firmware.net", "connectivitycheck.gstatic.com"
]

ATTACKER_IPS = [
    "45.33.32.8", "185.220.101.5", "89.248.165.12", "194.26.29.41"
]


class CollectorSimulator:
    def __init__(self, interval_seconds: float = 3.0):
        self.interval = interval_seconds
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def generate_single_sample(self):
        """Generates a small batch of traffic events and ingests them into the engine."""
        db = SessionLocal()
        try:
            devices = db.query(DeviceModel).filter_by(status="online").all()
            device_ips = [d.ip for d in devices] if devices else ["192.168.1.10", "192.168.1.20"]
        finally:
            db.close()

        now_ts = time.time()
        flows = []
        # 1. Generate 3-6 benign flows
        for _ in range(random.randint(3, 6)):
            src = random.choice(device_ips)
            dst = random.choice(EXTERNAL_BENIGN_IPS + device_ips)
            port = random.choice([80, 443, 8080, 8883, 53])
            proto = "udp" if port == 53 else "tcp"
            flows.append(FlowEvent(
                ts=now_ts,
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                proto=proto,
                bytes_out=random.randint(80, 2500),
                bytes_in=random.randint(100, 5000),
                packets=random.randint(1, 10)
            ))

        # 2. Ingest flows into engine
        for f in flows:
            engine_instance.ingest_flow(f)

        # 3. Occasionally generate a benign DNS lookup
        if random.random() < 0.4:
            src = random.choice(device_ips)
            qname = random.choice(BENIGN_DOMAINS)
            engine_instance.ingest_dns(DnsEvent(ts=now_ts, src_ip=src, qname=qname))

        # 4. Periodically tick rule expiry
        engine_instance.expire_rules()

    def trigger_test_attack(self, attack_type: str = "port_scan") -> dict:
        """Helper to generate a distinct verifiable attack trace for testing or demo."""
        now_ts = time.time()
        attacker = random.choice(ATTACKER_IPS)

        if attack_type == "port_scan":
            # 20 distinct ports from attacker to gateway in 10 seconds
            for p in range(1000, 1025):
                flow = FlowEvent(
                    ts=now_ts + (p - 1000) * 0.1,
                    src_ip=attacker,
                    dst_ip="192.168.1.1",
                    dst_port=p,
                    proto="tcp",
                    bytes_out=60,
                    bytes_in=0,
                    packets=1
                )
                engine_instance.ingest_flow(flow)
            return {"type": "port_scan", "src_ip": attacker, "ports_probed": 25}

        elif attack_type == "brute_force":
            for i in range(15):
                flow = FlowEvent(
                    ts=now_ts + i * 0.2,
                    src_ip=attacker,
                    dst_ip="192.168.1.10",
                    dst_port=22,
                    proto="tcp",
                    bytes_out=250,
                    bytes_in=60,
                    packets=3
                )
                engine_instance.ingest_flow(flow)
            return {"type": "brute_force", "src_ip": attacker, "target_port": 22}

        elif attack_type == "dns_tunnel":
            import secrets
            for _ in range(6):
                sub = secrets.token_hex(20)  # 40 chars entropy
                dns = DnsEvent(ts=now_ts, src_ip="192.168.1.30", qname=f"{sub}.c2-exfil.xyz")
                engine_instance.ingest_dns(dns)
            return {"type": "dns_tunnel", "src_ip": "192.168.1.30"}

        return {"error": "unknown attack type"}

    def _run_loop(self):
        while self._running:
            try:
                self.generate_single_sample()
            except Exception:
                pass
            time.sleep(self.interval)


simulator = CollectorSimulator()
