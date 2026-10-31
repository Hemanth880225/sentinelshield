"""
SentinelShield — Unified Database Layer (SQLAlchemy)
Supports SQLite (default) and PostgreSQL via DATABASE_URL.
"""
from __future__ import annotations
import os
import json
import datetime
from typing import Optional, Generator
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///sentinelshield.db")

# For SQLite, enable check_same_thread=False
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class DeviceModel(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    mac = Column(String(32), unique=True, index=True, nullable=False)
    ip = Column(String(45), index=True, nullable=False)
    hostname = Column(String(128), default="")
    status = Column(String(20), default="online")  # online, offline, quarantined
    device_type = Column(String(64), default="IoT Endpoint")
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)


class TrafficFlowModel(Base):
    __tablename__ = "traffic_flows"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ts = Column(Float, index=True, nullable=False)
    time_str = Column(String(32), index=True, nullable=False)
    src_ip = Column(String(45), index=True, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    dst_port = Column(Integer, nullable=False)
    proto = Column(String(16), default="tcp")
    bytes_out = Column(Integer, default=0)
    bytes_in = Column(Integer, default=0)
    packets = Column(Integer, default=1)
    src_mac = Column(String(32), default="")


class DnsRecordModel(Base):
    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ts = Column(Float, index=True, nullable=False)
    time_str = Column(String(32), nullable=False)
    src_ip = Column(String(45), index=True, nullable=False)
    qname = Column(String(255), index=True, nullable=False)
    qtype = Column(String(16), default="A")


class ThreatFindingModel(Base):
    __tablename__ = "threat_findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    src_ip = Column(String(45), index=True, nullable=False)
    target_device = Column(String(128), default="Network Gateway")
    kind = Column(String(64), index=True, nullable=False)  # port_scan, brute_force, beaconing, etc.
    display_type = Column(String(64), nullable=False)  # "Port Scan", "Brute Force", etc.
    severity = Column(String(16), nullable=False)  # Low, Medium, High
    severity_score = Column(Float, default=0.0)  # 0.0 .. 1.0
    risk_score = Column(Integer, default=0)  # 0 .. 100
    mitre = Column(String(32), default="")
    evidence_json = Column(Text, default="{}")
    timestamp = Column(DateTime, default=utc_now, index=True)
    time_str = Column(String(32), nullable=False)
    status = Column(String(20), default="active")  # active, mitigated, dismissed


class AgentDecisionModel(Base):
    __tablename__ = "agent_decisions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now, index=True)
    time_str = Column(String(32), nullable=False)
    event_type = Column(String(32), default="detection")  # detection, decision, enforcement, audit
    status = Column(String(32), index=True, nullable=False)  # auto_approved, needs_approval, notify_only, denied
    action = Column(String(32), nullable=False)  # block_ip, rate_limit, isolate_device, deploy_honeypot, alert
    target = Column(String(64), nullable=False)
    ttl_seconds = Column(Integer, default=300)
    risk_score = Column(Integer, default=0)
    reason = Column(String(255), default="")
    command_id = Column(String(64), default="")
    reviewed_by = Column(String(64), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    message = Column(Text, default="")


class EnforcementRuleModel(Base):
    __tablename__ = "enforcement_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action = Column(String(32), nullable=False)
    ip = Column(String(45), index=True, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    expires_at = Column(DateTime, index=True, nullable=False)
    command_id = Column(String(64), default="")
    status = Column(String(20), default="active")  # active, expired, revoked


class EnforcementAuditModel(Base):
    __tablename__ = "enforcement_audit"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ts = Column(Float, index=True, nullable=False)
    time_str = Column(String(32), nullable=False)
    command_id = Column(String(64), default="")
    outcome = Column(String(32), nullable=False)  # applied, rejected, failed, expired
    detail = Column(String(255), default="")
    action = Column(String(32), default="")
    target = Column(String(45), default="")


class HoneypotModel(Base):
    __tablename__ = "honeypots"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    honeypot_code = Column(String(16), unique=True, index=True, nullable=False)  # HP-1, HP-2
    service = Column(String(64), nullable=False)  # Fake SSH, Fake FTP, Fake Telnet, Fake HTTP
    port = Column(Integer, default=22)
    status = Column(String(20), default="Active")  # Active, Triggered
    attacker_ip = Column(String(45), nullable=True)
    interactions = Column(Integer, default=0)
    interaction_time = Column(String(32), nullable=True)
    last_payload = Column(Text, nullable=True)


class SystemPolicyModel(Base):
    __tablename__ = "system_policy"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), unique=True, default="default")
    autonomy = Column(String(20), default="automatic")  # automatic, approval, notify
    auto_threshold = Column(Integer, default=70)
    approve_threshold = Column(Integer, default=40)
    max_ttl = Column(Integer, default=3600)
    auto_isolate = Column(Boolean, default=False)
    protected_cidrs = Column(Text, default="127.0.0.1/32,10.0.0.1/32,192.168.1.1/32")


# Ensure tables are created immediately when database module is imported
Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI database dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database() -> None:
    """Create all tables and seed default rows if needed."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Check if policy exists
        pol = db.query(SystemPolicyModel).first()
        if not pol:
            default_pol = SystemPolicyModel(
                tenant_id="default",
                autonomy="automatic",
                auto_threshold=70,
                approve_threshold=40,
                max_ttl=3600,
                auto_isolate=False,
                protected_cidrs="127.0.0.1/32,10.0.0.1/32,192.168.1.1/32"
            )
            db.add(default_pol)

        # Check if honeypots exist
        if db.query(HoneypotModel).count() == 0:
            default_hps = [
                HoneypotModel(honeypot_code="HP-1", service="Fake SSH", port=2222, status="Active", interactions=0),
                HoneypotModel(honeypot_code="HP-2", service="Fake FTP", port=2121, status="Triggered", attacker_ip="198.51.100.23", interactions=7, interaction_time=datetime.datetime.now().strftime("%H:%M:%S")),
                HoneypotModel(honeypot_code="HP-3", service="Fake Telnet", port=2323, status="Active", interactions=2, interaction_time=datetime.datetime.now().strftime("%H:%M:%S")),
                HoneypotModel(honeypot_code="HP-4", service="Fake HTTP", port=8080, status="Triggered", attacker_ip="203.0.113.88", interactions=14, interaction_time=datetime.datetime.now().strftime("%H:%M:%S")),
                HoneypotModel(honeypot_code="HP-5", service="Fake SMTP", port=2525, status="Active", interactions=0),
            ]
            db.add_all(default_hps)

        # Check if devices exist
        if db.query(DeviceModel).count() == 0:
            devices = [
                DeviceModel(mac="00:1A:2B:3C:4D:01", ip="192.168.1.1", hostname="Router – Primary", device_type="Gateway", status="online"),
                DeviceModel(mac="00:1A:2B:3C:4D:10", ip="192.168.1.10", hostname="Smart Camera – Front Door", device_type="Camera", status="online"),
                DeviceModel(mac="00:1A:2B:3C:4D:11", ip="192.168.1.11", hostname="Smart Camera – Garage", device_type="Camera", status="online"),
                DeviceModel(mac="00:1A:2B:3C:4D:20", ip="192.168.1.20", hostname="Smart Thermostat", device_type="Thermostat", status="online"),
                DeviceModel(mac="00:1A:2B:3C:4D:30", ip="192.168.1.30", hostname="Smart Speaker – Living Room", device_type="Audio", status="online"),
                DeviceModel(mac="00:1A:2B:3C:4D:40", ip="192.168.1.40", hostname="Smart Bulb – Bedroom", device_type="Lighting", status="online"),
                DeviceModel(mac="00:1A:2B:3C:4D:50", ip="192.168.1.50", hostname="Smart Lock – Main Door", device_type="Security", status="online"),
                DeviceModel(mac="00:1A:2B:3C:4D:60", ip="192.168.1.60", hostname="Smart TV – Den", device_type="Media", status="online"),
                DeviceModel(mac="00:1A:2B:3C:4D:70", ip="192.168.1.70", hostname="Smart Plug – Office", device_type="Power", status="offline"),
                DeviceModel(mac="00:1A:2B:3C:4D:80", ip="192.168.1.80", hostname="Baby Monitor", device_type="Camera", status="online"),
            ]
            db.add_all(devices)

        # Seed initial agent logs / decisions if empty
        if db.query(AgentDecisionModel).count() == 0:
            now_dt = datetime.datetime.now()
            logs = [
                ("monitoring", "auto_approved", "alert", "192.168.1.0/24", 0, "Scanning IoT network for anomalous traffic patterns", "Scanning IoT network for anomalous traffic patterns"),
                ("detection", "auto_approved", "alert", "198.51.100.23", 75, "SYN burst detected targeting internal ports", "Packet anomaly detected — abnormal SYN flood from 198.51.100.23"),
                ("detection", "needs_approval", "block_ip", "203.0.113.88", 68, "Port scan detected on ports 22, 23, 80", "Port scan detected from 203.0.113.88 targeting ports 22, 23, 80"),
                ("decision", "auto_approved", "deploy_honeypot", "0.0.0.0", 0, "Deploying SSH deception honeypot", "Deploying SSH honeypot on port 2222 to lure attacker"),
                ("enforcement", "auto_approved", "block_ip", "198.51.100.23", 85, "Brute force against Fake FTP honeypot", "Firewall rule added: DROP all from 198.51.100.23 (Signed Ed25519)"),
                ("audit", "auto_approved", "alert", "192.168.1.10", 0, "Baseline traffic analysis active", "Resuming baseline traffic analysis on 10 IoT endpoints"),
                ("detection", "needs_approval", "isolate_device", "192.168.1.10", 65, "Suspicious outbound beaconing from camera", "Suspicious traffic anomaly on Smart Camera – Front Door"),
                ("resolution", "auto_approved", "alert", "0.0.0.0", 0, "Threat neutralized — network secured successfully", "Threat neutralized — network secured successfully"),
            ]
            for i, (ev_type, status, act, tgt, rsk, rsn, msg) in enumerate(logs):
                t_str = (now_dt - datetime.timedelta(minutes=(len(logs) - i) * 4)).strftime("%H:%M:%S")
                db.add(AgentDecisionModel(
                    time_str=t_str,
                    event_type=ev_type,
                    status=status,
                    action=act,
                    target=tgt,
                    risk_score=rsk,
                    reason=rsn,
                    message=msg
                ))

        # Seed initial threats if empty
        if db.query(ThreatFindingModel).count() == 0:
            now_dt = datetime.datetime.now()
            threat_samples = [
                ("198.51.100.23", "Smart Camera – Front Door", "brute_force", "Brute Force", "High", 0.85, 85, "T1110"),
                ("203.0.113.88", "Network Gateway", "port_scan", "Port Scan", "Medium", 0.65, 65, "T1046"),
                ("185.220.101.5", "Smart Lock – Main Door", "brute_force", "Brute Force", "High", 0.82, 82, "T1110"),
                ("192.0.2.44", "Smart TV – Den", "beaconing", "Malware Attempt", "Medium", 0.55, 55, "T1071"),
                ("198.51.100.99", "Router – Primary", "port_scan", "Port Scan", "Low", 0.35, 35, "T1046"),
                ("203.0.113.150", "Baby Monitor", "dns_tunnel", "Suspicious Login", "Medium", 0.60, 60, "T1071.004"),
            ]
            for i, (src, tgt, kind, dtype, sev, sev_s, rsk, mtr) in enumerate(threat_samples):
                t_str = (now_dt - datetime.timedelta(minutes=(len(threat_samples) - i) * 7)).strftime("%H:%M:%S")
                db.add(ThreatFindingModel(
                    src_ip=src,
                    target_device=tgt,
                    kind=kind,
                    display_type=dtype,
                    severity=sev,
                    severity_score=sev_s,
                    risk_score=rsk,
                    mitre=mtr,
                    time_str=t_str,
                    status="active"
                ))

        db.commit()
    finally:
        db.close()
