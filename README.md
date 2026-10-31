# SentinelShield

**Agentic AI-Powered Deception Security Platform for Startups**  
*“Don't Just Block Attackers — Deceive Them”*  
Version: 2.0 (Cloud-Native Architecture Edition)

---

## 1. Executive Summary

SentinelShield is an autonomous network security system engineered specifically for startups, developer labs, and IoT-enabled environments that lack dedicated cybersecurity operations teams. 

Unlike traditional passive monitoring systems that merely log events, SentinelShield is **agentic**: it actively detects network threats, correlates risks using statistical and AI-driven models, autonomously decides defensive countermeasures, signs cryptographic security commands using Ed25519, and orchestrates local enforcement and dynamic deception traps in real time.

This repository represents the unified SentinelShield platform, integrating the established SOC dashboard frontend with the high-performance Python/FastAPI backend and cryptographic local enforcement agent.

---

## 2. Integrated Architecture

SentinelShield strictly separates the **Cloud Control Plane** (analysis, intelligence, orchestration, command signing) from the **Local Enforcement Agent** (least-privilege firewall enforcement and decoy traffic redirection).

```
+-----------------------------------------------------------------------------------------+
|                                    CUSTOMER NETWORK                                     |
|                                                                                         |
|  [ IoT Endpoints ] <----+                                                               |
|  [ Laptops/Servers ]    |                                                               |
|                         v                                                               |
|              +----------------------+               +--------------------------------+  |
|              | Lightweight Collector|               | Local Enforcement Agent        |  |
|              | (Scapy / Zeek flows) |               | (iptables/nftables / DryRun)   |  |
|              +----------+-----------+               +---------------+----------------+  |
|                         |                                           ^                   |
+-------------------------|-------------------------------------------|-------------------+
                          | TLS 1.3 Telemetry                         | Outbound mTLS     |
                          | (Flows, DNS, Devices)                     | Ed25519 Commands  |
                          v                                           |                   |
+---------------------------------------------------------------------|-------------------+
|                            SENTINELSHIELD CONTROL PLANE             |                   |
|                                                                     |                   |
|   +-------------------------------------------------------------+   |                   |
|   |                     FastAPI Backend (:8000)                 |   |                   |
|   |  - Ingestion APIs       - Security Engine API               |   |                   |
|   |  - REST & WebSocket     - Honeypot Controller               |   |                   |
|   +------------------------------+------------------------------+   |                   |
|                                  |                                  |                   |
|                                  v                                  |                   |
|   +-------------------------------------------------------------+   |                   |
|   |                    Detection & AI Engine                    |   |                   |
|   |  * Port Scan (T1046)          * Brute Force (T1110)         |   |                   |
|   |  * C2 Beaconing (T1071)       * DNS Tunnel (T1071.004)      |   |                   |
|   |  * Exfiltration (T1041)       * Unknown Device (T1200)      |   |                   |
|   +------------------------------+------------------------------+   |                   |
|                                  |                                  |                   |
|                                  v                                  |                   |
|   +-------------------------------------------------------------+   |                   |
|   |                Noisy-OR Risk Scoring & Policy               |   |                   |
|   |  - Autonomy levels: automatic | approval | notify           |   |                   |
|   |  - Protected asset validation (CIDR / host safety)          |   |                   |
|   +------------------------------+------------------------------+   |                   |
|                                  |                                  |                   |
|                                  v                                  |                   |
|   +-------------------------------------------------------------+   |                   |
|   |                Ed25519 Command Signer (Cloud)               +---+                   |
|   |  - Replay protection (nonces)   - Short TTL expiry          |                       |
|   +-------------------------------------------------------------+                       |
|                                  |                                                      |
|                                  v                                                      |
|   +-------------------------------------------------------------+                       |
|   |                Dynamic Honeypot Deception Engine            |                       |
|   |  - Fake SSH (:2222)           - Fake FTP (:2121)            |                       |
|   |  - Fake Telnet (:2323)        - Fake HTTP (:8080)           |                       |
|   +-------------------------------------------------------------+                       |
|                                  |                                                      |
|                                  v                                                      |
|   +-------------------------------------------------------------+                       |
|   |                  Unified Persistence Layer                  |                       |
|   |           SQLite (default) / PostgreSQL (enterprise)        |                       |
|   +------------------------------+------------------------------+                       |
+----------------------------------|------------------------------------------------------+
                                   | HTTP / WebSocket
                                   v
+-----------------------------------------------------------------------------------------+
|                                SOC DASHBOARD FRONTEND                                   |
|                                                                                         |
|   +-------------------------------------------------------------+                       |
|   |                   Flask Web Server (:5000)                  |                       |
|   |  - Preserved SOC Visual Theme  - Reverse Proxy to FastAPI   |                       |
|   +------------------------------+------------------------------+                       |
|                                  |                                                      |
|                                  v                                                      |
|   +-------------------------------------------------------------+                       |
|   |                 Centralized JS API Client                   |                       |
|   |  - Live Counters & Donut/Line Charts                        |                       |
|   |  - Real-Time Packet Stream & MITRE Threat Intel             |                       |
|   |  - Interactive Deception Trap Probe Simulation              |                       |
|   |  - Human-in-the-Loop Action Approval (1-Click Enforce)      |                       |
|   +-------------------------------------------------------------+                       |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Core Capabilities

### 1. Intelligent Threat Detection
Six statistical and algorithmic detectors evaluate sliding telemetry windows:
* **Port Scan (`T1046`)**: Detects reconnaissance probing across 15+ ports within 60-second windows.
* **Brute Force (`T1110`)**: Identifies rapid authentication attempts on sensitive ports (SSH, FTP, Telnet, SMB, RDP).
* **C2 Beaconing (`T1071`)**: Flags outbound heartbeat traffic with low coefficient of variance ($CV \le 0.15$).
* **DNS Tunneling (`T1071.004`)**: Shannon entropy analysis of high-length query labels to uncover C2 covert channels.
* **Data Exfiltration (`T1041`)**: Detects baseline-exceeding outbound transfers ($z \ge 4.0$, $>10\text{ MB}$).
* **Unknown Device Discovery (`T1200`)**: Detects rogue hardware joining local broadcast domains.

### 2. Probabilistic Risk Scoring & Policy Engine
* Aggregates findings per source IP using a **noisy-OR** probability formulation:
  $$\text{Risk Score} = 100 \times \left(1 - \prod_{f \in \text{findings}} \left(1 - w_f \cdot \text{severity}_f\right)\right)$$
* Enforces tenant-scoped policy rules:
  - **Autonomy levels**: `automatic`, `approval`, or `notify`.
  - **Protected assets**: Never blocks gateway CIDRs or core infrastructure.
  - **TTL clamping**: Prevents infinite lockouts by clamping action windows.

### 3. Cryptographic Ed25519 Command Pipeline
* Cloud orchestrator generates single-use signed commands containing payload digest, nonce, expiry, tenant ID, and collector ID.
* Local agent cryptographically verifies signatures before applying rules.
* Tampered commands, replay attempts, expired commands, and mismatched keys are rejected with full audit logging.
* Agent executes local expiry independently of cloud link health.

### 4. Dynamic Honeypots & Deception Traps
* Deploys fake services (Fake SSH, Fake FTP, Fake Telnet, Fake HTTP, Fake SMTP) in isolated sandbox environments.
* Captures attacker probes, records payloads, and feeds interaction telemetry back into the risk scoring engine.

---

## 4. API Communication Contracts

The frontend communicates with the backend through standardized JSON HTTP APIs and WebSocket streams:

| Route | Method | Payload / Query | Response | Auth | Description |
|---|---|---|---|---|---|
| `/api/status` | `GET` | None | `{ devices_online, threats_detected, honeypots_active, network_status, pending_approvals }` | Optional | SOC overview card metrics |
| `/api/traffic` | `GET` | `?limit=15` | `[ { time, source, destination, protocol, size } ]` | Optional | Live packet stream feed |
| `/api/threats` | `GET` | `?status=active` | `[ { id, time, ip, type, target, severity, risk_score, mitre } ]` | Optional | Threat feed and distribution |
| `/api/honeypots` | `GET` | None | `[ { id, service, port, status, attacker_ip, interactions, last_trigger } ]` | Optional | Active deception traps |
| `/api/honeypots/interact` | `POST` | `{ honeypot_code, attacker_ip, payload }` | `{ status, trap }` | Admin | Simulates / captures decoy probe |
| `/api/logs` | `GET` | `?limit=40` | `[ { id, timestamp, event_type, message, status, action, target, command_id } ]` | Optional | AI terminal activity log |
| `/api/decisions` | `GET` | `?status=needs_approval` | `[ { id, time, action, target, risk_score, reason, status } ]` | Optional | Pending security decisions |
| `/api/decisions/{id}/approve` | `POST` | None | `{ status: "approved", enforcement: { command_id, outcome } }` | Admin | Cryptographically signs & enforces action |
| `/api/decisions/{id}/deny` | `POST` | `{ reason }` | `{ status: "denied" }` | Admin | Operator overrides & rejects action |
| `/api/telemetry/flow` | `POST` | `{ ts, src_ip, dst_ip, dst_port, proto, bytes_out, packets }` | `{ status, result }` | Ingest | Collector network flow ingest |
| `/api/telemetry/dns` | `POST` | `{ ts, src_ip, qname, qtype }` | `{ status, result }` | Ingest | Collector DNS query ingest |
| `/api/telemetry/device` | `POST` | `{ ts, mac, ip, hostname }` | `{ status, result }` | Ingest | Collector device discovery ingest |
| `/api/enforcement/rules` | `GET` | None | `[ { id, action, ip, created_at, expires_at, status } ]` | Optional | Active local firewall rules |
| `/api/policy` | `GET` / `PUT` | Policy fields | Current policy config | Admin (PUT) | Get / update autonomy policies |
| `/ws/dashboard` | `WebSocket` | None | Streaming `{ type: "status_update", data }` | None | Real-time live status push |

---

## 5. Repository Structure

```
SentinelShield/
├── app/                               # Core SentinelShield Backend & Security Engine
│   ├── core/                          # Telemetry models & data structures
│   │   ├── __init__.py
│   │   └── telemetry.py               # FlowEvent, DnsEvent, DeviceEvent dataclasses
│   ├── detection/                     # Pure detection algorithms
│   │   ├── __init__.py
│   │   └── detectors.py               # 6 algorithmic detectors & Shannon entropy
│   ├── orchestration/                 # Risk scoring & policy decision engine
│   │   ├── __init__.py
│   │   └── decision.py                # Noisy-OR scoring, policy validation, proposal clamps
│   ├── security/                      # Cryptographic signing & verification
│   │   ├── __init__.py
│   │   └── commands.py                # Ed25519 CommandSigner & CommandVerifier
│   ├── enforcement/                   # Local enforcement agent
│   │   ├── __init__.py
│   │   └── agent.py                   # EnforcementAgent, DryRunBackend, NftBackend
│   ├── services/                      # High-level backend platform services
│   │   ├── security_engine.py         # Ingestion, pipeline orchestration & approvals
│   │   ├── honeypot_service.py        # Deception traps and attacker simulation
│   │   ├── telemetry_generator.py     # Background collector stream simulator
│   │   └── auth.py                    # Role-based API key & token authorization
│   ├── database.py                    # Unified SQLAlchemy persistence layer
│   └── __init__.py
│
├── fastapi_backend/                   # FastAPI Cloud Control Plane
│   ├── modules/                       # Service bridges (zero duplicate code)
│   │   ├── ai_decision.py
│   │   ├── honeypot_controller.py
│   │   ├── packet_sniffer.py
│   │   └── threat_detector.py
│   ├── api.py                         # FastAPI REST & WebSocket endpoints
│   └── __init__.py
│
├── flask_app/                         # Existing SOC Dashboard Frontend (Design Preserved)
│   ├── backend/                       # Legacy compatibility models
│   │   ├── database.py
│   │   ├── init_db.py
│   │   └── models.py                  # Bridges to app.database
│   ├── static/                        # CSS, Fonts, Images & Client JavaScript
│   │   ├── css/
│   │   │   ├── home.css
│   │   │   └── styles.css             # Established SOC design system
│   │   ├── js/
│   │   │   ├── api_client.js          # Centralized API client & WebSocket manager
│   │   │   ├── dashboard.js           # Live status counters & volume charts
│   │   │   ├── traffic.js             # Packet stream monitor
│   │   │   ├── threats.js             # MITRE threat feed & distribution
│   │   │   ├── honeypots.js           # Deception grid with interactive probe
│   │   │   └── agent_logs.js          # Terminal log & 1-click human approval
│   │   └── images/
│   │       └── logo.png
│   ├── templates/                     # Jinja2 HTML Templates
│   │   ├── base.html                  # Sidebar, topbar, clock, theme layout
│   │   ├── home.html                  # Particle shield landing page
│   │   ├── dashboard.html             # Overview cards & charts
│   │   ├── traffic.html               # Network packet stream
│   │   ├── threats.html               # Threat intelligence
│   │   ├── honeypots.html             # Honeypot deception manager
│   │   ├── agent_logs.html            # Autonomous decision audit trail
│   │   └── logo.html                  # Splash entry
│   └── app.py                         # Flask application & reverse proxy
│
├── tests/                             # Comprehensive Automated Test Suites
│   ├── test_core.py                   # 26 unit tests for core algorithms & crypto
│   └── test_integration.py            # 7 E2E tests for API, DB, pipeline & UI
│
├── run.py                             # Parallel runner for FastAPI + Flask
├── requirements.txt                   # Production dependencies
├── Dockerfile                         # Container build definition
└── README.md                          # Platform documentation
```

---

## 6. Installation & Setup

### Prerequisites
* Python 3.11, 3.12, or 3.13
* Git

### Step 1: Clone & Checkout Integration Branch
```bash
git clone https://github.com/Hemanth880225/sentinelshield.git
cd sentinelshield
git checkout feature/backend-frontend-integration
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables (Optional)
Defaults work out of the box using local SQLite. For production, set:
```bash
# Database URL (SQLite default: sqlite:///sentinelshield.db)
export DATABASE_URL="postgresql://user:password@localhost:5432/sentinelshield"

# FastAPI service URL for Flask reverse-proxy (default: http://127.0.0.1:8000)
export FASTAPI_URL="http://127.0.0.1:8000"

# Admin API Key for authorization
export SENTINEL_ADMIN_KEY="sentinel-admin-sec-key-v2"
```

---

## 7. Running the Integrated Application

To start both the FastAPI backend and Flask frontend in parallel:

```bash
python run.py
```

Console Output:
```
============================================================
  SentinelShield — Agentic Deception Security Platform v2.0
  'Don't Just Block Attackers — Deceive Them'
============================================================
[*] Initializing unified database and security policies...
[*] Starting FastAPI Backend on http://0.0.0.0:8000 ...
[*] Starting Flask SOC Dashboard on http://0.0.0.0:5000 ...
[+] All SentinelShield services running:
    - Web Dashboard:     http://localhost:5000
    - FastAPI Swagger:   http://localhost:8000/docs
    - Real-Time WS:      ws://localhost:8000/ws/dashboard
============================================================
```

### Service Access Points
* **SOC Web Dashboard**: Open [http://localhost:5000/dashboard](http://localhost:5000/dashboard) in your browser.
* **Interactive Threat Intel**: [http://localhost:5000/threats](http://localhost:5000/threats)
* **Live Traffic Monitor**: [http://localhost:5000/traffic](http://localhost:5000/traffic)
* **Honeypot Deception Center**: [http://localhost:5000/honeypots](http://localhost:5000/honeypots)
* **Agent Decision Logs & Approvals**: [http://localhost:5000/agent_logs](http://localhost:5000/agent_logs)
* **FastAPI Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 8. Verification & Automated Testing

SentinelShield features a comprehensive test suite covering detection math, cryptographic guarantees, API contracts, and user experience routes:

To run all 33 unit and integration tests:

```bash
python -m unittest discover -s tests -t .
```

Expected Output:
```
.................................
----------------------------------------------------------------------
Ran 33 tests in 4.806s

OK
```

### Test Coverage Highlights:
1. **`tests/test_core.py` (26 tests)**:
   * Validation of `FlowEvent`, `DnsEvent`, and `DeviceEvent` dataclasses.
   * Accuracy of port scan, brute force, beaconing, DNS tunneling, exfiltration, and unknown device detectors.
   * Noisy-OR risk scoring calculation and policy threshold evaluation.
   * LLM proposal validation and TTL clamping.
   * Ed25519 cryptographic signature verification, replay protection, and expiration containment.
   * Local enforcement agent rule application, fail-safe rule expiry without cloud connectivity, and injection-safe argv construction.
2. **`tests/test_integration.py` (7 tests)**:
   * Telemetry-to-enforcement automated pipeline execution.
   * Human-in-the-loop decision approval via `POST /api/decisions/{id}/approve`.
   * Honeypot probe interaction and real-time deception reaction.
   * FastAPI REST endpoints schema validation.
   * Flask templates rendering with brand preservation.
   * Flask-to-FastAPI reverse-proxy and fallback.

---

## 9. Troubleshooting & FAQ

* **Port 5000 or 8000 Already in Use**:
  If another process is bound to port 5000 or 8000, stop the competing service or customize the ports in `run.py`.
* **CORS Errors When Calling FastAPI Directly**:
  FastAPI has `CORSMiddleware` configured to allow `*`. Alternatively, access all APIs through the Flask origin (`http://localhost:5000/api/...`) which transparently proxies to FastAPI with zero CORS friction.
* **Database Reset**:
  To reset the database to a fresh state with default seed policies, devices, and honeypots, delete `sentinelshield.db`. A fresh database is created and seeded automatically on startup.
* **Firewall Driver Configuration**:
  By default, `DryRunBackend` is enabled so the platform runs smoothly on any OS (Windows, macOS, Linux) without requiring root/sudo privileges. In Linux production environments with nftables installed, instantiate `NftBackend` to directly apply kernel firewall sets.

---

## 10. License

SentinelShield Engineering Team — Proprietary Hackathon & Startup Security Platform.
All rights reserved.
