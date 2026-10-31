# SentinelShield

**Agentic AI-Powered Deception Security Platform for Startups**  
*“Don't Just Block Attackers — Deceive Them”*  
Version: 2.0 (Cloud-Native Architecture Edition — Production Hardened)

---

## 1. Executive Summary

SentinelShield is an autonomous network security platform engineered specifically for startups, developer labs, and IoT-enabled environments that lack dedicated cybersecurity operations teams. 

Unlike traditional passive monitoring systems that merely log events, SentinelShield is **agentic**: it actively monitors network telemetry, correlates risks using statistical and AI-driven models, autonomously decides defensive countermeasures, signs cryptographic security commands using Ed25519, and orchestrates local enforcement and dynamic deception traps in real time.

This repository integrates the SOC dashboard frontend with the high-performance Python/FastAPI backend, persistent Ed25519 command signing, multi-tenant isolation, Role-Based Access Control (RBAC), and cryptographic local enforcement.

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
                          | (Collector Token Auth)                    |                   |
                          v                                           |                   |
+---------------------------------------------------------------------|-------------------+
|                            SENTINELSHIELD CONTROL PLANE             |                   |
|                                                                     |                   |
|   +-------------------------------------------------------------+   |                   |
|   |                     FastAPI Backend (:8000)                 |   |                   |
|   |  - Role-Based Access Control (Admin, Analyst, Viewer, Col)  |   |                   |
|   |  - Strict Configurable CORS & Authenticated WebSockets      |   |                   |
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
|   |            Persistent Ed25519 Command Signer (Cloud)        +---+                   |
|   |  - Durable replay protection    - Short TTL expiry          |                       |
|   |  - Persistent PEM keypair       - Nonce deduplication       |                       |
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
|   |                  Unified Multi-Tenant Persistence           |                       |
|   |           SQLite (default) / PostgreSQL (enterprise)        |                       |
|   |           Auto-migrating schema with tenant_id isolation    |                       |
|   +------------------------------+------------------------------+                       |
+----------------------------------|------------------------------------------------------+
                                   | HTTP / WebSocket
                                   v
+-----------------------------------------------------------------------------------------+
|                                SOC DASHBOARD FRONTEND                                   |
|                                                                                         |
|   +-------------------------------------------------------------+                       |
|   |                   Flask Web Server (:5000)                  |                       |
|   |  - Preserved SOC Visual Theme  - Authenticated Reverse Proxy|                       |
|   +------------------------------+------------------------------+                       |
|                                  |                                                      |
|                                  v                                                      |
|   +-------------------------------------------------------------+                       |
|   |             Hardened JS API Client & XSS Sanitization       |                       |
|   |  - DOM XSS Sanitization on all tables, cards & badges       |                       |
|   |  - Live Counters & Donut/Line Charts                        |                       |
|   |  - Real-Time Packet Stream & MITRE Threat Intel             |                       |
|   |  - Interactive Deception Trap Probe Simulation              |                       |
|   |  - Human-in-the-Loop Action Approval (1-Click Enforce)      |                       |
|   +-------------------------------------------------------------+                       |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Security Hardening & Controls

SentinelShield v2.0 implements production-grade security across every layer:

### 1. Role-Based Access Control (RBAC) & Constant-Time Auth
- **No Hardcoded Credentials**: Passwords and secrets have been removed from source code and client scripts.
- **Constant-Time Verification**: API tokens are evaluated using `hmac.compare_digest` to prevent timing attacks.
- **Defined RBAC Roles**:
  - `admin`: Full administrative control (policy modification, action approvals/denials, trap deployment, simulation).
  - `analyst`: Read access across all telemetry, ability to trigger honeypot interactions.
  - `viewer`: Read-only dashboard access.
  - `collector`: Telemetry ingestion only (`/api/telemetry/*`); denied access to administrative and query endpoints.

### 2. Persistent Cryptographic Command Pipeline
- **Persistent Ed25519 Keypair**: Saved securely to `sentinel_signing_key.pem` or loaded from `SENTINEL_ED25519_PRIVATE_KEY_PEM`. Survives container and process restarts without invalidating previously verified agents.
- **Durable Replay Protection**: Verifier checks both memory nonce cache and database audit history (`EnforcementAuditModel`) to prevent command replay attacks across reboots.

### 3. Multi-Tenant Data Isolation
- All database models (`DeviceModel`, `TrafficFlowModel`, `DnsRecordModel`, `ThreatFindingModel`, `AgentDecisionModel`, `EnforcementRuleModel`, `EnforcementAuditModel`, `HoneypotModel`, `SystemPolicyModel`) include indexed `tenant_id` fields.
- Queries across the control plane and API are strictly scoped to the authenticated tenant.

### 4. DOM XSS Remediation
- Frontend client scripts (`dashboard.js`, `threats.js`, `honeypots.js`, `agent_logs.js`, `traffic.js`) sanitize all network IPs, hostnames, MITRE tags, and payload strings with `SentinelAPI.escapeHTML()`, while 100% preserving the existing design, styling, and animations.

### 5. Strict CORS & Authenticated WebSockets
- CORS is restricted to explicitly configured trusted origins (configurable via `CORS_ORIGINS`).
- Real-time WebSockets (`/ws/dashboard`) require token authentication on connect and validate origins against allowed origins.

---

## 4. API Communication Contracts

| Route | Method | Payload / Query | Auth Role | Description |
|---|---|---|---|---|
| `/api/status` | `GET` | None | Read (`viewer`+) | SOC overview card metrics |
| `/api/traffic` | `GET` | `?limit=15` | Read (`viewer`+) | Live packet stream feed |
| `/api/threats` | `GET` | `?status=active` | Read (`viewer`+) | Threat feed and distribution |
| `/api/threats/summary` | `GET` | None | Read (`viewer`+) | Aggregated threat counts & types |
| `/api/honeypots` | `GET` | None | Read (`viewer`+) | Active deception traps |
| `/api/honeypots/interact` | `POST` | `{ honeypot_code, attacker_ip, payload }` | `analyst`, `admin` | Simulates / captures decoy probe |
| `/api/honeypots/deploy` | `POST` | `{ service, port }` | `admin` | Deploys new deception trap |
| `/api/logs` | `GET` | `?limit=40` | Read (`viewer`+) | AI terminal activity log |
| `/api/decisions` | `GET` | `?status=needs_approval` | Read (`viewer`+) | Pending security decisions |
| `/api/decisions/{id}/approve` | `POST` | None | `admin` | Cryptographically signs & enforces action |
| `/api/decisions/{id}/deny` | `POST` | `{ reason }` | `admin` | Operator overrides & rejects action |
| `/api/telemetry/flow` | `POST` | `{ ts, src_ip, dst_ip, dst_port, proto, ... }` | `collector`, `admin` | Collector network flow ingest |
| `/api/telemetry/dns` | `POST` | `{ ts, src_ip, qname, qtype }` | `collector`, `admin` | Collector DNS query ingest |
| `/api/telemetry/device` | `POST` | `{ ts, mac, ip, hostname }` | `collector`, `admin` | Collector device discovery ingest |
| `/api/telemetry/simulate_attack` | `POST` | `{ attack_type }` | `admin` | Injects test attack trace |
| `/api/enforcement/rules` | `GET` | None | Read (`viewer`+) | Active local firewall rules |
| `/api/enforcement/audit` | `GET` | `?limit=30` | Read (`viewer`+) | Cryptographic command audit trail |
| `/api/policy` | `GET` / `PUT` | Policy fields | `admin` (PUT) | Get / update autonomy policies |
| `/ws/dashboard` | `WebSocket` | `?token=<key>` | Authenticated | Real-time live status push |

---

## 5. Configuration & Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///sentinelshield.db` | Persistence backend (SQLite or PostgreSQL) |
| `FASTAPI_URL` | `http://127.0.0.1:8000` | FastAPI control plane location for Flask proxy |
| `SENTINEL_ADMIN_KEY` | Auto-generated in `sentinel_keys.env` | Master administrative API key |
| `SENTINEL_ANALYST_KEY` | Auto-generated in `sentinel_keys.env` | Security analyst API key |
| `SENTINEL_VIEWER_KEY` | Auto-generated in `sentinel_keys.env` | Read-only viewer API key |
| `SENTINEL_COLLECTOR_TOKEN` | Auto-generated in `sentinel_keys.env` | Collector telemetry ingestion token |
| `SENTINEL_SIGNING_KEY_PATH` | `sentinel_signing_key.pem` | Path to persistent Ed25519 signing key |
| `SENTINEL_SIMULATOR_ENABLED` | `false` | Enable background telemetry generator |
| `CORS_ORIGINS` | `http://localhost:5000,http://localhost:8000` | Comma-separated list of allowed origins |

---

## 6. Installation & Quick Start

### Option A: Local Development Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start both Flask SOC Dashboard and FastAPI Control Plane
python run.py
```

### Option B: Docker Compose

```bash
docker compose up --build
```

Services will be available at:
* **SOC Web Dashboard**: [http://localhost:5000/dashboard](http://localhost:5000/dashboard)
* **Live Traffic Monitor**: [http://localhost:5000/traffic](http://localhost:5000/traffic)
* **Threat Intelligence**: [http://localhost:5000/threats](http://localhost:5000/threats)
* **Honeypot Deception Center**: [http://localhost:5000/honeypots](http://localhost:5000/honeypots)
* **Agent Decision Logs & Approvals**: [http://localhost:5000/agent_logs](http://localhost:5000/agent_logs)
* **FastAPI Swagger API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 7. Verification & Automated Testing

SentinelShield features 43 automated unit, integration, and security hardening tests with 100% pass rate:

```bash
python -m pytest tests/ -v
```

Output:
```
============================= test session starts =============================
tests/test_core.py ..........................                            [ 60%]
tests/test_integration.py .......                                       [ 76%]
tests/test_security_hardening.py ..........                             [100%]
============================= 43 passed in 13.11s =============================
```

### Test Suite Structure:
1. **`tests/test_core.py` (26 tests)**:
   - Validates all 6 statistical detectors (port scan, brute force, C2 beaconing, DNS tunnel, exfiltration, unknown device).
   - Verifies Noisy-OR probability math, proposal validation, and policy decision engine.
   - Tests Ed25519 command signing, tampering rejection, and expiry without cloud connectivity.
2. **`tests/test_integration.py` (7 tests)**:
   - Tests complete end-to-end telemetry ingestion to signed firewall rule execution.
   - Validates human-in-the-loop authorization workflow (`approve_decision`).
   - Verifies honeypot interaction, FastAPI REST endpoints, and Flask proxy.
3. **`tests/test_security_hardening.py` (10 tests)**:
   - Verifies unauthenticated API calls return HTTP 401.
   - Validates RBAC permissions for `admin`, `analyst`, `viewer`, and `collector` roles.
   - Tests persistent Ed25519 key loading across reloads.
   - Confirms durable command replay protection and multi-tenant data isolation.
   - Verifies strict honeypot validation and production simulator safety posture.

---

## 8. License

SentinelShield Engineering Team — Proprietary Startup & Cloud Security Platform. All rights reserved.
