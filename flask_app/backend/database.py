"""
SentinelShield — SQLite Database Module
In-memory database for Vercel serverless (stateless, read-only filesystem).
Each cold start creates a fresh DB with seeded demo data.
"""

import sqlite3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS devices (
    device_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name TEXT    NOT NULL,
    ip_address  TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'online',
    last_seen   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS threats (
    threat_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip     TEXT    NOT NULL,
    target_device TEXT    NOT NULL,
    threat_type   TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS honeypots (
    honeypot_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    service          TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'Active',
    attacker_ip      TEXT,
    interactions     INTEGER NOT NULL DEFAULT 0,
    interaction_time TEXT
);

CREATE TABLE IF NOT EXISTS agent_logs (
    log_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT    NOT NULL,
    decision   TEXT    NOT NULL,
    timestamp  TEXT    NOT NULL
);
"""

# ── Module-level in-memory connection (persists within a single invocation) ──
_conn = None


def _init_memory_db():
    """Create an in-memory SQLite DB, apply schema, and seed demo data."""
    global _conn
    _conn = sqlite3.connect(":memory:", check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.executescript(SCHEMA_SQL)
    _conn.commit()

    from flask_app.backend.init_db import seed_data
    seed_data(_conn)


def get_connection():
    """Return the shared in-memory connection, initializing on first call."""
    if _conn is None:
        _init_memory_db()
    return _conn


def init_db():
    """Compatibility shim — triggers in-memory DB creation."""
    get_connection()
