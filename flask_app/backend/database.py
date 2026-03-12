"""
SentinelShield — SQLite Database Module
Handles connection, schema creation, and initialization.
"""

import sqlite3
import os

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
DB_PATH = os.path.join(DB_DIR, 'sentinelshield.db')

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


def get_connection():
    """Return a new SQLite connection with row_factory set."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the database directory, tables, and seed data if the DB is new."""
    os.makedirs(DB_DIR, exist_ok=True)

    is_new = not os.path.exists(DB_PATH)

    conn = get_connection()
    conn.executescript(SCHEMA_SQL)
    conn.commit()

    # Seed sample data only if fresh database
    if is_new or _is_empty(conn):
        from flask_app.backend.init_db import seed_data
        seed_data(conn)

    conn.close()


def _is_empty(conn):
    """Check if all tables are empty."""
    cursor = conn.execute("SELECT COUNT(*) FROM devices")
    return cursor.fetchone()[0] == 0
