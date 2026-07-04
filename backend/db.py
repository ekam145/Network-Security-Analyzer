"""
db.py — All SQLite database operations for the SOC system.
Two tables:
  - raw_logs: Every ingested log line
  - alerts:   Detected threats with full intelligence report
"""
import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "soc_database.db")

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    # Table 1: Every raw log line ingested
    c.execute("""
    CREATE TABLE IF NOT EXISTS raw_logs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        log_line  TEXT NOT NULL,
        port      INTEGER,
        protocol  TEXT
    )""")
    
    # Table 2: Detected threat alerts
    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       TEXT NOT NULL,
        attacker_ip     TEXT,
        threat_type     TEXT NOT NULL,
        severity        TEXT NOT NULL,
        ml_score        REAL,
        groq_verdict    TEXT,
        evidence        TEXT,
        recommendation  TEXT,
        defense_script  TEXT
    )""")
    
    # Optimized indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_ts          ON raw_logs(timestamp)")
    conn.commit()
    conn.close()
    print("[DB] Database initialized with raw_logs + alerts tables.")

def store_raw_log(timestamp, source_ip, log_line, port, protocol):
    conn = get_connection()
    conn.execute("""
        INSERT INTO raw_logs (timestamp, source_ip, log_line, port, protocol)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, source_ip, log_line, port, protocol))
    conn.commit()
    conn.close()

def store_alert(timestamp, attacker_ip, threat_type, severity, ml_score,
                groq_verdict, evidence, recommendation, defense_script):
    conn = get_connection()
    conn.execute("""
        INSERT INTO alerts (timestamp, attacker_ip, threat_type, severity, ml_score,
                            groq_verdict, evidence, recommendation, defense_script)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, attacker_ip, threat_type, severity, ml_score,
          groq_verdict, evidence, recommendation, defense_script))
    conn.commit()
    conn.close()

def get_all_alerts(limit=100):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_raw_logs(limit=200):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM raw_logs ORDER BY timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_timeline():
    """Returns alerts sorted ascending by timestamp for Timeline view."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT timestamp, threat_type, severity, attacker_ip
        FROM alerts ORDER BY timestamp ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats():
    """Aggregated stats for the Analytics dashboard."""
    conn = get_connection()
    c = conn.cursor()
    severity_counts = dict(c.execute(
        "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
    ).fetchall())
    threat_counts = dict(c.execute(
        "SELECT threat_type, COUNT(*) FROM alerts GROUP BY threat_type"
    ).fetchall())
    total_logs = c.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]
    conn.close()
    return {
        "severity_counts": severity_counts,
        "threat_counts": threat_counts,
        "total_logs": total_logs
    }
