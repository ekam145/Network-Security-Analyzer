"""
app.py — Flask Thin Controller (Routes ONLY)
All business logic is delegated to detection.py, response.py, db.py.
"""
import os
import sys
from datetime import datetime

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv
import io

# Load environment FIRST — validate API key presence on startup
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)

# Validate on startup — fail loudly if key is missing
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    print("\n" + "="*60)
    print("  CRITICAL: GROQ_API_KEY not found in backend/.env")
    print("  Edit outputs/backend/.env and add your free Groq key")
    print("  Get one free at: https://console.groq.com/keys")
    print("="*60 + "\n")

# Import backend modules
sys.path.insert(0, os.path.dirname(__file__))
import db
from detection import run_full_detection
from response import generate_defense_script, get_recommendations
from models.anomaly_detector import load_model

app = Flask(__name__)
CORS(app)

# Initialize DB and load ML model once at startup
db.init_db()
print("[SOC] Initializing ML Anomaly Detection Model...")
ML_MODEL = load_model()
print(f"[SOC] Backend fully operational. API Key: {'[OK] Loaded' if GROQ_API_KEY else '[X] MISSING'}")

# ─── 1. Batch Analysis (Upload/Paste entire log block) ───────────────────────
@app.route('/api/analyze', methods=['POST'])
def analyze_batch():
    data = request.json
    if not data or 'logs' not in data:
        return jsonify({"error": "No log data provided."}), 400

    log_text = data['logs'].strip()
    if len(log_text) < 10:
        return jsonify({"error": "Log content too short for analysis."}), 400

    try:
        # Full 3-layer hybrid detection
        report = run_full_detection(log_text, ML_MODEL)

        attacker_ip  = report.get("attacker_ip", "")
        top_severity = report.get("overall_threat_level", "LOW")
        top_threat   = report["threats"][0]["type"] if report["threats"] else "Unknown"

        defense_script  = generate_defense_script(attacker_ip, top_severity, top_threat)
        recommendations = get_recommendations(top_severity, report.get("threats", []))

        report["defense_script"]    = defense_script
        report["recommendations"]   = recommendations

        # ── Progressive Timestamps: use real timestamps from log lines ──
        # Each alert gets the timestamp of the log line that triggered it,
        # giving the Timeline a realistic time-spread instead of identical times.
        log_timestamps = report.get("log_timestamps", [])

        # Store raw log block summary (use first log timestamp if available)
        raw_ts = log_timestamps[0] if log_timestamps else datetime.utcnow().isoformat()
        db.store_raw_log(
            timestamp=raw_ts,
            source_ip=attacker_ip or "multiple",
            log_line=log_text[:500],
            port=None,
            protocol=None
        )

        # Store each detected alert with its own progressive timestamp
        threats = report.get("threats", [])
        for i, threat in enumerate(threats):
            # Assign a different log timestamp to each threat if available
            if i < len(log_timestamps):
                alert_ts = log_timestamps[i]
            else:
                # Fallback: space alerts 60s apart from last known ts
                base = datetime.fromisoformat(log_timestamps[-1]) if log_timestamps else datetime.utcnow()
                from datetime import timedelta
                alert_ts = (base + timedelta(seconds=60 * (i - len(log_timestamps) + 1))).isoformat()

            db.store_alert(
                timestamp=alert_ts,
                attacker_ip=attacker_ip,
                threat_type=threat.get("type", "Unknown"),
                severity=threat.get("severity", "LOW"),
                ml_score=report["ml_analysis"]["max_anomaly_score"],
                groq_verdict=report.get("threat_summary", ""),
                evidence=threat.get("evidence", "")[:500],
                recommendation="; ".join(recommendations[:2]),
                defense_script=defense_script
            )

        return jsonify({"status": "success", "report": report})

    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# ─── 2. Line-by-line Streaming Ingestion ─────────────────────────────────────
@app.route('/api/ingest', methods=['POST'])
def ingest_line():
    data = request.json
    if not data or 'log_line' not in data:
        return jsonify({"error": "No log_line provided."}), 400
    
    line = data['log_line'].strip()
    now  = datetime.utcnow().isoformat()
    
    # Quick rule-based check on this single line
    from detection import rule_based_scan, extract_attacker_ip
    hits = rule_based_scan(line)
    
    # Store raw log
    db.store_raw_log(
        timestamp=now,
        source_ip=extract_attacker_ip(line) or "unknown",
        log_line=line,
        port=None,
        protocol=None
    )
    
    threat_detected = len(hits) > 0
    if threat_detected:
        for h in hits:
            db.store_alert(
                timestamp=now,
                attacker_ip=extract_attacker_ip(line),
                threat_type=h["type"],
                severity=h["severity"],
                ml_score=None,
                groq_verdict="Rule-engine detection (streaming mode)",
                evidence=line[:500],
                recommendation="",
                defense_script=""
            )
    
    return jsonify({
        "status": "ok",
        "log_stored": True,
        "threat_detected": threat_detected,
        "detections": hits
    })

# ─── 3. History / Database Views ─────────────────────────────────────────────
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity_filter = request.args.get('severity')
    alerts = db.get_all_alerts(limit=100)
    if severity_filter:
        alerts = [a for a in alerts if a['severity'] == severity_filter.upper()]
    return jsonify({"alerts": alerts})

@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    return jsonify({"timeline": db.get_timeline()})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(db.get_stats())

@app.route('/api/logs', methods=['GET'])
def get_raw_logs():
    return jsonify({"logs": db.get_all_raw_logs(limit=200)})

# ─── 4. Download Firewall Script ──────────────────────────────────────────────
@app.route('/api/download-script', methods=['POST'])
def download_script():
    data = request.json
    script = data.get("script", "")
    filename = data.get("filename", "soc_firewall_response.sh")
    
    script_bytes = script.encode("utf-8")
    return send_file(
        io.BytesIO(script_bytes),
        mimetype="text/x-shellscript",
        as_attachment=True,
        download_name=filename
    )

# ─── 5. Health Check ─────────────────────────────────────────────────────────
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "operational",
        "groq_key_loaded": bool(GROQ_API_KEY),
        "ml_model": "IsolationForest (active)",
        "database": "SQLite (raw_logs + alerts)"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
