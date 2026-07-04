"""
ingestion.py — Real-time log streaming simulation.
Reads a log file line-by-line with a configurable delay,
sending each line to the Flask /api/ingest endpoint.
This simulates continuous syslog ingestion from a live server.
"""
import time
import requests
import sys

BACKEND_URL = "http://127.0.0.1:5001/api/ingest"

def stream_log_file(filepath: str, delay_seconds: float = 0.5):
    """
    Streams a log file line-by-line to the backend ingestion API,
    simulating real-time log feed from a monitored server.
    
    In production, this would be replaced by:
      - Syslog UDP/TCP listener
      - Filebeat / Fluentd agent
      - Cloud CloudWatch Logs subscription
    """
    print(f"\n[INGESTION] Starting streaming from: {filepath}")
    print(f"[INGESTION] Posting each line to: {BACKEND_URL}")
    print(f"[INGESTION] Simulated delay: {delay_seconds}s per line\n")
    
    with open(filepath, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                response = requests.post(BACKEND_URL, json={"log_line": line}, timeout=10)
                status = response.json()
                print(f"[{i:03}] → {line[:80]}...")
                print(f"       Status: {status.get('status', 'unknown')} | "
                      f"Threat: {status.get('threat_detected', False)}")
            except Exception as e:
                print(f"[{i:03}] ERROR: {e}")
            
            time.sleep(delay_seconds)
    
    print("\n[INGESTION] ✅ Stream complete. All lines delivered to SOC backend.")

if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "../sample_attack_logs.txt"
    delay    = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
    stream_log_file(log_path, delay)
