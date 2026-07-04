"""
models/anomaly_detector.py — IsolationForest ML model for anomaly detection.
Trains on synthetic "normal" traffic and flags statistical outliers.
Saves/loads from anomaly_model.pkl for persistence.
"""
import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "anomaly_model.pkl")

def _generate_normal_traffic(n=600):
    """
    Creates synthetic 'normal' network feature vectors for training.
    Features: [port, bytes_transferred, hour_of_day, is_internal_src, protocol_num]
    """
    np.random.seed(42)
    # Normal web traffic: ports 80/443, reasonable bytes, business hours
    ports      = np.random.choice([80, 443, 8080, 3306, 22], n,
                                   p=[0.4, 0.35, 0.1, 0.1, 0.05])
    bytes_tx   = np.random.normal(50_000, 10_000, n).clip(min=100)
    hour       = np.random.normal(12, 3, n).clip(0, 23)
    is_internal = np.random.choice([1, 0], n, p=[0.85, 0.15])
    protocol   = np.random.choice([0, 1, 2], n, p=[0.7, 0.25, 0.05])  # TCP, UDP, ICMP
    return np.column_stack([ports, bytes_tx, hour, is_internal, protocol])

def train_and_save():
    """Train IsolationForest on normal traffic and persist it."""
    X = _generate_normal_traffic(600)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"[ML] IsolationForest trained on 600 samples. Saved -> {MODEL_PATH}")
    return model

def load_model():
    """Load saved model or train a fresh one if not found."""
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    print("[ML] No saved model found. Training fresh IsolationForest...")
    return train_and_save()

def extract_features(log_line: str) -> np.ndarray:
    """
    Extract numeric features from a raw log text line.
    Returns a (1,5) feature vector.
    """
    import re

    port = 80
    port_match = re.search(r'port[=:\s]+(\d+)', log_line, re.IGNORECASE)
    if port_match:
        port = int(port_match.group(1))

    # Estimate bytes from transfer size hint in message
    bytes_tx = 50_000
    if "4.5GB" in log_line or "exfil" in log_line.lower():
        bytes_tx = 5_000_000_000
    elif "large" in log_line.lower():
        bytes_tx = 500_000_000

    # Extract hour from timestamp e.g. [2024-05-16 14:02:11]
    hour = 12
    ts_match = re.search(r'\d{4}-\d{2}-\d{2}\s+(\d{2}):', log_line)
    if ts_match:
        hour = int(ts_match.group(1))

    # Is source internal (10.x.x.x or 192.168.x.x)?
    src_match = re.search(r'src_ip[=:\s]+(\d+\.\d+)', log_line)
    is_internal = 1
    if src_match:
        prefix = src_match.group(1)
        is_internal = 1 if (prefix.startswith("10.") or prefix.startswith("192.")) else 0

    # Protocol
    protocol_map = {"tcp": 0, "udp": 1, "icmp": 2}
    protocol = 0
    proto_match = re.search(r'protocol[=:\s]+(\w+)', log_line, re.IGNORECASE)
    if proto_match:
        protocol = protocol_map.get(proto_match.group(1).lower(), 0)

    return np.array([[port, bytes_tx, hour, is_internal, protocol]])

def predict_anomaly(log_line: str, model) -> dict:
    """
    Returns anomaly verdict and score for a single log line.
    IsolationForest: -1 = anomaly, 1 = normal
    Score closer to -1 = more anomalous
    """
    features = extract_features(log_line)
    prediction = model.predict(features)[0]      # -1 or 1
    raw_score  = model.score_samples(features)[0] # negative float

    # Normalize to 0-1 range (0=normal, 1=very anomalous)
    anomaly_score = max(0.0, min(1.0, 1.0 - (raw_score + 0.5) / 0.5))

    return {
        "is_anomaly": prediction == -1,
        "anomaly_score": round(anomaly_score, 3),
        "raw_score": round(float(raw_score), 4)
    }
