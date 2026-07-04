"""
detection.py — Hybrid threat detection engine.
Stage 1: Rule-based regex patterns catch known threat signatures instantly.
Stage 2: IsolationForest ML flags statistical outliers in traffic behavior.
Stage 3: Groq LLM provides semantic understanding and human-readable context.
Final verdict = combination of all three layers.

Includes:
- Standardized threat taxonomy (NIST/MITRE-aligned naming)
- MITRE ATT&CK framework mapping per threat
- Progressive timestamp extraction from log lines
- Attack Correlation Summary (XDR-style narrative)
"""
import re
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)

# ─── MITRE ATT&CK Mapping ────────────────────────────────────────────────────
MITRE_MAPPING = {
    "SQL Injection":       {"id": "T1190", "tactic": "Initial Access",    "name": "Exploit Public-Facing Application"},
    "SSH Brute Force":     {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
    "C2 Communication":    {"id": "T1071", "tactic": "Command & Control", "name": "Application Layer Protocol"},
    "Data Exfiltration":   {"id": "T1041", "tactic": "Exfiltration",      "name": "Exfiltration Over C2 Channel"},
    "Port Scanning":       {"id": "T1046", "tactic": "Discovery",         "name": "Network Service Discovery"},
    "Privilege Escalation":{"id": "T1078", "tactic": "Privilege Escalation","name": "Valid Accounts"},
}

# ─── Standardized Threat Signatures ──────────────────────────────────────────
THREAT_SIGNATURES = [
    {
        "name": "SQL Injection",          # Standardized name
        "severity": "CRITICAL",
        "description": "Malicious SQL payloads are being injected into HTTP requests to manipulate backend databases, potentially leading to unauthorized data access or destruction.",
        "kill_chain_phase": "Exploitation",
        "patterns": [
            r"(sqlmap|sql\s*injection)",
            r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
            r"(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO)",
            r"payload=.*(?:OR|AND).*=",
        ]
    },
    {
        "name": "SSH Brute Force",        # Standardized name
        "severity": "HIGH",
        "description": "Repeated failed SSH authentication attempts from a single source IP indicate an automated credential stuffing or brute force attack targeting remote access services.",
        "kill_chain_phase": "Credential Access",
        "patterns": [
            r"Failed\s+(?:SSH\s+)?(?:login|password|publickey)\s+(?:attempt|for)",
            r"Invalid\s+user\s+\w+\s+from",
            r"authentication\s+failure.*ssh",
        ]
    },
    {
        "name": "C2 Communication",       # Standardized (was "Command & Control (C2)")
        "severity": "CRITICAL",
        "description": "A compromised internal host is communicating with a known malicious external domain, indicating active malware beaconing or command-and-control channel establishment.",
        "kill_chain_phase": "Command & Control",
        "patterns": [
            r"(evildom|c2server|callhome|beaconing|malware-c2)",
            r"req=\"[^\"]*\.(xyz|tk|pw|top|cc)\"",
            r"(dns\s+tunneling|dnscat|iodine)",
        ]
    },
    {
        "name": "Data Exfiltration",      # Standardized name
        "severity": "HIGH",
        "description": "An unusually large volume of data is being transferred outbound to an external IP address, suggesting sensitive organizational data may be leaving the network without authorization.",
        "kill_chain_phase": "Exfiltration",
        "patterns": [
            r"(Large\s+outbound\s+data\s+transfer|exfil)",
            r"bytes[_\s]*(?:sent|out)[=:\s]+([5-9]\d{6,}|\d{8,})",
            r"upload.*\b(\d+\.?\d*\s*[GT]B)",
        ]
    },
    {
        "name": "Port Scanning",          # Standardized name
        "severity": "MEDIUM",
        "description": "Systematic probing of multiple ports on target hosts has been detected, indicating active network reconnaissance by a threat actor preparing for exploitation.",
        "kill_chain_phase": "Reconnaissance",
        "patterns": [
            r"(port.?scan|nmap|masscan|zmap)",
            r"SYN_RECV.*?\bCOUNT\b[=:\s]+([5-9]\d|\d{3,})",
        ]
    },
    {
        "name": "Privilege Escalation",   # Standardized name
        "severity": "HIGH",
        "description": "Authentication as a privileged root account was accepted following multiple failures, indicating a successful lateral movement or privilege escalation event.",
        "kill_chain_phase": "Privilege Escalation",
        "patterns": [
            r"(sudo|su\b|privilege\s+escalation|setuid)",
            r"Accepted\s+publickey\s+for\s+root",
            r"(unauthorized\s+root|wheel\s+group)",
        ]
    },
]

# Kill chain ordering for correlation (lower = earlier in attack)
KILL_CHAIN_ORDER = {
    "Reconnaissance": 1,
    "Exploitation": 2,
    "Credential Access": 3,
    "Privilege Escalation": 4,
    "Command & Control": 5,
    "Exfiltration": 6,
}


def rule_based_scan(log_text: str) -> list:
    """Scan log text for all matching threat signatures. Returns list of detections."""
    detections = []
    for sig in THREAT_SIGNATURES:
        for pattern in sig["patterns"]:
            if re.search(pattern, log_text, re.IGNORECASE):
                # Find first matching evidence line
                evidence = log_text[:200]
                for line in log_text.splitlines():
                    if re.search(pattern, line, re.IGNORECASE):
                        evidence = line.strip()
                        break

                mitre = MITRE_MAPPING.get(sig["name"], {})
                detections.append({
                    "type": sig["name"],
                    "severity": sig["severity"],
                    "description": sig.get("description", "Threat pattern matched by rule engine."),
                    "kill_chain_phase": sig.get("kill_chain_phase", "Unknown"),
                    "mitre_id": mitre.get("id", ""),
                    "mitre_tactic": mitre.get("tactic", ""),
                    "mitre_name": mitre.get("name", ""),
                    "source": "rule_engine",
                    "evidence": evidence
                })
                break  # One match per signature is enough
    return detections


def extract_attacker_ip(log_text: str) -> str:
    """Extracts the first non-internal source IP from log text."""
    ips = re.findall(r'src_ip[=:\s]+([\d.]+)', log_text, re.IGNORECASE)
    for ip in ips:
        if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")):
            return ip
    return ips[0] if ips else ""


def extract_log_timestamps(log_text: str) -> list:
    """
    Extract all unique timestamps from log lines for progressive alert storage.
    Returns list of ISO strings sorted ascending.
    Falls back to spaced-out synthetic timestamps if none found.
    """
    pattern = r'\[?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]?'
    raw_ts = re.findall(pattern, log_text)
    parsed = []
    for ts in raw_ts:
        try:
            parsed.append(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            pass
    return sorted(set(parsed)) if parsed else []


def build_correlation_summary(threats: list, attacker_ip: str) -> dict:
    """
    Generates an XDR-style Attack Correlation Summary.
    Identifies multi-stage attack chains and confidence levels.
    """
    if not threats:
        return {}

    # Sort by kill-chain phase order
    sorted_threats = sorted(threats, key=lambda t: KILL_CHAIN_ORDER.get(t.get("kill_chain_phase", ""), 99))

    # Determine confidence based on number of phases covered
    phases_covered = len({t.get("kill_chain_phase") for t in sorted_threats if t.get("kill_chain_phase")})
    if phases_covered >= 4:
        confidence = "HIGH"
        chain_label = "Multi-Stage Advanced Persistent Threat (APT)"
    elif phases_covered >= 2:
        confidence = "MEDIUM"
        chain_label = "Multi-Stage Attack Sequence"
    else:
        confidence = "LOW"
        chain_label = "Isolated Threat Event"

    # Build narrative steps
    steps = []
    for i, t in enumerate(sorted_threats, 1):
        ip_note = f"from {attacker_ip}" if attacker_ip else ""
        steps.append(f"Step {i}: **{t['type']}** {ip_note} [{t.get('kill_chain_phase','')}]")

    # MITRE techniques involved
    mitre_refs = [f"{t['mitre_id']} ({t['type']})" for t in sorted_threats if t.get("mitre_id")]

    return {
        "chain_label": chain_label,
        "confidence": confidence,
        "phases_covered": phases_covered,
        "steps": steps,
        "mitre_techniques": list(dict.fromkeys(mitre_refs)),  # deduplicated
        "attacker_ip": attacker_ip,
    }


def groq_deep_analysis(log_text: str) -> dict:
    """
    Sends suspicious log content to Groq LLM for semantic threat analysis.
    Returns structured dict with threat_level, threats, recommendations.
    """
    import json
    from groq import Groq

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return {"error": "GROQ_API_KEY not set in backend .env"}

    client = Groq(api_key=api_key)
    prompt = f"""You are a SOC analyst. Analyze these network logs for threats.
Use ONLY these standardized threat names: SQL Injection, SSH Brute Force, C2 Communication, Data Exfiltration, Port Scanning, Privilege Escalation.
Respond ONLY with valid JSON — no markdown, no explanations.

Logs:
{log_text}

JSON format:
{{
  "overall_threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "attacker_ip": "most suspicious source IP or empty string",
  "threat_summary": "one-sentence summary of what is happening",
  "threats": [
    {{
      "type": "standardized threat name from list above",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "what this threat does",
      "evidence": "specific log line"
    }}
  ],
  "recommendations": ["action 1", "action 2", "action 3"]
}}"""

    completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    raw = completion.choices[0].message.content.strip()

    if "```json" in raw:
        raw = raw.split("```json")[1].split("```")[0].strip()
    elif "```" in raw:
        raw = raw.split("```")[1].split("```")[0].strip()

    return json.loads(raw)


def run_full_detection(log_text: str, ml_model) -> dict:
    """
    Master 3-layer detection pipeline.
    Returns unified intelligence report with correlation summary + MITRE mapping.
    """
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from models.anomaly_detector import predict_anomaly

    # Layer 1: Rule Engine
    rule_hits = rule_based_scan(log_text)
    attacker_ip = extract_attacker_ip(log_text)

    # Layer 2: ML Anomaly Scoring — per-line with VARIABLE scores
    ml_results = []
    for line in log_text.splitlines():
        line = line.strip()
        if len(line) > 20:
            ml_result = predict_anomaly(line, ml_model)
            ml_result["line"] = line[:80]
            ml_results.append(ml_result)

    max_ml_score = max((r["anomaly_score"] for r in ml_results), default=0.0)
    any_ml_anomaly = any(r["is_anomaly"] for r in ml_results)
    anomaly_lines = [r for r in ml_results if r["is_anomaly"]]

    # Layer 3: Groq LLM (only if something found)
    groq_result = {}
    if rule_hits or any_ml_anomaly:
        try:
            groq_result = groq_deep_analysis(log_text)
        except Exception as e:
            groq_result = {"error": str(e)}

    # Severity verdict
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if rule_hits:
        top_severity = max(rule_hits, key=lambda x: severity_order.get(x["severity"], 0))["severity"]
    elif any_ml_anomaly:
        top_severity = "MEDIUM" if max_ml_score < 0.7 else "HIGH"
    else:
        top_severity = "LOW"

    # Merge rule + Groq threats (avoid duplicates, add MITRE to Groq hits)
    all_threats = rule_hits.copy()
    rule_types = {h["type"] for h in rule_hits}
    if "threats" in groq_result:
        for gt in groq_result["threats"]:
            if gt.get("type") not in rule_types:
                gt["source"] = "groq_llm"
                mitre = MITRE_MAPPING.get(gt.get("type", ""), {})
                gt["mitre_id"]     = mitre.get("id", "")
                gt["mitre_tactic"] = mitre.get("tactic", "")
                gt["mitre_name"]   = mitre.get("name", "")
                gt["kill_chain_phase"] = mitre.get("tactic", "")
                all_threats.append(gt)

    # Extract log timestamps for progressive storage
    log_timestamps = extract_log_timestamps(log_text)

    # Attack chain correlation
    correlation = build_correlation_summary(all_threats, attacker_ip)

    return {
        "overall_threat_level": groq_result.get("overall_threat_level", top_severity),
        "attacker_ip": groq_result.get("attacker_ip", attacker_ip),
        "threat_summary": groq_result.get("threat_summary", f"{len(rule_hits)} rule-based threats detected."),
        "threats": all_threats,
        "recommendations": groq_result.get("recommendations", []),
        "attack_correlation": correlation,
        "log_timestamps": [ts.isoformat() for ts in log_timestamps],
        "ml_analysis": {
            "max_anomaly_score": round(max_ml_score, 3),
            "anomaly_detected": any_ml_anomaly,
            "lines_scanned": len(ml_results),
            "anomaly_count": len(anomaly_lines),
            "per_line_scores": [{"line": r["line"], "score": r["anomaly_score"]} for r in ml_results if r["is_anomaly"]][:10]
        },
        "detection_layers": {
            "rule_engine": f"{len(rule_hits)} threats matched",
            "ml_isolation_forest": f"ANOMALY ({len(anomaly_lines)} lines)" if any_ml_anomaly else "NORMAL",
            "groq_llm": "ANALYZED" if groq_result and "error" not in groq_result else "SKIPPED"
        }
    }
