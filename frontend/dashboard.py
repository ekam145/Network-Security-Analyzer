"""
dashboard.py — SOC Streamlit Frontend (Pure API Client)
Communicates exclusively with Flask backend on http://127.0.0.1:5001
No AI keys, no DB logic — purely UI + visualization.
"""
import streamlit as st
import requests
import pandas as pd
import json
import time
import os

# Use environment variable for production, fallback to local backend
API_BASE_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:5001")
API = f"{API_BASE_URL}/api"
# ─── Theme ────────────────────────────────────────────────────────────────────
def apply_theme():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;600;700;800&display=swap');
    html, body, [class*="css"] { font-family: 'Space Grotesk', sans-serif !important; }
    .stApp {
        background: #070d1a;
        background-image:
            radial-gradient(ellipse at 0% 0%, rgba(56,189,248,.07) 0%, transparent 50%),
            radial-gradient(ellipse at 100% 100%, rgba(139,92,246,.07) 0%, transparent 50%);
        color: #f1f5f9;
    }
    [data-testid="stSidebar"] {
        background: rgba(10,17,35,.97);
        border-right: 1px solid rgba(255,255,255,.05);
    }
    .metric-card {
        background: rgba(255,255,255,.04);
        border: 1px solid rgba(255,255,255,.08);
        border-radius: 12px; padding: 1.2rem 1.5rem; text-align: center;
    }
    .metric-card h2 { font-size:2.5rem; font-weight:800; margin:0; }
    .metric-card p  { color:#94a3b8; margin:0; font-size:.9rem; }
    .timeline-item {
        display:flex; align-items:flex-start; gap:14px;
        padding:.75rem 0; border-bottom:1px solid rgba(255,255,255,.05);
    }
    .tl-dot { width:12px; height:12px; border-radius:50%; margin-top:4px; flex-shrink:0; }
    .tl-CRITICAL { background:#ef4444; box-shadow:0 0 8px #ef4444; }
    .tl-HIGH     { background:#f97316; box-shadow:0 0 8px #f97316; }
    .tl-MEDIUM   { background:#eab308; box-shadow:0 0 8px #eab308; }
    .tl-LOW      { background:#22c55e; box-shadow:0 0 8px #22c55e; }
    .tl-text { flex:1; }
    .tl-time { color:#64748b; font-size:.8rem; }
    .tl-event { font-weight:600; }
    .badge-CRITICAL { background:#7f1d1d; color:#fca5a5; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:700; }
    .badge-HIGH     { background:#7c2d12; color:#fdba74; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:700; }
    .badge-MEDIUM   { background:#713f12; color:#fde047; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:700; }
    .badge-LOW      { background:#14532d; color:#86efac; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:700; }
    div.stButton > button { border-radius:10px; font-weight:700; border:none; }
    /* Fix download button white background */
    div[data-testid="stDownloadButton"] > button {
        background: linear-gradient(135deg, #1e3a5f 0%, #1e1b4b 100%) !important;
        color: #93c5fd !important;
        border: 1px solid rgba(147,197,253,.3) !important;
        border-radius: 10px !important;
        font-weight: 700 !important;
        width: 100% !important;
        padding: .65rem 1.5rem !important;
    }
    div[data-testid="stDownloadButton"] > button:hover {
        background: linear-gradient(135deg, #1e40af 0%, #312e81 100%) !important;
        border-color: rgba(147,197,253,.6) !important;
        transform: translateY(-1px);
    }
    /* Remove white gap boxes between expanders */
    [data-testid="stExpander"] {
        background: rgba(255,255,255,.03) !important;
        border: 1px solid rgba(255,255,255,.07) !important;
        border-radius: 10px !important;
        margin-bottom: 0.5rem !important;
    }
    [data-testid="stExpander"] summary {
        color: #f1f5f9 !important;
    }
    /* Remove spurious white divider blocks */
    .element-container:has([data-testid="stExpander"]) + div:empty { display: none; }
    /* ── Sidebar radio navigation: bigger & brighter ── */
    [data-testid="stSidebar"] [role="radiogroup"] label {
        font-size: 1.05rem !important;
        font-weight: 600 !important;
        color: #e2e8f0 !important;
        padding: 0.5rem 0.7rem !important;
        border-radius: 8px !important;
        transition: background .2s;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:hover {
        background: rgba(56,189,248,.12) !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label[data-checked="true"],
    [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
        background: rgba(56,189,248,.18) !important;
        color: #38bdf8 !important;
    }
    [data-testid="stSidebar"] .stRadio > label {
        font-size: 1.1rem !important;
        font-weight: 700 !important;
        color: #94a3b8 !important;
        margin-bottom: 0.3rem !important;
    }
    </style>
    """, unsafe_allow_html=True)

def badge(severity):
    return f'<span class="badge-{severity}">{severity}</span>'

def mitre_badge(mitre_id, tactic):
    if not mitre_id:
        return ""
    return (f'<span style="background:#1e293b;color:#7dd3fc;border:1px solid #334155;'
            f'padding:2px 9px;border-radius:4px;font-size:.75rem;font-weight:600;'
            f'font-family:monospace;">{mitre_id}</span> '
            f'<span style="color:#64748b;font-size:.78rem">{tactic}</span>')

def render_correlation_summary(correlation: dict):
    if not correlation or not correlation.get("steps"):
        return
    conf  = correlation.get("confidence", "LOW")
    label = correlation.get("chain_label", "Threat Sequence")
    conf_color = {"HIGH": "#ef4444", "MEDIUM": "#f97316", "LOW": "#eab308"}.get(conf, "#94a3b8")
    steps_html = "".join(
        f'<div style="padding:.4rem 0;border-bottom:1px solid rgba(255,255,255,.05)">'
        f'<span style="color:#64748b;font-size:.8rem">{s}</span></div>'
        for s in correlation["steps"]
    )
    mitre_html = ""
    if correlation.get("mitre_techniques"):
        refs = " &nbsp; ".join(
            f'<code style="background:#0f172a;color:#7dd3fc;padding:1px 6px;border-radius:3px;font-size:.78rem">{m}</code>'
            for m in correlation["mitre_techniques"]
        )
        mitre_html = f'<p style="margin:.6rem 0 0 0;color:#64748b;font-size:.82rem">MITRE ATT&CK: {refs}</p>'

    st.markdown(f"""
    <div style="background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.25);
    border-left:4px solid {conf_color};border-radius:12px;padding:1.2rem 1.5rem;margin:1.2rem 0;">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:.8rem">
            <span style="font-size:1.4rem">🔗</span>
            <div>
                <h4 style="margin:0;color:#f1f5f9">Attack Chain Identified: {label}</h4>
                <span style="color:{conf_color};font-weight:700;font-size:.85rem">Confidence: {conf}</span>
                &nbsp;·&nbsp;
                <span style="color:#64748b;font-size:.82rem">{correlation.get('phases_covered',0)} kill-chain phases covered</span>
            </div>
        </div>
        {steps_html}
        {mitre_html}
    </div>""", unsafe_allow_html=True)

def check_backend():
    try:
        r = requests.get(f"{API}/health", timeout=3)
        return r.status_code == 200, r.json()
    except:
        return False, {}

# ─── Pages ────────────────────────────────────────────────────────────────────
def page_analyze():
    st.markdown("## 🔍 Threat Intelligence Engine")
    st.caption("Hybrid detection: Rule engine + ML (IsolationForest) + Groq LLM")

    tab_paste, tab_upload, tab_stream = st.tabs(["📝 Paste Logs", "📁 Upload File", "📡 Simulate Stream"])

    log_input = None

    with tab_paste:
        default = open("../sample_attack_logs.txt").read() if __import__("os").path.exists("../sample_attack_logs.txt") else ""
        log_input = st.text_area("Paste network log entries", value=default, height=280,
                                  placeholder="Paste raw syslog / access log lines here...")

    with tab_upload:
        uploaded = st.file_uploader("Upload .log / .txt / .csv", type=["txt","log","csv"])
        if uploaded:
            log_input = uploaded.read().decode("utf-8", errors="replace")
            st.success(f"✅ Loaded {len(log_input):,} characters")
            st.code(log_input[:600] + ("..." if len(log_input) > 600 else ""), language="text")

    with tab_stream:
        st.info("**Real-Time Streaming Simulation** — Ingests logs line-by-line at 0.5s intervals, simulating a live syslog feed.")
        st.code("# Run in a separate terminal to simulate live log ingestion:\npython backend/ingestion.py sample_attack_logs.txt 0.5", language="bash")
        if st.button("▶ Stream sample_attack_logs.txt now", use_container_width=True):
            log_lines = []
            try:
                with open("../sample_attack_logs.txt") as f:
                    lines = [l.strip() for l in f if l.strip()]
            except:
                lines = []
            
            placeholder = st.empty()
            stream_log = []
            for line in lines:
                stream_log.append(line)
                placeholder.code("\n".join(stream_log[-10:]), language="text")
                try:
                    requests.post(f"{API}/ingest", json={"log_line": line}, timeout=5)
                except:
                    pass
                time.sleep(0.4)
            st.success("✅ Stream complete — check Database Logs and Timeline for ingested alerts.")
            return

    st.divider()
    if st.button("🚀 Run Full Hybrid Analysis", use_container_width=True, type="primary"):
        if not log_input or len(log_input.strip()) < 10:
            st.error("Please provide log data.")
            return
        with st.spinner("Running detection pipeline: Rule Engine → ML → Groq LLM..."):
            try:
                r = requests.post(f"{API}/analyze", json={"logs": log_input}, timeout=120)
                if r.status_code != 200:
                    st.error(f"Backend error: {r.json().get('error')}")
                    return
                render_report(r.json()["report"])
            except requests.exceptions.ConnectionError:
                st.error("❌ Cannot reach SOC Backend. Run: `python backend/app.py` first.")
            except Exception as e:
                st.error(f"Error: {e}")

def render_report(report):
    severity = report.get("overall_threat_level", "LOW")
    colour = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#22c55e"}.get(severity,"#94a3b8")
    
    st.markdown(f"""<div style="background:rgba(255,255,255,.04);border:1px solid {colour}44;
    border-left:4px solid {colour};border-radius:12px;padding:1.2rem 1.5rem;margin:1rem 0;">
    <h3 style="margin:0;color:{colour}">● {severity} — {report.get('threat_summary','')}</h3>
    <p style="color:#94a3b8;margin:.4rem 0 0 0">Attacker IP: <b>{report.get('attacker_ip','N/A')}</b></p>
    </div>""", unsafe_allow_html=True)

    # === ATTACK CHAIN CORRELATION SUMMARY ===
    correlation = report.get("attack_correlation", {})
    render_correlation_summary(correlation)

    # Detection layers summary
    layers = report.get("detection_layers", {})
    ml = report.get("ml_analysis", {})
    c1, c2, c3 = st.columns(3)
    c1.metric("Rule Engine",    layers.get("rule_engine", "—"))
    c2.metric("ML Anomaly Score", f"{ml.get('max_anomaly_score', 0):.2f}",
              delta="ANOMALY" if ml.get("anomaly_detected") else "NORMAL")
    c3.metric("Groq LLM",       layers.get("groq_llm", "—"))

    # === THREATS with MITRE badges ===
    threats = report.get("threats", [])
    if threats:
        st.markdown("### 🎯 Detected Threats")
        for t in threats:
            mitre_html = mitre_badge(t.get("mitre_id",""), t.get("mitre_tactic",""))
            with st.expander(f"{badge(t.get('severity','LOW'))} &nbsp; {t.get('type','Unknown')}", expanded=True):
                if mitre_html:
                    st.markdown(f"**MITRE:** {mitre_html}", unsafe_allow_html=True)
                st.write(f"**Description:** {t.get('description','')}")
                if t.get("kill_chain_phase"):
                    st.caption(f"Kill Chain Phase: `{t['kill_chain_phase']}`")
                if t.get("evidence"):
                    st.code(t["evidence"], language="text")
                src = t.get("source","")
                if src:
                    st.caption(f"Detected by: `{src}`")

    # Recommendations
    recs = report.get("recommendations", [])
    if recs:
        st.markdown("### 📋 Security Recommendations")
        for i, r in enumerate(recs, 1):
            st.markdown(f"**{i}.** {r}")

    # Firewall Script Download
    script = report.get("defense_script", "")
    if script and "No specific attacker IP" not in script and "Severity" not in script[:30]:
        st.markdown("### 🛡️ Incident Response Playbook")
        st.warning("⚠️ **Human-in-the-Loop Policy**: Review this script before executing. Download and run manually with root privileges only.")
        st.code(script, language="bash")
        st.download_button(
            "⬇️ Download Firewall Response Script",
            data=script,
            file_name="soc_response.sh",
            mime="text/x-shellscript",
            use_container_width=True
        )

def page_timeline():
    st.markdown("## 🗓️ Attack Timeline")
    st.caption("Chronological view of all detected threats — correlate multi-stage attacks")
    try:
        r = requests.get(f"{API}/timeline", timeout=5)
        events = r.json().get("timeline", [])
    except:
        st.error("❌ Backend unreachable.")
        return
    
    if not events:
        st.info("No alerts in database yet. Run an analysis first.")
        return
    
    st.markdown(f"**{len(events)} events detected**")
    timeline_html = '<div style="padding:1rem 0;">'
    for ev in events:
        sev = ev.get("severity", "LOW")
        ts  = ev.get("timestamp","")[:19].replace("T"," ")
        timeline_html += f"""
        <div class="timeline-item">
            <div class="tl-dot tl-{sev}"></div>
            <div class="tl-text">
                <div class="tl-time">{ts} UTC</div>
                <div class="tl-event">{ev.get('threat_type','')} &nbsp; {badge(sev)}</div>
                <div style="color:#64748b;font-size:.85rem">Attacker: {ev.get('attacker_ip','unknown')}</div>
            </div>
        </div>"""
    timeline_html += "</div>"
    st.markdown(timeline_html, unsafe_allow_html=True)

def page_alerts():
    st.markdown("## 🚨 Alert Investigation Panel")
    col_f1, col_f2 = st.columns([1, 3])
    with col_f1:
        sev_filter = st.selectbox("Filter by Severity", ["ALL","CRITICAL","HIGH","MEDIUM","LOW"])
    with col_f2:
        st.markdown("")

    try:
        params = {} if sev_filter == "ALL" else {"severity": sev_filter}
        r = requests.get(f"{API}/alerts", params=params, timeout=5)
        alerts = r.json().get("alerts", [])
    except:
        st.error("❌ Backend unreachable.")
        return

    if not alerts:
        st.info("No alerts match the filter. Run an analysis first.")
        return

    st.markdown(f"**{len(alerts)} alert(s) found**")
    st.divider()

    # Color-coded incident cards
    sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
    sev_bg     = {"CRITICAL": "rgba(239,68,68,.07)", "HIGH": "rgba(249,115,22,.07)",
                  "MEDIUM": "rgba(234,179,8,.07)",   "LOW": "rgba(34,197,94,.07)"}

    for alert in alerts:
        sev   = alert.get("severity", "LOW")
        color = sev_colors.get(sev, "#94a3b8")
        bg    = sev_bg.get(sev, "rgba(255,255,255,.03)")
        ts    = str(alert.get("timestamp",""))[:19].replace("T"," ")

        with st.expander(
            f"[{ts}]  {alert.get('threat_type','Unknown')}  ·  {sev}",
            expanded=False
        ):
            st.markdown(
                f'<div style="border-left:3px solid {color};padding:.6rem 1rem;'
                f'background:{bg};border-radius:0 8px 8px 0;margin-bottom:.6rem">'
                f'<b style="color:{color}">{sev}</b> &nbsp;·&nbsp; {alert.get("threat_type")}'
                f'</div>', unsafe_allow_html=True
            )
            aid = alert.get('id', 0)
            col_a, col_b = st.columns(2)
            col_a.text_input("Attacker IP",  value=alert.get("attacker_ip","N/A"), disabled=True, key=f"ip_{aid}")
            col_b.text_input("ML Score",     value=str(alert.get("ml_score","N/A")), disabled=True, key=f"ml_{aid}")
            st.text_input("Timestamp (UTC)", value=ts, disabled=True, key=f"ts_{aid}")
            if alert.get("groq_verdict"):
                st.info(f"🤖 **AI Verdict:** {alert['groq_verdict']}")
            if alert.get("evidence"):
                st.code(alert["evidence"], language="text")
            if alert.get("recommendation"):
                st.markdown(f"**💡 Recommendation:** {alert['recommendation']}")
            if alert.get("defense_script") and len(str(alert["defense_script"])) > 60:
                if st.button(f"⬇ Download Script (Alert #{alert['id']})", key=f"dl_{alert['id']}"):
                    st.code(alert["defense_script"], language="bash")

def page_analytics():
    st.markdown("## 📊 SOC Analytics Dashboard")
    try:
        r = requests.get(f"{API}/stats", timeout=5)
        stats = r.json()
    except:
        st.error("❌ Backend unreachable.")
        return
    
    c1, c2, c3 = st.columns(3)
    c1.markdown(f"""<div class="metric-card"><h2>{stats.get('total_logs',0)}</h2><p>Total Logs Ingested</p></div>""", unsafe_allow_html=True)
    
    sev = stats.get("severity_counts", {})
    total_alerts = sum(sev.values())
    c2.markdown(f"""<div class="metric-card"><h2>{total_alerts}</h2><p>Total Alerts</p></div>""", unsafe_allow_html=True)
    
    critical = sev.get("CRITICAL", 0)
    c3.markdown(f"""<div class="metric-card" style="border-color:rgba(239,68,68,.4)"><h2 style="color:#ef4444">{critical}</h2><p>Critical Threats</p></div>""", unsafe_allow_html=True)
    
    st.divider()
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.markdown("#### Threats by Severity")
        if sev:
            df_sev = pd.DataFrame(list(sev.items()), columns=["Severity","Count"])
            st.bar_chart(df_sev.set_index("Severity"))
    
    with col_b:
        st.markdown("#### Threats by Type")
        threat_counts = stats.get("threat_counts", {})
        if threat_counts:
            df_th = pd.DataFrame(list(threat_counts.items()), columns=["Threat Type","Count"])
            st.bar_chart(df_th.set_index("Threat Type"))

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    st.set_page_config(page_title="AI SOC Platform", page_icon="🛡️", layout="wide")
    apply_theme()

    # Check backend health
    online, health = check_backend()

    # Header
    st.markdown("""
    <h1 style="background:linear-gradient(135deg,#60a5fa,#c084fc);
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
    font-size:2.8rem;font-weight:800;margin-bottom:.2rem">
    🛡️ AI-Powered SOC Platform
    </h1>
    <p style="color:#64748b;font-size:1rem;margin-bottom:1.5rem">
    Full-Stack · Flask Backend · Hybrid Detection (Rule + ML + LLM) · Real-Time Streaming
    </p>""", unsafe_allow_html=True)

    # Sidebar
    st.sidebar.markdown("### 🔧 SOC Console")
    if online:
        st.sidebar.success("✅ Backend: Online")
        groq_ok = health.get("groq_key_loaded", False)
        st.sidebar.info(f"Groq LLM: {'✅ Ready' if groq_ok else '⚠️ Key Missing'}")
        st.sidebar.caption("ML: IsolationForest Active")
        st.sidebar.caption("DB: SQLite (logs + alerts)")
    else:
        st.sidebar.error("❌ Backend: Offline\nRun: `python backend/app.py`")
    
    st.sidebar.divider()
    page = st.sidebar.radio("Navigation", [
        "🔍 Analysis Engine",
        "🗓️ Attack Timeline",
        "🚨 Alert Investigation",
        "📊 Analytics Dashboard"
    ])

    if "Analysis" in page:
        page_analyze()
    elif "Timeline" in page:
        page_timeline()
    elif "Alert" in page:
        page_alerts()
    elif "Analytics" in page:
        page_analytics()

if __name__ == "__main__":
    main()
