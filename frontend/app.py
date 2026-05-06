import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import time
import os

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")

st.set_page_config(page_title="Honeypot Log Storyteller", page_icon="🍯", layout="wide")

# Custom CSS for a clean, modern dashboard look
st.markdown("""
    <style>
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    .metric-card {
        background-color: #262730;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        min-height: 90px;
        border: 1px solid #333333;
    }
    .metric-title {
        color: #aaaaaa;
        font-size: 13px;
        text-transform: uppercase;
        margin-bottom: 4px;
        font-weight: 600;
    }
    .metric-value {
        font-size: 22px;
        font-weight: bold;
        color: #4CAF50;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🍯 Honeypot Log Storyteller")
st.markdown("Automated AI pipeline for converting raw honeypot logs into STIX-compliant threat intelligence reports.")

# ─────────────── UI STATE ───────────────
if "processed_file_id" not in st.session_state:
    st.session_state.processed_file_id = None
if "selected_session" not in st.session_state:
    st.session_state.selected_session = None

# ─────────────── SIDEBAR ───────────────
with st.sidebar:
    st.header("Upload Logs")
    
    backend_status = "🔴 Offline (Booting)"
    try:
        if requests.get(f"{BACKEND_URL}/", timeout=1.0).status_code == 200:
            backend_status = "🟢 Online"
    except requests.exceptions.ConnectionError:
        backend_status = "🟡 Pre-Booting (RabbitMQ Delay)"
        
    st.markdown(f"**Backend Status**: {backend_status}")
    
    uploaded_file = st.file_uploader("Upload Cowrie/Dionaea JSON", type=['json', 'log'])
    
    if st.button("Process Logs") and uploaded_file:
        with st.spinner("Uploading and Analyzing Pipeline (this may take a moment)..."):
            try:
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/json")}
                resp = requests.post(f"{BACKEND_URL}/upload/", files=files)
                if resp.status_code == 200:
                    data = resp.json()
                    st.success(f"Queued! ID: {data['file_id']}")
                    st.session_state.processed_file_id = data['file_id']
                else:
                    st.error(f"Error: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("⚠️ Backend initializing. Please wait 15-20s and retry.")
            except Exception as e:
                st.error(f"Connection failed: {e}")

    st.markdown("---")
    st.header("Recent Sessions")
    if st.button("Refresh Sessions"):
        try:
            resp = requests.get(f"{BACKEND_URL}/status/sessions/list")
            if resp.status_code == 200:
                sessions = resp.json()
                st.session_state.sessions_list = sessions
        except Exception:
            st.warning("Could not connect to backend.")

    if "sessions_list" in st.session_state and st.session_state.sessions_list:
        session_opts = {f"{s['src_ip']} ({s['session_id'][:8]}...)": s['session_id'] for s in st.session_state.sessions_list}
        selected_display = st.selectbox("Select a Session", list(session_opts.keys()))
        if selected_display:
            st.session_state.selected_session = session_opts[selected_display]

# ─────────────── MITRE ENTERPRISE MATRIX (static reference) ───────────────
# Representative subset of the full MITRE ATT&CK Enterprise matrix (14 tactics)
MITRE_MATRIX = {
    "Reconnaissance": ["T1595", "T1592", "T1590", "T1591", "T1598"],
    "Resource Development": ["T1583", "T1586", "T1584", "T1585", "T1588"],
    "Initial Access": ["T1190", "T1133", "T1566", "T1078", "T1189"],
    "Execution": ["T1059", "T1053", "T1569", "T1204", "T1047"],
    "Persistence": ["T1053.003", "T1543.002", "T1098", "T1136", "T1505"],
    "Privilege Escalation": ["T1548", "T1134", "T1068", "T1055", "T1078"],
    "Defense Evasion": ["T1222", "T1070.004", "T1036", "T1027", "T1562"],
    "Credential Access": ["T1110", "T1003.008", "T1087", "T1555", "T1552"],
    "Discovery": ["T1082", "T1083", "T1046", "T1057", "T1049"],
    "Lateral Movement": ["T1021", "T1080", "T1072", "T1563", "T1570"],
    "Collection": ["T1560", "T1005", "T1074", "T1119", "T1114"],
    "Command and Control": ["T1105", "T1071", "T1573", "T1095", "T1572"],
    "Exfiltration": ["T1041", "T1048", "T1567", "T1029", "T1030"],
    "Impact": ["T1485", "T1486", "T1496", "T1489", "T1529"],
}

TECHNIQUE_NAMES = {
    "T1595": "Active Scanning", "T1592": "Gather Victim Host Info", "T1590": "Gather Victim Network Info",
    "T1591": "Gather Victim Org Info", "T1598": "Phishing for Information",
    "T1583": "Acquire Infrastructure", "T1586": "Compromise Accounts", "T1584": "Compromise Infrastructure",
    "T1585": "Establish Accounts", "T1588": "Obtain Capabilities",
    "T1190": "Exploit Public App", "T1133": "External Remote Services", "T1566": "Phishing",
    "T1078": "Valid Accounts", "T1189": "Drive-by Compromise",
    "T1059": "Command & Scripting Interpreter", "T1053": "Scheduled Task/Job", "T1569": "System Services",
    "T1204": "User Execution", "T1047": "WMI",
    "T1053.003": "Cron", "T1543.002": "Systemd Service", "T1098": "Account Manipulation",
    "T1136": "Create Account", "T1505": "Server Software Component",
    "T1548": "Abuse Elevation", "T1134": "Access Token Manipulation", "T1068": "Exploitation for Privilege Escalation",
    "T1055": "Process Injection", 
    "T1222": "File Permissions Modification", "T1070.004": "File Deletion", "T1036": "Masquerading",
    "T1027": "Obfuscated Files", "T1562": "Impair Defenses",
    "T1110": "Brute Force", "T1003.008": "OS Credential Dumping", "T1087": "Account Discovery",
    "T1555": "Credentials from Password Stores", "T1552": "Unsecured Credentials",
    "T1082": "System Information Discovery", "T1083": "File & Dir Discovery", "T1046": "Network Service Scanning",
    "T1057": "Process Discovery", "T1049": "System Network Connections",
    "T1021": "Remote Services", "T1080": "Taint Shared Content", "T1072": "Software Deployment Tools",
    "T1563": "Remote Service Session", "T1570": "Lateral Tool Transfer",
    "T1560": "Archive Data", "T1005": "Data from Local System", "T1074": "Data Staged",
    "T1119": "Automated Collection", "T1114": "Email Collection",
    "T1105": "Ingress Tool Transfer", "T1071": "Application Layer Protocol", "T1573": "Encrypted Channel",
    "T1095": "Non-Application Layer Protocol", "T1572": "Protocol Tunneling",
    "T1041": "Exfil Over C2", "T1048": "Exfil Over Alternative Protocol", "T1567": "Exfil Over Web Service",
    "T1029": "Scheduled Transfer", "T1030": "Data Transfer Size Limits",
    "T1485": "Data Destruction", "T1486": "Data Encrypted for Impact", "T1496": "Resource Hijacking",
    "T1489": "Service Stop", "T1529": "System Shutdown",
}


def render_mitre_heatmap(detected_techniques):
    """Render full MITRE ATT&CK coverage matrix grid."""
    detected_map = {t['id']: t for t in detected_techniques}
    tactics = list(MITRE_MATRIX.keys())

    z_matrix = []
    hover_matrix = []

    # MITRE_MATRIX has 5 techniques per tactic in our static definition
    for row_idx in range(5):
        z_row = []
        hover_row = []
        for tactic in tactics:
            tech_id = MITRE_MATRIX[tactic][row_idx]
            tech_name = TECHNIQUE_NAMES.get(tech_id, tech_id)
            
            if tech_id in detected_map:
                conf = detected_map[tech_id]['confidence']
                z_row.append(conf)
                hover_row.append(
                    f"<b>Tactic: {tactic}</b><br><br>"
                    f"⬤ <b>{tech_name}</b><br>"
                    f"   ID: {tech_id} | Confidence: <b>{conf:.0%}</b>"
                )
            else:
                z_row.append(0.0)
                hover_row.append(
                    f"<b>Tactic: {tactic}</b><br><br>"
                    f"○ <i>{tech_name}</i><br>"
                    f"   ID: {tech_id} | Not Detected"
                )
        z_matrix.append(z_row)
        hover_matrix.append(hover_row)

    # Reverse rows so the 1st technique in the list appears at the top horizontally
    z_matrix.reverse()
    hover_matrix.reverse()

    # Colorscale uniformly mapping confidence for dark theme
    colorscale = [
        [0.00, "#262730"],   # dark (undetected)
        [0.01, "#262730"],
        [0.49, "#4a1919"],   # faint transition
        [0.50, "#800000"],   # dark red
        [0.70, "#b30000"],   # medium red
        [0.90, "#e60000"],   # bright red
        [1.00, "#ff3333"],   # intense red
    ]

    fig = go.Figure(data=go.Heatmap(
        z=z_matrix,
        x=tactics,
        y=["Tech 5", "Tech 4", "Tech 3", "Tech 2", "Tech 1"],
        hovertext=hover_matrix,
        hoverinfo="text",
        colorscale=colorscale,
        zmin=0,
        zmax=1,
        showscale=True,
        xgap=4,
        ygap=4,
        colorbar=dict(
            title=dict(text="Confidence", font=dict(size=11)),
            tickformat=".0%",
            len=0.9,
            thickness=12,
            tickfont=dict(size=10),
            x=1.02,
        ),
    ))

    fig.update_layout(
        title=dict(
            text="MITRE ATT&CK Enterprise Matrix",
            font=dict(size=18, color="#fafafa"),
            x=0.5,
            xanchor="center",
            y=0.95,
        ),
        xaxis=dict(
            side="top",
            tickangle=-45,
            tickfont=dict(size=11, color="#cccccc"),
            automargin=True,
        ),
        yaxis=dict(
            showticklabels=False,
            automargin=True,
        ),
        height=450,
        margin=dict(l=10, r=60, t=120, b=10),
        paper_bgcolor="#0e1117",
        plot_bgcolor="#0e1117",
        font=dict(color="#fafafa"),
        hoverlabel=dict(
            bgcolor="#262730",
            font_size=13,
            font_color="#fafafa",
            bordercolor="#444444",
        ),
    )

    return fig


# ─────────────── MAIN AREA ───────────────
if st.session_state.processed_file_id:
    st.info(f"Currently tracking file processing ID: {st.session_state.processed_file_id}")
    
if not st.session_state.selected_session:
    st.markdown("### Welcome to the Analysis Dashboard")
    st.write("Upload a file from the sidebar, or refresh the recent sessions to view analysis.")
else:
    sid = st.session_state.selected_session
    st.markdown(f"### Session Analysis: `{sid}`")
    
    with st.spinner("Loading report..."):
        try:
            resp = requests.get(f"{BACKEND_URL}/report/{sid}")
            if resp.status_code == 200:
                report = resp.json()
                
                st.success("Analysis Complete!")
                
                # ─── Profile Card ───
                st.markdown("#### 👤 Attacker Profile")
                
                skill = report.get('profile', {}).get('skill_level', 'Unknown')
                skill_color = "#4CAF50" if skill == "Script Kiddie" else "#FF9800" if skill == "Intermediate" else "#F44336" if skill in ["Advanced", "Expert"] else "#9E9E9E"
                
                cmd_count = len(report.get('session', {}).get('commands', []))
                duration = report.get('session', {}).get('duration', 0)
                
                # Row 1: IP, Skill, Attack Type
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Source IP</div>
                        <div class="metric-value" style="color:#E91E63;">{report.get('session', {}).get('src_ip', 'Unknown')}</div>
                    </div>
                    """, unsafe_allow_html=True)
                with c2:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Skill Level</div>
                        <div class="metric-value"><span style="background-color:{skill_color}; color:white; padding:4px 8px; border-radius:4px; font-size:16px;">{skill}</span></div>
                    </div>
                    """, unsafe_allow_html=True)
                with c3:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Attack Type</div>
                        <div class="metric-value" style="color:#03A9F4;">{report.get('profile', {}).get('attack_type', 'Unknown')}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # Row 2: Complexity, Commands, Duration
                c4, c5, c6 = st.columns(3)
                with c4:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Complexity Score</div>
                        <div class="metric-value">{report.get('profile', {}).get('score', 0)}/10</div>
                    </div>
                    """, unsafe_allow_html=True)
                with c5:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Total Commands Executed</div>
                        <div class="metric-value" style="color:#9C27B0;">{cmd_count}</div>
                    </div>
                    """, unsafe_allow_html=True)
                with c6:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Session Duration</div>
                        <div class="metric-value" style="color:#00BCD4;">{duration}s</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # Row 3: GeoIP + Profiling
                g1, g2, g3, g4 = st.columns(4)
                with g1:
                    country = report.get('session', {}).get('country', 'Unknown') or 'Unknown'
                    city = report.get('session', {}).get('city', 'Unknown') or 'Unknown'
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Location</div>
                        <div class="metric-value" style="color:#FFC107; font-size:18px;">📍 {city}, {country}</div>
                    </div>
                    """, unsafe_allow_html=True)
                with g2:
                    asn = report.get('session', {}).get('asn', 'Unknown') or 'Unknown'
                    isp = report.get('session', {}).get('isp', 'Unknown') or 'Unknown'
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">ASN / ISP</div>
                        <div class="metric-value" style="color:#8BC34A; font-size:14px;">🌐 {asn}<br>{isp}</div>
                    </div>
                    """, unsafe_allow_html=True)
                with g3:
                    tool_count = report.get('profile', {}).get('tool_count', 0)
                    tools_list = report.get('profile', {}).get('tools_identified', [])
                    tools_str = ', '.join(tools_list[:5]) if tools_list else 'None'
                    error_rate = report.get('profile', {}).get('error_rate', 0.0)
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Tool Diversity</div>
                        <div class="metric-value" style="color:#FF5722;">{tool_count} tools</div>
                        <div style="color:#888; font-size:12px; margin-top:4px;">{tools_str}</div>
                        <div style="color:#888; font-size:11px;">Error rate: {error_rate:.0%}</div>
                    </div>
                    """, unsafe_allow_html=True)
                with g4:
                    obfuscation = report.get('profile', {}).get('obfuscation_detected', False)
                    obf_display = "🔴 YES" if obfuscation else "🟢 None"
                    obf_color = "#F44336" if obfuscation else "#4CAF50"
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-title">Obfuscation Detected</div>
                        <div class="metric-value" style="color:{obf_color};">{obf_display}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # ─── Narrative ───
                st.markdown("#### 📜 AI Narrative")
                st.info(report['profile']['narrative'])
                
                # ─── MITRE Matrix ───
                st.markdown("#### 🎯 MITRE ATT&CK Enterprise Matrix")
                techniques = report.get('techniques', [])
                
                fig = render_mitre_heatmap(techniques)
                st.plotly_chart(fig, use_container_width=True)
                
                if techniques:
                    st.markdown("<br>", unsafe_allow_html=True)
                    st.markdown("##### Detected Techniques")
                    df = pd.DataFrame(techniques)
                    st.dataframe(df, use_container_width=True)
                else:
                    st.write("No specific techniques detected in this session.")
                
                # ─── Downloads ───
                st.markdown("#### 💾 Export Intelligence")
                
                def get_download_data(file_type, sid):
                    try:
                        r = requests.get(f"{BACKEND_URL}/download/{file_type}/{sid}")
                        if r.status_code == 200:
                            return r.content
                        return None
                    except:
                        return None

                d_col1, d_col2, d_col3 = st.columns(3)
                
                with d_col1:
                    pdf_data = get_download_data("pdf", sid)
                    if pdf_data:
                        st.download_button("📄 Download PDF Report", data=pdf_data, file_name=f"{sid}.pdf", mime="application/pdf")
                    else:
                        st.button("📄 PDF Not Ready", disabled=True)
                        
                with d_col2:
                    json_data = get_download_data("json", sid)
                    if json_data:
                        st.download_button("🧩 Download Raw JSON", data=json_data, file_name=f"{sid}.json", mime="application/json")
                    else:
                        st.button("🧩 JSON Not Ready", disabled=True)
                        
                with d_col3:
                    stix_data = get_download_data("stix", sid)
                    if stix_data:
                        st.download_button("🛡️ Download STIX 2.1 Bundle", data=stix_data, file_name=f"{sid}_stix.json", mime="application/json")
                    else:
                        st.button("🛡️ STIX Not Ready", disabled=True)
                    
            else:
                st.warning("Report not fully generated yet. Try again in a few moments.")
        except Exception as e:
            st.error(f"Failed to fetch report: {e}")
