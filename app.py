import streamlit as st
import pandas as pd
import numpy as np
import joblib
import shap
import matplotlib.pyplot as plt
import re
from datetime import datetime, time

# --- 1. SYSTEM CONFIGURATION ---
st.set_page_config(page_title="VERITAS FORENSICS", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: #e6edf3; font-family: 'Segoe UI', sans-serif; }
    .stTextArea>div>div>textarea { 
        font-family: 'Consolas', monospace; 
        background-color: #0d1117; 
        color: #58a6ff; 
        border: 1px solid #30363d;
    }
    div[data-testid="stMetricValue"] { font-size: 1.5rem !important; }
    h1, h2, h3 { color: #ffffff !important; font-weight: 600; }
    .status-box { padding: 15px; border-radius: 5px; margin-bottom: 10px; font-weight: bold; border: 1px solid rgba(255,255,255,0.1); }
    .status-green { background-color: #0d2e1a; color: #7ee787; border-left: 5px solid #2ea043; }
    .status-yellow { background-color: #3b2e00; color: #d2a106; border-left: 5px solid #a37f00; }
    .status-red { background-color: #3d0d0d; color: #ffadad; border-left: 5px solid #ff4d4d; }
    .status-grey { background-color: #161b22; color: #8b949e; border-left: 5px solid #30363d; }
</style>
""", unsafe_allow_html=True)

# --- 2. LOAD AI MODEL ---
@st.cache_resource
def load_system():
    try:
        model = joblib.load('veritas_model.pkl')
        scaler = joblib.load('veritas_scaler.pkl')
        return model, scaler
    except FileNotFoundError:
        return None, None

model, scaler = load_system()

# --- 3. STRICT TIMELINE PARSER ---
def parse_and_filter_logs(raw_text, target_date, start_t, end_t):
    lines = raw_text.strip().split('\n')
    
    active_events = 0
    unique_sources = set()
    action_types = set()
    system_noise = 0
    
    # FILTER LIST: Background processes that do NOT indicate human presence
    SYSTEM_FILTERS = [
        "Netwtw", "EventLog", "Service Control Manager", 
        "Microsoft-Windows-Kernel", "Microsoft-Windows-Update",
        "Microsoft-Windows-Time-Service", "NtpClient", "DNS Client",
        "Microsoft-Windows-Configuration", "Microsoft-Windows-PnP", 
        "BTHUSB", "Power-Troubleshooter"
    ]
    
    # Regex to capture: (Month) (Day) ... (Time)
    # Example: "Dec 03 ... 12:36"
    log_pattern = re.compile(r'([A-Z][a-z]{2})\s+(\d{1,2}).*?(\d{2}:\d{2}(?::\d{2})?)')
    
    for line in lines:
        line = line.strip()
        if not line or "Index" in line or "---" in line: continue
            
        match = log_pattern.search(line)
        if match:
            month_str, day_str, time_str = match.groups()
            
            try:
                # 1. PARSE DATE (Assume target_date year because logs often lack year)
                log_date_str = f"{month_str} {day_str} {target_date.year}"
                log_date_obj = datetime.strptime(log_date_str, "%b %d %Y").date()
                
                # 2. PARSE TIME
                if len(time_str) == 5:
                    log_time_obj = datetime.strptime(time_str, "%H:%M").time()
                else:
                    log_time_obj = datetime.strptime(time_str, "%H:%M:%S").time()
                
                # Combine
                log_dt = datetime.combine(log_date_obj, log_time_obj)
                start_dt = datetime.combine(target_date, start_t)
                end_dt = datetime.combine(target_date, end_t)
                
            except ValueError:
                continue # Skip malformed lines

            # --- STRICT FILTERING LOGIC ---
            
            # Check 1: Is the log from the SELECTED DATE?
            if log_date_obj != target_date:
                continue # Skip logs from wrong days
            
            # Check 2: Is the log inside the SELECTED TIME WINDOW?
            if start_dt <= log_dt <= end_dt:
                
                # Check 3: Is it Human Activity or System Noise?
                is_noise = any(f in line for f in SYSTEM_FILTERS)
                
                parts = line.split()
                # Try to grab Source/Action columns (index varies by log format, simplified here)
                # We count parts to avoid index errors
                source = parts[5] if len(parts) > 5 else "Unknown"
                action = parts[6] if len(parts) > 6 else "Unknown"

                if is_noise:
                    system_noise += 1
                else:
                    active_events += 1
                    unique_sources.add(source)
                    action_types.add(action)
                    
    return {
        'event_count': active_events,
        'unique_ip_count': len(unique_sources),
        'action_diversity': len(action_types),
        'dbscan_noise_points': system_noise
    }

# --- 4. SIDEBAR ---
st.sidebar.title("VERITAS FORENSICS")
st.sidebar.subheader("Case Parameters")
case_id = st.sidebar.text_input("Case ID", "CASE-2025-001")

# Default date set to match your sample logs (Dec 03, 2025 based on current year assumption)
# Note: You must select the date matching your logs!
incident_date = st.sidebar.date_input("Date of Analysis", value=datetime(2025, 12, 3))

st.sidebar.subheader("Verification Window")
start_time = st.sidebar.time_input("Start", value=time(8, 0))
end_time = st.sidebar.time_input("End", value=time(16, 0))

# --- 5. MAIN UI ---
st.title("Digital Presence Verification System")
col_main, col_res = st.columns([2, 1])

with col_main:
    st.subheader("1. Log Ingestion")
    st.write("System will strictly filter logs matching the **Date** and **Time Window** selected in the sidebar.")
    raw_logs = st.text_area("Terminal Input", height=400, placeholder="Paste raw logs here...\n32303 Dec 03 12:36 Info Microsoft-Windows...")
    run_btn = st.button("RUN FORENSIC ANALYSIS", type="primary")

if run_btn:
    if not model:
        st.error("Error: Brain missing. Run 'final_pipeline.py' first.")
    elif not raw_logs:
        st.warning("Error: No logs provided.")
    else:
        # 1. PARSE
        feats = parse_and_filter_logs(raw_logs, incident_date, start_time, end_time)
        
        # 2. PREDICT
        # Only predict if there are any active events. 
        if feats['event_count'] == 0:
            raw_prob = 0.0
        else:
            input_vec = pd.DataFrame([feats])[['event_count', 'unique_ip_count', 'action_diversity', 'dbscan_noise_points']]
            raw_prob = model.predict_proba(scaler.transform(input_vec))[0][1]

        # 3. LOGIC REFINEMENT (The Logic Check from before)
        # If noise outweighs events significantly, reduce confidence.
        final_prob = raw_prob
        penalty_text = ""
        
        if feats['dbscan_noise_points'] > (feats['event_count'] * 2) and feats['event_count'] < 5:
            final_prob = raw_prob * 0.2 # Heavy penalty for "mostly noise"
            penalty_text = " (Reduced due to high noise)"

        with col_res:
            st.subheader("2. Analysis Results")
            c1, c2 = st.columns(2)
            c1.metric("Active Events", feats['event_count'])
            c2.metric("System Noise", feats['dbscan_noise_points'])
            
            st.divider()
            
            # 4. VERDICT LOGIC
            st.subheader("Verdict")
            
            # SCENARIO A: No logs matching Date/Time
            if feats['event_count'] == 0 and feats['dbscan_noise_points'] == 0:
                st.markdown('<div class="status-box status-grey">NO DATA FOUND</div>', unsafe_allow_html=True)
                st.write(f"No logs found for **{incident_date}** between **{start_time}** and **{end_time}**.")
            
            # SCENARIO B: Only System Noise (The Passive User)
            elif feats['event_count'] == 0:
                st.markdown('<div class="status-box status-red">NEGATIVE: INACTIVE</div>', unsafe_allow_html=True)
                st.write("**Only background system processes found.** No human interaction detected.")
                
            # SCENARIO C: Confirmed Activity
            elif final_prob > 0.60:
                st.markdown('<div class="status-box status-green">POSITIVE: CONFIRMED</div>', unsafe_allow_html=True)
                st.write("**Human Presence Confirmed.**")
                st.metric("Probability", f"{final_prob*100:.1f}%")
                
            # SCENARIO D: Weak/Ambiguous
            else:
                st.markdown('<div class="status-box status-yellow">INCONCLUSIVE</div>', unsafe_allow_html=True)
                st.write("**High Noise / Low Confidence.**")
                st.write(f"Activity detected but statistically weak.{penalty_text}")
                st.metric("Probability", f"{final_prob*100:.1f}%")

    st.markdown("---")
    st.caption(f"Analysis run for Case {case_id} on {incident_date}")