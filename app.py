import streamlit as st
import pandas as pd
import numpy as np
import joblib
import re
import time
import shap
import matplotlib.pyplot as plt
from datetime import datetime, time as dt_time

# --- 1. CONFIGURATION & CSS ---
st.set_page_config(page_title="VERITAS FORENSICS", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    .stApp { background-color: #0b0c10; color: #c5c6c7; font-family: 'Consolas', monospace; }
    .stTextArea>div>div>textarea { background-color: #1f2833; color: #66fcf1; border: 1px solid #45a29e; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem !important; color: #fff; }
    .status-box { padding: 15px; border-radius: 5px; margin-bottom: 10px; font-weight: bold; border-left: 5px solid; }
    .status-green { background: #0d2e1a; border-color: #2ea043; color: #7ee787; }
    .status-red { background: #3d0d0d; border-color: #ff4d4d; color: #ffadad; }
    .status-yellow { background: #3b2e00; border-color: #d2a106; color: #f2cc8f; }
    
    /* Loading Animation */
    @keyframes scan {
        0% { width: 0%; }
        100% { width: 100%; }
    }
    .cyber-bar {
        height: 4px;
        background: #66fcf1;
        animation: scan 2s ease-in-out infinite;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# --- 2. LOAD SYSTEM ---
@st.cache_resource
def load_system():
    try:
        model = joblib.load('veritas_model.pkl')
        scaler = joblib.load('veritas_scaler.pkl')
        try:
            background = joblib.load('veritas_background.pkl')
        except:
            background = np.zeros((1, 5)) 
        return model, scaler, background
    except FileNotFoundError:
        return None, None, None

model, scaler, background = load_system()

# --- 3. ROBUST PARSER ---
def parse_logs_robust(log_content, target_date, start_t, end_t):
    lines = log_content.strip().split('\n')
    
    active_events = 0
    unique_sources = set()
    action_types = set()
    system_noise = 0
    critical_count = 0 
    debug_log = []
    
    NOISE_SOURCES = ["igccservice", "RestartManager", "BTHUSB", "Netwtw", "Time-Service", "DCOM", "Win32k", "Security-SPP"]
    CRITICAL_IDS = ["4624", "4672", "4103", "4104", "1000", "10010", "4798"] 

    window_start = datetime.combine(target_date, start_t)
    window_end = datetime.combine(target_date, end_t)

    for line in lines:
        line = line.strip()
        if not line or line.startswith('"TimeCreated"') or line.startswith("#"): continue
        
        # Split by comma (Clean CSV format)
        tokens = line.split(',')
        
        if len(tokens) >= 3:
            # CLEANING
            t_str = tokens[0].strip().replace('"', '')
            provider = tokens[1].strip().replace('"', '')
            evt_id = tokens[2].strip().replace('"', '')
            
            try:
                log_dt = datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue 

            # TIME FILTER
            if log_dt < window_start or log_dt > window_end:
                continue 

            # CLASSIFICATION
            is_noise = any(n.lower() in provider.lower() for n in NOISE_SOURCES)
            is_critical = (evt_id in CRITICAL_IDS)
            
            if is_noise:
                system_noise += 1
            else:
                active_events += 1
                unique_sources.add(provider)
                action_types.add(evt_id)
                
                if is_critical:
                    critical_count += 1
                    if len(debug_log) < 3: debug_log.append(f"{t_str}: ID {evt_id} ({provider})")

    return {
        'event_count': active_events,
        'unique_ip_count': len(unique_sources),
        'action_diversity': len(action_types),
        'dbscan_noise_points': system_noise,
        'critical_event_count': critical_count,
        'debug_data': debug_log
    }

# --- 4. MAIN INTERFACE ---
st.title("🛡️ VERITAS | Digital Alibi Verification")

# Sidebar - Configuration
st.sidebar.header("1. Case Setup")
case_id = st.sidebar.text_input("Case ID", "CASE-2025-DEC07")
analysis_date = st.sidebar.date_input("Target Date", value=datetime(2025, 12, 7).date())

st.sidebar.header("2. Time Window")
start_time = st.sidebar.time_input("Start Time", value=dt_time(19, 0)) # 7 PM
end_time = st.sidebar.time_input("End Time", value=dt_time(22, 0))     # 10 PM

# Sidebar - File Upload (RESTORED)
st.sidebar.markdown("---")
st.sidebar.subheader("3. Evidence Upload")
uploaded_file = st.sidebar.file_uploader("Upload Clean CSV Logs", type=['txt', 'csv'])

# Main Layout
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Data Ingestion Terminal")
    # Priority: File Upload -> Text Area
    initial_text = ""
    if uploaded_file is not None:
        initial_text = uploaded_file.getvalue().decode("utf-8")
        
    raw_text = st.text_area("Log Input (Paste or Upload)", value=initial_text, height=300, 
                            help="Paste the content of 'final_clean_logs.txt' here, or upload it via sidebar.")

with col2:
    st.subheader("Control & Status")
    st.info("System Ready. Awaiting execution command.")
    analyze = st.button("RUN FORENSIC ANALYSIS", type="primary", use_container_width=True)
    
    if analyze and raw_text:
        # Loading Animation
        progress_ph = st.empty()
        progress_ph.markdown('<div class="cyber-bar"></div>', unsafe_allow_html=True)
        time.sleep(1) # Fake processing time for effect
        progress_ph.empty()
        
        # Run Debug Scan
        with st.expander("🔍 Live Parsing Stream"):
            debug_feats = parse_logs_robust(raw_text, analysis_date, start_time, end_time)
            st.write(f"Matched {debug_feats['event_count']} active events in window.")
            if debug_feats['critical_event_count'] > 0:
                st.success(f"CRITICAL ARTIFACTS FOUND: {debug_feats['critical_event_count']}")
            else:
                st.warning("No critical artifacts (Logons/Privileges) found.")

# --- 5. EXECUTION ---
if analyze:
    if not model:
        st.error("AI Brain Missing. Please run pipeline script.")
    elif not raw_text:
        st.warning("No data found.")
    else:
        # B. PARSE
        feats = parse_logs_robust(raw_text, analysis_date, start_time, end_time)
        
        # C. PREDICT
        input_df = pd.DataFrame([feats])
        input_df = input_df[['event_count', 'unique_ip_count', 'action_diversity', 
                           'dbscan_noise_points', 'critical_event_count']]
        
        # Get AI Probability
        prob = 0.0
        if feats['event_count'] > 0:
            input_scaled = scaler.transform(input_df)
            prob = model.predict_proba(input_scaled)[0][1]

        # D. VERDICT DASHBOARD
        st.markdown("---")
        st.subheader(f"3. Final Verdict")
        
        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Active Events", feats['event_count'])
        m2.metric("Critical Actions", feats['critical_event_count'])
        m3.metric("System Noise", feats['dbscan_noise_points'])
        m4.metric("AI Probability", f"{prob*100:.1f}%")
        
        # Heuristic Override for Definitive Proof (Logins are gold standard)
        if feats['critical_event_count'] > 0:
             prob = max(prob, 0.95)

        if prob > 0.65:
            st.markdown(f'<div class="status-box status-green">POSITIVE: PRESENCE CONFIRMED</div>', unsafe_allow_html=True)
            if feats['critical_event_count'] > 0:
                st.write(f"**Definitive Proof.** {feats['critical_event_count']} critical actions (Logon/Privilege) validate the alibi.")
            else:
                st.write("**Strong Signal.** High volume of complex activity detected.")
                
        elif prob < 0.35:
            st.markdown(f'<div class="status-box status-red">NEGATIVE: PRESENCE NOT ESTABLISHED</div>', unsafe_allow_html=True)
            st.write("**Only background system processes detected.**")
        else:
            st.markdown(f'<div class="status-box status-yellow">INCONCLUSIVE</div>', unsafe_allow_html=True)
            st.write("**Ambiguous Activity.** Events detected but lack definitive user signature.")

        # E. SHAP (FIXED)
        st.markdown("---")
        st.write("### AI Explainability Engine")
        
        try:
            explainer = shap.TreeExplainer(model)
            shap_vals = explainer.shap_values(input_scaled)
            
            # Handle Matrix Shape
            if isinstance(shap_vals, list):
                sv_single = shap_vals[1][0] 
                base_val = explainer.expected_value[1]
            else:
                sv_single = shap_vals[0, :, 1] if len(shap_vals.shape) == 3 else shap_vals[0]
                base_val = explainer.expected_value
            
            fig, ax = plt.subplots(figsize=(8,4))
            shap.plots.waterfall(shap.Explanation(
                values=sv_single, 
                base_values=base_val, 
                data=input_df.iloc[0].values, 
                feature_names=input_df.columns
            ), show=False)
            st.pyplot(fig)
            
        except Exception as e:
            st.warning("Explanation graph skipped (Data shape mismatch in library). Verdict is valid.")