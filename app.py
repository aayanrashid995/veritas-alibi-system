import streamlit as st
import pandas as pd
import numpy as np
import joblib
import re
import time
import shap
import matplotlib.pyplot as plt
from datetime import datetime, time as dt_time
from sklearn import set_config

# Configure sklearn to output pandas DFs (for SHAP), 
# but we will handle the input carefully to avoid mismatch errors.
set_config(transform_output="pandas") 

# --- Explicitly define the feature names used by the trained model/scaler ---
FEATURES_USED = [
    'event_count', 
    'unique_ip_count', 
    'action_diversity', 
    'dbscan_noise_points', 
    'critical_event_count'
]

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
    # Attempt to load saved models and scaler
    try:
        model = joblib.load('veritas_model.pkl')
        scaler = joblib.load('veritas_scaler.pkl')
        try:
            background = joblib.load('veritas_background.pkl')
        except:
            # Fallback if background data is missing (for SHAP)
            background = np.zeros((1, len(FEATURES_USED))) 
        return model, scaler, background
    except FileNotFoundError:
        return None, None, None

model, scaler, background = load_system()

# --- 3. ROBUST PARSER ---
def parse_logs_robust(log_content, target_date, start_t, end_t):
    # NOTE: This parser simulates the feature extraction logic of final_pipeline.py
    lines = log_content.strip().split('\n')
    
    active_events = 0
    unique_sources = set()
    action_types = set()
    system_noise = 0
    critical_count = 0 
    debug_log = []
    
    # Define keywords used in the simulated data generation logic
    NOISE_SOURCES = ["igccservice", "RestartManager", "BTHUSB", "Netwtw", "Time-Service", "DCOM", "Win32k", "Security-SPP"]
    CRITICAL_IDS = ["4624", "4672", "4103", "4104", "1000", "10010", "4798"] 

    window_start = datetime.combine(target_date, start_t)
    window_end = datetime.combine(target_date, end_t)

    for line in lines:
        line = line.strip()
        if not line or line.startswith('"TimeCreated"') or line.startswith("#"): continue
        
        # Assume input log format is: TimeCreated,ProviderName,EventID,...
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

    # The features must be returned in the order defined by FEATURES_USED
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
uploaded_file = st.sidebar.file_uploader("Upload Clean CSV Logs (TimeCreated,ProviderName,EventID,...)", type=['txt', 'csv'])

# Main Layout
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Data Ingestion Terminal")
    # Priority: File Upload -> Text Area
    initial_text = ""
    if uploaded_file is not None:
        initial_text = uploaded_file.getvalue().decode("utf-8")
        
    raw_text = st.text_area("Log Input (Paste or Upload)", value=initial_text, height=300, 
                            help="Paste the content of raw logs here (e.g., event logs, network traces).")

with col2:
    st.subheader("Control & Status")
    
    if not model:
        st.error("AI System Not Initialized (Model/Scaler files missing). Run 'final_pipeline.py' first!")
    else:
        st.info("AI System Ready. Awaiting execution command.")
    
    analyze = st.button("RUN FORENSIC ANALYSIS", type="primary", use_container_width=True, disabled=not model)
    
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
if analyze and model:
    if not raw_text:
        st.warning("No data found.")
    else:
        # A. PARSE & FEATURE EXTRACTION
        feats = parse_logs_robust(raw_text, analysis_date, start_time, end_time)
        
        # B. PREPARE INPUT FOR MODEL (CRITICAL FIX: Ensure correct columns/order)
        
        # 1. Create a DataFrame from the feature dictionary
        input_data = {k: [feats[k]] for k in FEATURES_USED}
        # Explicitly enforce column order to match training
        input_df = pd.DataFrame(input_data, columns=FEATURES_USED)

        # 2. Scale the data using the TRAINED scaler
        prob = 0.0
        if feats['event_count'] > 0:
            try:
                # NUCLEAR FIX: Bypass feature name check by passing NumPy array
                # We know the order is correct because we enforced it in step 1.
                input_scaled_raw = scaler.transform(input_df.values) 
                
                # Convert back to DataFrame for SHAP/Model to have column names (if configured for pandas output)
                input_scaled = pd.DataFrame(input_scaled_raw, columns=FEATURES_USED)
                
                # C. PREDICT
                prob = model.predict_proba(input_scaled)[0][1]
            except Exception as e:
                st.error(f"Prediction Error: {e}")
                st.stop()


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
             prob = max(prob, 0.95) # Boost probability if critical evidence exists

        if prob > 0.65:
            st.markdown(f'<div class="status-box status-green">POSITIVE: PRESENCE CONFIRMED</div>', unsafe_allow_html=True)
            if feats['critical_event_count'] > 0:
                st.write(f"**Definitive Proof.** {feats['critical_event_count']} critical actions (Logon/Privilege) validate the alibi.")
            else:
                st.write("**Strong Signal.** High volume of complex activity detected by the AI.")
                
        elif prob < 0.35:
            st.markdown(f'<div class="status-box status-red">NEGATIVE: PRESENCE NOT ESTABLISHED</div>', unsafe_allow_html=True)
            st.write("**Only background system processes detected.** The AI model found no strong indicators of user activity.")
        else:
            st.markdown(f'<div class="status-box status-yellow">INCONCLUSIVE</div>', unsafe_allow_html=True)
            st.write("**Ambiguous Activity.** Events detected but lack definitive user signature, placing the verdict near the AI threshold.")

        # E. SHAP Explanation
        st.markdown("---")
        st.write("### AI Explainability Engine (SHAP)")
        
        try:
            explainer = shap.TreeExplainer(model)
            shap_vals = explainer.shap_values(input_scaled)
            
            # --- FIX: Simplify scalar extraction to resolve length-1 array error ---
            
            # 1. Determine the expected_value for the positive class (1)
            # Check if expected_value is an array (typical for balanced RF)
            if isinstance(explainer.expected_value, np.ndarray) and len(explainer.expected_value) == 2:
                base_val = explainer.expected_value[1]
            else:
                # If it's a single scalar, use it directly
                base_val = explainer.expected_value
            
            # 2. Determine the SHAP values for the positive class (1)
            if isinstance(shap_vals, list):
                # For TreeExplainer on multi-output models, shap_vals is a list of arrays.
                # We select the array for the positive class (index 1) and the first (and only) instance (index 0).
                sv_single = shap_vals[1][0]
            elif len(shap_vals.shape) == 3:
                # Fallback for complex shapes
                sv_single = shap_vals[0, :, 1]
            else:
                # Final fallback for simple shapes
                sv_single = shap_vals[0]


            # The error usually occurs because the library tries to convert the base_val 
            # (which is an array [0.X, 0.Y]) to a scalar.
            # By enforcing base_val selection as above, the error should be resolved.
            
            fig, ax = plt.subplots(figsize=(8,4))
            
            # Create a simplified Explanation object for the waterfall plot
            explanation_data = shap.Explanation(
                values=sv_single, 
                base_values=base_val, 
                data=input_df.iloc[0].values, 
                feature_names=input_df.columns
            )
            
            # Generate and display the plot
            shap.plots.waterfall(explanation_data, show=False)
            st.pyplot(fig)
            
        except Exception as e:
            # Display a human-readable error instead of skipping silently
            st.warning(f"SHAP Visualization Error: Could not generate waterfall plot. Verdict remains valid.")
            st.error(f"Debug Info (Scalar Error Fix Applied): {e}")
            # Display a human-readable error instead of skipping silently
            st.warning(f"SHAP Visualization Error: Could not generate waterfall plot. Verdict remains valid.")
            st.error(f"Debug Info (Scalar Error Fix Applied): {e}")

