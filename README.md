🛡️ VERITAS: Digital Alibi Verification System  
AI-Powered Timeline Reconstruction for Cyber Incident Attribution  

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28-red)
![Scikit-Learn](https://img.shields.io/badge/AI-Random%20Forest-orange)
![SHAP](https://img.shields.io/badge/Explainability-SHAP-green)

Course: CS-351 Artificial Intelligence  
Institution: Ghulam Ishaq Khan Institute of Engineering Sciences and Technology (GIKI)  
Semester Project: Week 13 Deliverable (Final System)

---

📖 Project Overview  
In cybersecurity investigations, determining whether a suspect was digitally active during a specific incident window is a critical task. Traditional log analysis is manual, time-consuming, and prone to human error.

Veritas is an AI-powered forensic tool designed to verify digital alibis. It parses raw system logs, filters them by a strict timeframe, and uses a machine learning model to distinguish between Active Human Behavior and Passive System Noise (e.g., background updates, telemetry).

🎯 Key Objectives  
1. Parse & Clean: Ingest raw Windows/PowerShell logs using Regex-based parsing.  
2. Verify Presence: Use a Random Forest Classifier to determine if a user was active during a disputed timeframe.  
3. Explain Verdicts: Utilize SHAP (SHapley Additive exPlanations) to provide transparent reasoning for every AI decision.  
4. Visualize: Provide a sleek, dark-mode dashboard for investigators.  

---

⚙️ Tech Stack  
Frontend: Streamlit (Python)  
Machine Learning: Scikit-Learn (Random Forest)  
Explainability: SHAP (Waterfall Plots)  
Data Processing: Pandas, NumPy, Regex  
Persistence: Joblib (Model serialization)  

---

🚀 Installation & Setup  

Prerequisites  
- Python 3.8 or higher  
- Git  

1. Clone the Repository  
```bash
git clone https://github.com/YOUR_USERNAME/veritas-alibi-system.git
cd veritas-alibi-system
```

2. Install Dependencies  
```bash
pip install -r requirements.txt
```

3. Initialize the AI Model (Crucial Step)  
Before running the interface, you must generate the forensic training data and train the model. This script creates the `.pkl` files ("the brain").  

```bash
python final_pipeline.py
```

Output: "✅ System Ready. Artifacts saved: veritas_model.pkl..."

4. Launch the Dashboard  
```bash
streamlit run app.py
```

---

🖥️ Usage Guide  

Case Configuration (Sidebar)  
- Enter the Case ID and Target Date.  
- Set the Verification Window (Start Time & End Time). Logs outside this window are ignored.  

Log Ingestion  
- Paste raw logs into the Terminal Input box.  
- Supported formats: Windows Event Viewer, PowerShell `Get-EventLog`, or standard timestamped text logs.  

Analysis  
- Click RUN FORENSIC ANALYSIS.  
- Green Verdict: Human Presence Confirmed.  
- Red Verdict: Inactive/Passive (only system noise detected).  
- Yellow Verdict: Inconclusive (high noise, low signal).  

Interpretation  
- Review the SHAP Waterfall Plot to see which features (Event Count, IP Diversity, Noise Score) drove the decision.  

---

🧠 Methodology & Logic  

Feature Engineering  
The system extracts four key features from raw text logs:  
- `event_count`: Total valid logs inside the window.  
- `unique_ip_count`: Distinct source addresses.  
- `action_diversity`: Distinct types of operations performed.  
- `dbscan_noise_points`: Count of known background processes (e.g., Netwtw14, EventLog, Service Control Manager).  

The AI Model  
We utilize a Random Forest Classifier trained on 2,000 synthetic forensic samples.  
- Logic: The model learns that high event counts combined with high system noise often indicates inactivity, whereas specific interaction patterns indicate human presence.  
- Confidence Penalty: If the ratio of Noise-to-Events is too high, the system reduces the confidence score to prevent False Positives.  

---

📂 Project Structure  
```text
veritas-alibi-system/
├── app.py                # Main Streamlit Interface (Frontend)
├── final_pipeline.py     # Data Generation & Model Training (Backend)
├── requirements.txt      # List of dependencies
├── veritas_model.pkl     # Trained Random Forest Model (Generated)
├── veritas_scaler.pkl    # Feature Scaler (Generated)
└── README.md             # Documentation
```

---

👥 Authors  
Aayan Rashid (2023002)  
Muaaz Bin Salman (2023338)  

Faculty: Department of Computer Science & Engineering, GIKI  

---

This project was developed for the CS-351 Artificial Intelligence Semester Project (Fall 2025).
