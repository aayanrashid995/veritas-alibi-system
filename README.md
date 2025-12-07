

````markdown
# 🛡️ VERITAS: Digital Alibi Verification System
### AI-Powered Forensic Timeline Reconstruction & Attribution

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32-red)
![Scikit-Learn](https://img.shields.io/badge/AI-Random%20Forest-orange)
![SHAP](https://img.shields.io/badge/Explainability-SHAP-green)

**Course:** CS-351 Artificial Intelligence  
**Institution:** Ghulam Ishaq Khan Institute of Engineering Sciences and Technology (GIKI)  
**Semester Project:** Final Deliverable (Week 13)

---

## 📖 Executive Summary
**Veritas** is a forensic intelligence tool designed to automate the validation of digital alibis. In cybersecurity investigations, determining if a user was physically present at a machine during a specific timeframe is often manual and error-prone.

Veritas solves this by parsing raw system logs (PowerShell/Event Viewer), extracting behavioral features, and using a **Random Forest Classifier** to distinguish between **Active Human Presence** and **Passive System Noise**. It uniquely prioritizes "Critical Artifacts" (e.g., Logons, Privilege Escalation) while filtering out thousands of background maintenance events.

---

## 🌟 Key Features

### 1. Robust Log Ingestion 📂
* **Universal Parser:** Automatically handles widely-spaced PowerShell `Format-Table` output, CSV exports, and raw text.
* **Strict Time Windowing:** Filters millions of logs down to the exact second of the alibi window.
* **File Upload Support:** Drag-and-drop `.txt` or `.csv` log files directly into the interface.

### 2. Intelligent Feature Engineering 🧠
The system doesn't just count logs; it understands them. It extracts 5 key forensic vectors:
* **Event Volume:** Total activity in the window.
* **Critical Actions:** Count of high-fidelity user markers (Event ID 4624, 4672, 4103).
* **Action Diversity:** Variety of distinct operations (prevents bots from looking like humans).
* **Source Complexity:** Unique providers/IPs involved.
* **System Noise:** Quantification of background telemetry (ignored by the AI).

### 3. "Grey Area" Machine Learning 🤖
* **Model:** Random Forest Classifier (n=200, depth=12).
* **Training Strategy:** Trained on **3,000 synthetic forensic cases** that include "False Positive" scenarios (e.g., system updates running under user accounts).
* **Performance:** Achieves **~94-96% Accuracy** (deliberately not 100% to reflect real-world ambiguity).

### 4. Explainable Verdicts 📊
* **Traffic Light System:**
    * 🟢 **POSITIVE:** Confirmed Presence (Critical events found).
    * 🟡 **INCONCLUSIVE:** High activity but lacks definitive user signatures.
    * 🔴 **NEGATIVE:** Only background noise detected.
* **SHAP Analysis:** Includes Waterfall plots to show exactly *why* the AI reached its decision (e.g., "+20% confidence due to Login Event").

---

## ⚙️ Tech Stack & Architecture
* **Frontend:** Streamlit (Python) with Custom CSS for Cyber-Themed UI.
* **Backend:** Scikit-Learn (Random Forest).
* **Data Processing:** Pandas & NumPy (Vectorization).
* **Explainability:** SHAP (SHapley Additive exPlanations).
* **Regex Engine:** Custom patterns for handling `Format-Table` padding issues.

---

## 🚀 Installation & Usage

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/veritas-alibi-system.git](https://github.com/YOUR_USERNAME/veritas-alibi-system.git)
cd veritas-alibi-system
````

### 2\. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3\. Initialize the AI Brain

Before running the app, you must generate the training data and compile the model.

```bash
python final_pipeline.py
```

*Output: "✅ Realistic Accuracy: 95.4% ... Artifacts Saved."*

### 4\. Launch the Dashboard

```bash
python -m streamlit run app.py
```

-----

## 🧪 Forensic Log Generation (PowerShell)

To test the system with **Real-World Evidence**, run this command in Administrator PowerShell to generate a clean log file:

```powershell
$StartDate = Get-Date "2025-12-07 19:00:00"
$EndDate = Get-Date "2025-12-07 22:00:00"

Get-WinEvent -FilterHashtable @{
    LogName='Security', 'Application'
    StartTime=$StartDate
    EndTime=$EndDate
} -ErrorAction SilentlyContinue | 
Select-Object @{N='TimeCreated'; E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, ProviderName, Id, Message |
ConvertTo-Csv -NoTypeInformation | 
Select-Object -Skip 1 | 
Out-File "C:\Forensics\clean_logs.txt" -Encoding UTF8
```

*Upload the resulting `clean_logs.txt` into the Veritas sidebar.*

-----

## 📂 Project Structure

```text
veritas-alibi-system/
├── app.py                # Main Streamlit Dashboard (Frontend)
├── final_pipeline.py     # ML Training & Data Generation (Backend)
├── requirements.txt      # Python dependencies
├── veritas_model.pkl     # Trained Random Forest Model (Generated)
├── veritas_scaler.pkl    # Feature Scaler (Generated)
├── veritas_background.pkl# Background data for SHAP (Generated)
└── README.md             # Documentation
```

-----

## 👥 Authors

  * **Aayan Rashid** (2023002)
  * **Muaaz Bin Salman** (2023338)

**Faculty:** Department of Computer Science & Engineering, GIKI.

```
```-351 Artificial Intelligence Semester Project (Fall 2025).
