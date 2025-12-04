import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# --- 1. FORENSIC DATA GENERATION ---
# We simulate 2000 cases to teach the AI what "Guilty" vs "Innocent" looks like.
def generate_forensic_data(n_samples=2000):
    np.random.seed(42)
    data = []
    
    for _ in range(n_samples):
        # Ground Truth: 0 = Innocent (Inactive), 1 = Guilty (Active)
        is_guilty = np.random.choice([0, 1])
        
        if is_guilty == 0:
            # INNOCENT: Mostly zero activity, but some "system noise" is allowed
            event_count = np.random.choice([0, 0, 0, 1, 2, 3]) # Mostly 0, rarely up to 3
            unique_ips = 1 if event_count > 0 else 0
            action_div = 1 if event_count > 0 else 0
            noise_points = 0
            
            # 10% chance of high noise (e.g., Windows Update running in background)
            if np.random.rand() < 0.1:
                event_count = np.random.randint(5, 15)
                unique_ips = 1
                noise_points = np.random.randint(3, 8) # High noise, but low IP diversity
                
        else:
            # GUILTY: User was actually there
            event_count = np.random.randint(5, 50)
            unique_ips = np.random.randint(1, 4)
            action_div = np.random.randint(2, 6)
            noise_points = np.random.randint(0, 3) # Humans are usually consistent/low noise
            
            # 5% chance of "Stealth Attack" (Trying to look innocent)
            if np.random.rand() < 0.05:
                event_count = np.random.randint(1, 4)
                unique_ips = 2 # Suspicious: Low events but changing IPs
                action_div = 2
        
        data.append([event_count, unique_ips, action_div, noise_points, is_guilty])
        
    df = pd.DataFrame(data, columns=['event_count', 'unique_ip_count', 'action_diversity', 'dbscan_noise_points', 'verdict'])
    return df

# --- 2. TRAINING THE MODEL ---
print("--- PHASE 1: Training Forensic AI Model ---")
df = generate_forensic_data()
X = df.drop('verdict', axis=1)
y = df['verdict']

# Scale features (Standardize numbers)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Random Forest Classifier (The Brain)
model = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
model.fit(X_scaled, y)

print("✅ Model Trained successfully.")

# --- 3. SAVING ARTIFACTS ---
# We save these files so the Interface app can load them later
joblib.dump(model, 'veritas_model.pkl')
joblib.dump(scaler, 'veritas_scaler.pkl')
# Save a small sample for SHAP background data
joblib.dump(X_scaled[:100], 'veritas_background.pkl')

print("✅ System Ready. Artifacts saved: veritas_model.pkl, veritas_scaler.pkl")