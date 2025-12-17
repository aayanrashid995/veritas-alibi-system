import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn import set_config

# CRITICAL CONFIGURATION: Ensure Pandas output to fix feature name mismatch in deployment
set_config(transform_output="pandas")

# 1. Define the EXACT feature list (5 Features) - Global Source of Truth
FEATURES_USED = [
    'event_count', 
    'unique_ip_count', 
    'action_diversity', 
    'dbscan_noise_points', 
    'critical_event_count' 
]

def generate_realistic_forensic_data(n_samples=3000):
    np.random.seed(42)
    data = []
    
    for _ in range(n_samples):
        # 0 = Inactive, 1 = Active
        is_active = np.random.choice([0, 1])
        
        # Initialize features with noise
        event_count = 0
        unique_ips = 0
        action_div = 0
        noise = 0
        critical = 0

        if is_active == 0:
            # INACTIVE: Low events, high noise
            event_count = np.random.randint(0, 8)
            noise = np.random.randint(5, 25) 
            # Rare false positive critical event
            if np.random.rand() < 0.05: critical = 1 
            
        else:
            # ACTIVE: Heavy or Stealth usage
            if np.random.rand() > 0.6:
                event_count = np.random.randint(40, 150)
                unique_ips = np.random.randint(3, 15)
                action_div = np.random.randint(4, 12)
                critical = np.random.randint(1, 4)
                noise = np.random.randint(0, 10)
            else:
                # Stealth
                event_count = np.random.randint(4, 15)
                unique_ips = 1
                action_div = np.random.randint(1, 3)
                critical = np.random.choice([0, 0, 1]) 
                noise = np.random.randint(2, 8)

        data.append([event_count, unique_ips, action_div, noise, critical, is_active])
        
    # Return DataFrame with correct 5 feature columns + verdict
    return pd.DataFrame(data, columns=FEATURES_USED + ['verdict'])

if __name__ == "__main__":
    print("🧠 Training Realistic Forensic Model (5 Features)...")
    
    # 1. Generate Data 
    df = generate_realistic_forensic_data()
    
    # Select features and target explicitly
    X = df[FEATURES_USED]
    y = df['verdict']
    
    print(f"Feature shape: {X.shape} (Should be 3000, 5)")
    
    # 2. Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 3. Scale (Fit on Training Data)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 4. Train 
    model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    # 5. Evaluate
    preds = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, preds)
    print(f"\n✅ Realistic Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, preds))
    
    # 6. Final Fit and Save (CRITICAL STEP)
    # Refit scaler on ALL data (X) to capture full range stats
    scaler.fit(X) 
    
    # Transform X using the fitted scaler for the final model training
    X_scaled_full = scaler.transform(X)
    model.fit(X_scaled_full, y)
    
    joblib.dump(model, 'veritas_model.pkl')
    joblib.dump(scaler, 'veritas_scaler.pkl')
    # Save a small sample for SHAP background
    joblib.dump(X.iloc[:100], 'veritas_background.pkl')
    
    print("💾 System Artifacts Saved. The Scaler now expects exactly 5 features.")

