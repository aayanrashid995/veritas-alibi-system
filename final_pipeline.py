import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

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
            # INACTIVE: Mostly quiet, but sometimes high noise
            event_count = np.random.randint(0, 8)
            noise = np.random.randint(5, 25) 
            # TRICK: Sometimes system accounts generate "critical-like" events (False Positives)
            if np.random.rand() < 0.05: 
                critical = 1 
            
        else:
            # ACTIVE: Real usage
            # Scenario A: Heavy Usage
            if np.random.rand() > 0.6:
                event_count = np.random.randint(40, 150)
                unique_ips = np.random.randint(3, 15)
                action_div = np.random.randint(4, 12)
                critical = np.random.randint(1, 4)
                noise = np.random.randint(0, 10)
            
            # Scenario B: Stealth/Light Usage (Hard to detect)
            else:
                event_count = np.random.randint(4, 15)
                unique_ips = 1
                action_div = np.random.randint(1, 3)
                critical = np.random.choice([0, 0, 1]) # Often no critical event found!
                noise = np.random.randint(2, 8)

        data.append([event_count, unique_ips, action_div, noise, critical, is_active])
        
    return pd.DataFrame(data, columns=['event_count', 'unique_ip_count', 'action_diversity', 'dbscan_noise_points', 'critical_event_count', 'verdict'])

if __name__ == "__main__":
    print("🧠 Training Realistic Forensic Model...")
    
    # 1. Generate Data (Now with noise/errors)
    df = generate_realistic_forensic_data()
    X = df.drop('verdict', axis=1)
    y = df['verdict']
    
    # 2. Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 3. Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 4. Train (Reduced depth to prevent overfitting on the noise)
    model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    # 5. Evaluate (Should now be ~0.90 - 0.96, NOT 1.0)
    preds = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, preds)
    print(f"\n✅ Realistic Accuracy: {acc*100:.2f}%")
    print("Detailed Report (Notice F1 is not 1.0):")
    print(classification_report(y_test, preds))
    
    # 6. Save
    scaler.fit(X) 
    model.fit(scaler.transform(X), y)
    
    joblib.dump(model, 'veritas_model.pkl')
    joblib.dump(scaler, 'veritas_scaler.pkl')
    joblib.dump(scaler.transform(X.iloc[:100]), 'veritas_background.pkl')
    print("💾 System Artifacts Saved.")