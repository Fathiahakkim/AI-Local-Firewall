# firewall_ai.py

from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import joblib

# 1. Generate fake firewall dataset
data = {
    'packet_size': [200, 450, 1300, 60, 800, 1500, 500, 70, 1000, 60],
    'protocol': [1, 2, 1, 3, 2, 1, 3, 1, 2, 3],
    'is_malicious': [0, 0, 1, 1, 0, 1, 0, 1, 0, 1]
}
df = pd.DataFrame(data)

# 2. Split features (X) and label (y)
X = df[['packet_size', 'protocol']]
y = df['is_malicious']

# 3. Train the model
model = RandomForestClassifier()
model.fit(X, y)

# 4. Save the model
joblib.dump(model, 'firewall_model.pkl')

# 5. Show accuracy (on the same training data)
print("Accuracy:", model.score(X, y))
print("✅ Model saved as firewall_model.pkl")
