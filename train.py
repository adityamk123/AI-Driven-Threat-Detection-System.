import random
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump

# -----------------------------
# 1. Generate synthetic dataset
# -----------------------------
def generate_logs(n=1000):
    data = []
    for _ in range(n):
        protocol = random.choice(["TCP", "UDP", "ICMP"])
        login_attempts = random.randint(0, 20)
        packet_size = random.randint(50, 1500)
        connections_per_min = random.randint(1, 100)
        hour = random.randint(0, 23)

        # Label: mark as threat if suspicious pattern
        threat = 1 if (
            login_attempts > 10 or
            packet_size > 1000 or
            connections_per_min > 50 or
            (protocol == "ICMP" and hour < 6)
        ) else 0

        data.append([protocol, login_attempts, packet_size, connections_per_min, hour, threat])

    return pd.DataFrame(data, columns=[
        "protocol", "login_attempts", "packet_size",
        "connections_per_min", "hour", "threat"
    ])

# -----------------------------
# 2. Prepare dataset
# -----------------------------
df = generate_logs(2000)

# Encode protocol (categorical → numeric)
protocol_encoder = LabelEncoder()
df["protocol"] = protocol_encoder.fit_transform(df["protocol"])

X = df.drop("threat", axis=1)
y = df["threat"]

feature_order = X.columns.tolist()

# -----------------------------
# 3. Train model
# -----------------------------
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# -----------------------------
# 4. Evaluate
# -----------------------------
y_pred = model.predict(X)
print("✅ Model Performance")
print(classification_report(y, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y, y_pred))

# -----------------------------
# 5. Save model + encoders
# -----------------------------
dump(model, "threat_model.pkl")
dump(protocol_encoder, "protocol_encoder.pkl")
dump(feature_order, "feature_order.pkl")

print("✅ Saved: threat_model.pkl, protocol_encoder.pkl, feature_order.pkl")
