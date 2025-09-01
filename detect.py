import joblib
import random
import pandas as pd

# Load the saved model + encoders + feature order
model = joblib.load("threat_model.pkl")
protocol_encoder = joblib.load("protocol_encoder.pkl")
feature_order = joblib.load("feature_order.pkl")

def simulate_log():
    return {
        "src_ip": f"192.168.1.{random.randint(1, 100)}",
        "dst_ip": f"10.0.0.{random.randint(1, 50)}",
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "login_attempts": random.randint(0, 20),
        "packet_size": random.randint(40, 1500),
        "connections_per_min": random.randint(1, 100),
        "hour": random.randint(0, 23)
    }

def preprocess_log(log):
    # Encode protocol
    protocol_encoded = protocol_encoder.transform([log["protocol"]])[0]

    # Build feature dict with correct keys
    features = {
        "login_attempts": log["login_attempts"],
        "packet_size": log["packet_size"],
        "connections_per_min": log["connections_per_min"],
        "hour": log["hour"],
        "protocol": protocol_encoded
    }

    # Create DataFrame with correct column order
    df = pd.DataFrame([[features[col] for col in feature_order]], columns=feature_order)
    return df

for _ in range(3):
    log = simulate_log()
    features = preprocess_log(log)
    prediction = model.predict(features)[0]

    status = "⚠️ THREAT" if prediction == 1 else "✅ NORMAL"
    print(f"Log → {log}  ⇒  {status}")
