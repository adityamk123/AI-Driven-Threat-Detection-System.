import pandas as pd
import random
import os
import csv
import joblib
import smtplib
from email.mime.text import MIMEText
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# ================== EMAIL CONFIG ==================
SENDER_EMAIL = "adityakhiroji7@gmail.com"        # Change this
APP_PASSWORD = "sqwpxjhiormwymbj"      # Gmail App password
RECEIVER_EMAIL = "adityakhiroji2@gmail.com"  # Receiver address

def send_email_alert(log):
    subject = "⚠️ Threat Detected in Network Logs"
    body = f"Threat detected!\n\nDetails:\n{log}"

    msg = MIMEText(body)
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        print("📧 Email alert sent!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# ================== STEP 1: Generate Synthetic Data ==================
def generate_training_data(n=500):
    protocols = ["TCP", "UDP", "ICMP"]
    data = []
    for _ in range(n):
        log = {
            "src_ip": f"192.168.1.{random.randint(1, 100)}",
            "dst_ip": f"10.0.0.{random.randint(1, 50)}",
            "protocol": random.choice(protocols),
            "login_attempts": random.randint(0, 20),
            "packet_size": random.randint(20, 1500),
            "connections_per_min": random.randint(1, 100),
            "hour": random.randint(0, 23),
        }
        # Label = Threat if abnormal
        label = 1 if (log["login_attempts"] > 5 or log["connections_per_min"] > 80 or log["packet_size"] > 1000) else 0
        log["label"] = label
        data.append(log)
    df = pd.DataFrame(data)
    df.to_csv("train_data.csv", index=False)
    print("✅ Training data generated → train_data.csv")
    return df

# ================== STEP 2: Train Model ==================
def train_model():
    df = pd.read_csv("train_data.csv")

    # Encode protocol
    le = LabelEncoder()
    df["protocol"] = le.fit_transform(df["protocol"])

    X = df.drop(columns=["label", "src_ip", "dst_ip"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    joblib.dump(model, "threat_model.pkl")
    joblib.dump(le, "protocol_encoder.pkl")
    joblib.dump(list(X.columns), "feature_order.pkl")

    print("✅ Model trained & saved → threat_model.pkl")
    return model, le, list(X.columns)

# ================== STEP 3: Simulate Detection ==================
def generate_log():
    protocols = ["TCP", "UDP", "ICMP"]
    return {
        "src_ip": f"192.168.1.{random.randint(1, 100)}",
        "dst_ip": f"10.0.0.{random.randint(1, 50)}",
        "protocol": random.choice(protocols),
        "login_attempts": random.randint(0, 20),
        "packet_size": random.randint(20, 1500),
        "connections_per_min": random.randint(1, 100),
        "hour": random.randint(0, 23)
    }

csv_file = "cyber_logs.csv"

def save_log(log, prediction):
    log["label"] = prediction
    write_header = not os.path.exists(csv_file)

    with open(csv_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=log.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(log)

def run_detection(model, encoder, feature_order, n=5):
    for _ in range(n):
        log = generate_log()
        log_features = log.copy()
        log_features["protocol"] = encoder.transform([log["protocol"]])[0]

        X = [[log_features[f] for f in feature_order]]
        prediction = model.predict(X)[0]

        status = "⚠️ THREAT" if prediction == 1 else "✅ NORMAL"
        print(f"Log → {log}  ⇒  {status}")

        save_log(log, prediction)

        if prediction == 1:
            send_email_alert(log)

# ================== STEP 4: Visualize ==================
def plot_results():
    if not os.path.exists("cyber_logs.csv"):
        print("ℹ️ No detection logs yet to visualize.")
        return
    df = pd.read_csv("cyber_logs.csv")
    counts = df["label"].value_counts().sort_index()
    ax = counts.plot(kind="bar", color=["green", "red"])
    ax.set_title("Threat (1) vs Normal (0) Logs")
    ax.set_xlabel("Label")
    ax.set_ylabel("Count")
    plt.tight_layout()
    plt.show()

# ================== MAIN PIPELINE ==================
if __name__ == "__main__":
    generate_training_data()
    model, encoder, feature_order = train_model()
    run_detection(model, encoder, feature_order, n=10)
    plot_results()
