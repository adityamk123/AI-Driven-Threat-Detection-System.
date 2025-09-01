# project_utils.py
import os, csv, time, random, smtplib
import pandas as pd
import joblib
from email.mime.text import MIMEText
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# Files used across the project
TRAIN_CSV = "train_data.csv"
LOG_CSV   = "cyber_logs.csv"
MODEL_PKL = "threat_model.pkl"
ENC_PKL   = "protocol_encoder.pkl"
FEATS_PKL = "feature_order.pkl"

# ---------------- Email ----------------
def send_email_alert(sender: str, app_pw: str, receiver: str, log_dict: dict):
    """Send email via Gmail SMTP using App Password."""
    subject = "⚠️ AI Threat Detection Alert"
    body = (
        "A potential threat was detected:\n\n"
        + "\n".join(f"{k}: {v}" for k, v in log_dict.items())
        + "\n\nPlease investigate."
    )
    msg = MIMEText(body)
    msg["From"], msg["To"], msg["Subject"] = sender, receiver, subject
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, app_pw)
        server.sendmail(sender, receiver, msg.as_string())

# ---------------- Data Generation ----------------
def generate_training_data(n_rows=1000) -> pd.DataFrame:
    """Create synthetic training data and save to train_data.csv"""
    protocols = ["TCP", "UDP", "ICMP"]
    data = []
    for _ in range(n_rows):
        log = {
            "src_ip": f"192.168.1.{random.randint(1, 254)}",
            "dst_ip": f"10.0.0.{random.randint(1, 254)}",
            "protocol": random.choice(protocols),
            "login_attempts": random.randint(0, 20),
            "packet_size": random.randint(20, 1600),
            "connections_per_min": random.randint(1, 200),
            "hour": random.randint(0, 23),
        }
        # simple rule-based labeling for synthetic data
        label = 1 if (
            log["login_attempts"] > 10 or
            log["packet_size"] > 1300 or
            (log["connections_per_min"] > 120 and log["hour"] in [1,2,3,4])
        ) else 0
        log["label"] = label
        data.append(log)
    df = pd.DataFrame(data)
    df.to_csv(TRAIN_CSV, index=False)
    return df

# ---------------- Training ----------------
def train_and_save(test_ratio=0.2):
    """Train model, save artifacts, and return metrics + artifacts."""
    df = pd.read_csv(TRAIN_CSV)

    le = LabelEncoder()
    df["protocol"] = le.fit_transform(df["protocol"])

    X = df.drop(columns=["label", "src_ip", "dst_ip"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_ratio, random_state=42, stratify=y
    )
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # Save artifacts
    joblib.dump(model, MODEL_PKL)
    joblib.dump(le, ENC_PKL)
    joblib.dump(list(X.columns), FEATS_PKL)

    # Metrics
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    return report, cm, model, le, list(X.columns)

def load_artifacts():
    """Load model + encoder + feature order if present; else (None, None, None)."""
    if not (os.path.exists(MODEL_PKL) and os.path.exists(ENC_PKL) and os.path.exists(FEATS_PKL)):
        return None, None, None
    return joblib.load(MODEL_PKL), joblib.load(ENC_PKL), joblib.load(FEATS_PKL)

# ---------------- Detection helpers ----------------
def simulate_log():
    return {
        "src_ip": f"192.168.1.{random.randint(1, 254)}",
        "dst_ip": f"10.0.0.{random.randint(1, 254)}",
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "login_attempts": random.randint(0, 20),
        "packet_size": random.randint(40, 1600),
        "connections_per_min": random.randint(1, 200),
        "hour": random.randint(0, 23),
    }

def predict_one(model, encoder, feature_order, log_dict: dict) -> int:
    """Return 0/1 prediction for a single raw log."""
    enc_protocol = encoder.transform([log_dict["protocol"]])[0]
    features = {
        "login_attempts": log_dict["login_attempts"],
        "packet_size": log_dict["packet_size"],
        "connections_per_min": log_dict["connections_per_min"],
        "hour": log_dict["hour"],
        "protocol": enc_protocol,
    }
    X = pd.DataFrame([[features[c] for c in feature_order]], columns=feature_order)
    return int(model.predict(X)[0])

def append_log(log_dict: dict, prediction: int):
    """Append a detection result to cyber_logs.csv"""
    row = dict(log_dict)
    row["label"] = prediction
    write_header = not os.path.exists(LOG_CSV)
    with open(LOG_CSV, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(row)

def get_overall_counts():
    """Return (normal_count, threat_count) from cyber_logs.csv if exists."""
    normal, threat = 0, 0
    if os.path.exists(LOG_CSV):
        df = pd.read_csv(LOG_CSV)
        if "label" in df.columns:
            normal = int((df["label"] == 0).sum())
            threat = int((df["label"] == 1).sum())
    return normal, threat
