import joblib
import random
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# =============================
# Load model + encoders
# =============================
model = joblib.load("threat_model.pkl")
protocol_encoder = joblib.load("protocol_encoder.pkl")
feature_order = joblib.load("feature_order.pkl")

# =============================
# Email Alert Function
# =============================
SENDER_EMAIL = "adityakhiroji7@gmail.com"   # <-- replace with your Gmail
APP_PASSWORD = "sqwpxjhiormwymbj"      # <-- replace with your Gmail App Password
RECEIVER_EMAIL = "adityakhiroji2@gmail.com"  # <-- where alert should go

def send_email_alert(log):
    subject = "⚠️ AI Threat Detection Alert"
    body = f"""
    A potential threat has been detected:

    Source IP: {log['src_ip']}
    Destination IP: {log['dst_ip']}
    Protocol: {log['protocol']}
    Login Attempts: {log['login_attempts']}
    Packet Size: {log['packet_size']}
    Connections/min: {log['connections_per_min']}
    Hour: {log['hour']}

    Please check immediately.
    """

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print("📧 Email alert sent successfully!")
    except Exception as e:
        print("❌ Failed to send email:", e)

# =============================
# Simulation + Prediction
# =============================
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
    protocol_encoded = protocol_encoder.transform([log["protocol"]])[0]

    features = {
        "login_attempts": log["login_attempts"],
        "packet_size": log["packet_size"],
        "connections_per_min": log["connections_per_min"],
        "hour": log["hour"],
        "protocol": protocol_encoded
    }

    df = pd.DataFrame([[features[col] for col in feature_order]], columns=feature_order)
    return df

# =============================
# Main Loop
# =============================
for _ in range(3):
    log = simulate_log()
    features = preprocess_log(log)
    prediction = model.predict(features)[0]

    if prediction == 1:
        status = "⚠️ THREAT"
        send_email_alert(log)   # 🚨 Send email when threat detected
    else:
        status = "✅ NORMAL"

    print(f"Log → {log}  ⇒  {status}")
