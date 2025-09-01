import pandas as pd
import random

# Synthetic network/security log generator
# Features: src_ip, dst_ip, protocol, login_attempts, packet_size, connections_per_min, hour, label

def rand_ip(prefix):
    return f"{prefix}.{random.randint(1, 254)}"

protocols = ["TCP", "UDP", "ICMP"]
rows = []

for i in range(2000):
    src_ip = rand_ip("192.168.1")
    dst_ip = rand_ip("10.0.0")
    protocol = random.choice(protocols)
    login_attempts = random.randint(0, 25)          # brute-force simulation
    packet_size = random.randint(40, 1600)          # bytes
    connections_per_min = random.randint(1, 200)    # traffic burstiness
    hour = random.randint(0, 23)                     # time-of-day pattern

    # Labeling rule-of-thumb (you can tweak later):
    # Suspicious if high login attempts or very large packets or unusual burst at odd hours.
    is_bruteforce = login_attempts >= 10
    is_excessive_packet = packet_size >= 1300
    is_burst_odd_hour = (connections_per_min >= 120 and hour in [1,2,3,4])

    label = 1 if (is_bruteforce or is_excessive_packet or is_burst_odd_hour) else 0

    rows.append({
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "login_attempts": login_attempts,
        "packet_size": packet_size,
        "connections_per_min": connections_per_min,
        "hour": hour,
        "label": label
    })

df = pd.DataFrame(rows)
df.to_csv("cyber_logs.csv", index=False)
print("✅ Dataset generated → cyber_logs.csv")
print(df.head())
