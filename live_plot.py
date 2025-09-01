import pandas as pd
import matplotlib.pyplot as plt
import time

plt.ion()  # Turn on interactive mode
fig, ax = plt.subplots()

while True:
    try:
        df = pd.read_csv("cyber_logs.csv")   # Read the log file
        counts = df["label"].value_counts().sort_index()
        
        ax.clear()
        counts.plot(kind="bar", ax=ax, color=["green", "red"])
        ax.set_title("Threat (1) vs Normal (0) Logs (Live)")
        ax.set_xlabel("Label (0=Normal, 1=Threat)")
        ax.set_ylabel("Count")
        
        plt.draw()
        plt.pause(2)   # refresh every 2 seconds

    except Exception as e:
        print(f"⚠️ Error reading/updating chart: {e}")
        time.sleep(2)
