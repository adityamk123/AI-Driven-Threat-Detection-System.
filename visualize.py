import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("cyber_logs.csv")

counts = df["label"].value_counts().sort_index()
ax = counts.plot(kind="bar")
ax.set_title("Threat (1) vs Normal (0) Logs")
ax.set_xlabel("Label")
ax.set_ylabel("Count")
plt.tight_layout()
plt.show()
