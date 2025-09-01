# app.py — Streamlit dashboard using project_utils
import os, time
import pandas as pd
import streamlit as st
import project_utils as U

st.set_page_config("AI Threat Detection Dashboard", layout="wide")
st.title("🛡️ AI-Driven Threat Detection Dashboard")

# -------- Sidebar configuration --------
with st.sidebar:
    st.header("Controls")
    n_train = st.number_input("Training rows to generate", 100, 10000, 1000, step=100)
    test_size = st.slider("Test size", 0.1, 0.5, 0.2, 0.05)
    n_logs = st.number_input("Logs to simulate (per run)", 1, 500, 20)

    st.divider()
    st.subheader("Email Alerts (Gmail App Password)")
    sender = st.text_input("Sender Gmail")
    app_pw = st.text_input("Gmail App Password", type="password")
    receiver = st.text_input("Receiver Email", value=sender)
    send_email = st.checkbox("Send email on THREAT", value=False)
    st.caption("Use a Google App Password (not your normal Gmail password).")

    st.divider()
    if st.button("Reset detection logs"):
        if os.path.exists(U.LOG_CSV):
            os.remove(U.LOG_CSV)
        st.success("Cleared cyber_logs.csv")

# -------- Buttons --------
col1, col2, col3 = st.columns(3)
with col1:
    gen_btn = st.button("① Generate Training Data")
with col2:
    train_btn = st.button("② Train / Save Model")
with col3:
    run_btn = st.button("③ Run Detection & Alerts")

status = st.empty()
chart_ph = st.empty()
table_ph = st.empty()
m1, m2 = st.columns(2)

# -------- Actions --------
if gen_btn:
    df = U.generate_training_data(n_train)
    status.info(f"✅ Generated {len(df)} rows → {U.TRAIN_CSV}")
    st.dataframe(df.head(10), use_container_width=True)

if train_btn:
    if not os.path.exists(U.TRAIN_CSV):
        st.warning("Generate training data first.")
    else:
        report, cm, model, le, feat_order = U.train_and_save(test_ratio=test_size)
        status.success("✅ Model trained & artifacts saved.")
        st.subheader("Classification Report")
        st.code(report, language="text")
        st.subheader("Confusion Matrix")
        st.write(pd.DataFrame(cm, index=["True 0","True 1"], columns=["Pred 0","Pred 1"]))

if run_btn:
    model, enc, feat_order = U.load_artifacts()
    if model is None:
        st.warning("Train the model first.")
    else:
        # Starting counts (include previous runs if file exists)
        normal_total, threat_total = U.get_overall_counts()
        status.info(f"▶️ Running detection for {int(n_logs)} simulated logs...")

        new_logs = []
        prog = st.progress(0)
        for i in range(int(n_logs)):
            log = U.simulate_log()
            pred = U.predict_one(model, enc, feat_order, log)
            U.append_log(log, pred)

            if pred == 1 and send_email:
                try:
                    U.send_email_alert(sender, app_pw, receiver, log)
                    st.toast("📧 Email alert sent", icon="✉️")
                except Exception as e:
                    st.error(f"Email failed: {e}")

            # update totals
            if pred == 1: threat_total += 1
            else: normal_total += 1

            # live UI updates
            new_logs.append({**log, "prediction": pred})
            with m1: st.metric("Normal (total)", normal_total)
            with m2: st.metric("Threat (total)", threat_total)

            chart_df = pd.DataFrame({"count":[normal_total, threat_total]}, index=["Normal","Threat"])
            chart_ph.bar_chart(chart_df)

            table_ph.dataframe(pd.DataFrame(new_logs), use_container_width=True, height=320)

            prog.progress((i+1)/int(n_logs))
            time.sleep(0.2)

        status.success("✅ Detection run complete.")

# Show latest detection summary if file exists
if os.path.exists(U.LOG_CSV):
    df_all = pd.read_csv(U.LOG_CSV)
    st.subheader("📄 All Detection Logs (cyber_logs.csv)")
    st.dataframe(df_all.tail(50), use_container_width=True)
