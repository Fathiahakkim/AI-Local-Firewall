# firewall_sniffer.py

from scapy.all import sniff, IP
import joblib
import pandas as pd

# Load your trained AI model
model = joblib.load("firewall_model.pkl")

# Prediction function
def predict_packet(packet):
    if IP in packet:
        size = len(packet)
        proto = packet[IP].proto

        # FIX: Use DataFrame with column names
        df = pd.DataFrame([[size, proto]], columns=["packet_size", "protocol"])
        prediction = model.predict(df)[0]

        if prediction == 1:
            print(f"🚨 Suspicious packet detected: Size={size}, Protocol={proto}")
            with open("suspicious_log.txt", "a") as log:
                log.write(f"[SUSPICIOUS] Size={size}, Protocol={proto}\n")
        else:
            print(f"✅ Safe packet: Size={size}, Protocol={proto}")
            with open("suspicious_log.txt", "a") as log:
                log.write(f"[SAFE] Size={size}, Protocol={proto}\n")


# Start sniffing
print("🔥 Sniffing... Press Ctrl+C to stop.")
sniff(prn=predict_packet, filter="ip", store=0)
