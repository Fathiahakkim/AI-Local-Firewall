# firewall_gui.py

import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP
import joblib
import threading
import pandas as pd
from datetime import datetime

# Load trained model
model = joblib.load("firewall_model.pkl")

# Global flag for sniffing state
sniffing = False
sniff_thread = None

# GUI setup
window = tk.Tk()
window.title("AI Powered Local Firewall")
window.geometry("600x400")

log_display = scrolledtext.ScrolledText(window, width=70, height=20)
log_display.pack(pady=10)

def log_message(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{timestamp} {message}")
    with open("suspicious_log.txt", "a", encoding="utf-8") as f:
        f.write(f"{timestamp} {message}\n")



# Prediction function
def predict_packet(packet):
    if IP in packet:
        size = len(packet)
        proto = packet[IP].proto

        # Predict using model
        df = pd.DataFrame([[size, proto]], columns=["packet_size", "protocol"])
        prediction = model.predict(df)[0]

        if prediction == 1:
            log_message(f"🚨 Suspicious packet: Size={size}, Protocol={proto}")
        else:
            log_message(f"✅ Safe packet: Size={size}, Protocol={proto}")

def sniff_packets():
    sniff(prn=predict_packet, filter="ip", store=0, stop_filter=lambda x: not sniffing)

def start_firewall():
    global sniffing, sniff_thread
    if not sniffing:
        sniffing = True
        sniff_thread = threading.Thread(target=sniff_packets)
        sniff_thread.start()
        log_message("🔥 Sniffing started...")

def stop_firewall():
    global sniffing
    sniffing = False
    log_message("🛑 Sniffing stopped.")

# Buttons
start_btn = tk.Button(window, text="Start Firewall", command=start_firewall, bg="green", fg="white")
start_btn.pack(pady=5)

stop_btn = tk.Button(window, text="Stop Firewall", command=stop_firewall, bg="red", fg="white")
stop_btn.pack(pady=5)

window.mainloop()
