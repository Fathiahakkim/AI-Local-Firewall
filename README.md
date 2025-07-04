🔥 AI-Powered Local Firewall (Learning Project)

Hey there! 👋  
This is a personal learning project I built to understand how **AI + Cybersecurity** can work together. It's a **local AI-powered firewall** that detects suspicious network packets using a basic machine learning model (Random Forest) and logs them in real-time.

---

💡 About This Project

I created this project to explore how artificial intelligence can be used in real-time packet monitoring. It uses **Scapy** to sniff packets and a **trained ML model** to decide if the packet is suspicious based on features like **size** and **protocol**.

This is a beginner-friendly project focused on understanding AI-based detection, not a full production-level firewall.

---

🛠️ Features

- 📡 Real-time packet sniffing using Scapy
- 🤖 AI-based prediction (trained with RandomForestClassifier)
- 📊 Logs safe and suspicious packets separately
- 🖥️ Simple and clean Tkinter GUI
- 📝 Outputs stored in a log file (`suspicious_log.txt`)

---

📁 Files Included

- `firewall_sniffer.py` – Packet analysis and prediction script  
- `firewall_gui.py` – GUI interface to control the firewall  
- `firewall_model.pkl` – Pretrained ML model  
- `suspicious_log.txt` – Stores output of sniffing  

---

🧪 How It Works

1. You run the GUI script.
2. Click "Start Sniffing".
3. It captures packets in real-time and extracts `size` and `protocol`.
4. The AI model checks if the packet is suspicious.
5. It logs results in terminal and `suspicious_log.txt`.

---

🧰 Requirements

- Python 3.10 or higher  
- Scapy  
- Pandas  
- scikit-learn  
- joblib  

Install dependencies:

```bash
pip install scapy pandas scikit-learn joblib
