# 🛡️ Threat Detection - Real-Time AI-Powered Threat Detection Dashboard

Threat2 is an advanced Flask-based web application that uses machine learning to detect and visualize real-time network threats. It features live packet analysis, threat classification, geo-intelligence mapping, and more.

## 🔥 Features

- 🌐 Real-time packet sniffing using Scapy
- 🤖 AI/ML-based threat prediction (RandomForest, etc.)
- 📊 Live dashboards with Chart.js and Leaflet maps
- 📌 GeoIP lookup for visualizing threat origins
- 🔒 Admin login, upload support, and history tracking
- ⚡ Socket.IO for real-time updates

## 🛠️ Technologies

- Python (Flask, Scapy, scikit-learn)
- JavaScript (Chart.js, Leaflet, Socket.IO)
- SQLite (or other DBs for logging)
- Tailwind CSS + HTML frontend

## 🚀 Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/threat2.git
cd threat2
pip install -r requirements.txt
python app.py

