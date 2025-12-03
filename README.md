# SOC Log Analyzer 🔍  
A lightweight SIEM-style log analysis tool that converts raw Linux system logs into human-friendly security alerts using Python + Flask.

This tool is designed for:
- SOC Analysts  
- Cybersecurity Students  
- Pentesters  
- Hackathon Projects  
- Anyone who wants quick insights from auth.log / syslog files  

---

## 🚀 Features
✔ Detects brute-force SSH attacks  
✔ Detects new user creation  
✔ Detects suspicious commands (wget | curl → sh, base64 decode, etc.)  
✔ Detects reverse-shell patterns  
✔ Detects unusual sudo usage  
✔ Detects port-scanning behavior  
✔ Generates severity score (Low / Medium / High / Critical)  
✔ Provides English-friendly security recommendations  
✔ Simple web UI (Flask)  
✔ REST API endpoint `/api/analyze`

---

## 🛠️ Tech Stack
- Python 3  
- Flask  
- Regex-based threat detection  
- Gunicorn (production server)  

---

## 📥 Input Supported
- Paste logs directly  
- Upload `auth.log`, `syslog`, or `.txt` log files  
- API: Send JSON `{ "logs": "your log here" }`

---

## 📦 Installation (Local)
```bash
git clone https://github.com/hemnathsaigodugula/Soc-Log-Analyzer
cd Soc-Log-Analyzer

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt
python app.py
