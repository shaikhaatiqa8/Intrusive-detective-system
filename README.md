# 🛡️ GuardAI — Web Intrusion Detection System

**GuardAI** is a smart security tool that acts like an AI-powered security guard for web applications. It scans web requests and log files to catch hackers, decodes hidden tricks (like base64 or URL encoding), and explains security risks in plain, easy-to-understand language.

---

## ✨ What Can It Do?

- **Hybrid Detection:** Uses fast pattern-matching for instant checks and Google's Gemini AI for deep, intelligent threat analysis.
- **Unlocks Hidden Payloads:** Automatically decodes tricks attackers use to hide malicious code (URL encoding, HTML entities, and Base64).
- **Log File Scanner:** Upload full server access logs (`.log`, `.txt`, `.csv`) to spot malicious traffic instantly.
- **Plain-Language Explanations:** Breaks down complex cyber attacks so anyone can understand what went wrong.
- **Interactive Code Fixes:** Shows side-by-side examples of vulnerable code vs. secure code fixes.
- **Excel-Safe Exports:** Automatically sanitizes downloaded CSV reports to protect against spreadsheet formula injection.

---

## 🚀 Quick Setup Guide

### 1. What You Need
- **Python 3.9+** installed on your computer.
- A free **Google Gemini API Key** (Get yours from [Google AI Studio](https://aistudio.google.com/app/apikey)).

### 2. Installation Steps

Open your terminal or command prompt and run:

```bash
# Clone the repository
git clone [https://github.com/your-username/GuardAI.git](https://github.com/your-username/GuardAI.git)
cd GuardAI

# Create and activate a virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install the required packages
pip install streamlit google-genai pandas



3.RUN THE APP
streamlit run app.py
Open your web browser and go to http://localhost:8501. Paste your Gemini API key in the sidebar, and you're ready to go!



Try These Sample AttacksCopy and paste any of these examples into the Scanner tab to test how GuardAI catches them:
Attack TypeTest PayloadWhat Happens  SQL Injection' OR '1'='1' --Tries to bypass database passwords.
Cross-Site Scripting (XSS)<script>alert('Hacked')</script>Tries to run malicious scripts in the browser.
Path Traversal../../../../etc/passwdTries to steal private server files.
Safe InputHello, update my email to user@example.comClean, normal user traffic.

PROJECT STRUCTURE
GuardAI/
├── app.py             # Main application code
└── README.md          # Project documentation

LISCENSE : Distributed under MIT.
