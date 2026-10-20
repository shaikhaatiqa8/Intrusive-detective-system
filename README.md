# 🛡️ GuardAI: Real-Time Web Intrusion Detection

## 1. Project Overview and Objectives
**GuardAI** is a Grammarly-styled security copilot designed to inspect HTTP traffic payloads, URL query strings, and form inputs in real time. Traditional signature-based Web Application Firewalls (WAFs) often fail against zero-day exploits, obfuscated attacks, and nuanced semantic injection. GuardAI leverages Google's `gemini-2.5-flash` model to analyze the behavioral intent behind user inputs, delivering instant threat assessments, risk scores, clear explanations, and precise remediation advice.

### Key Objectives:
* Bridge the gap between static WAF signature checks and semantic AI reasoning.
* Provide an intuitive, split-screen UI for security engineers and developers to test payloads instantly.
* Deliver actionable remediation steps rather than just blocking traffic.

---

## 2. Features and Technologies Used
### Features:
* **Pre-loaded Attack Vectors:** Quick-test dropdown containing common payloads (SQLi, XSS, Path Traversal, and Clean Traffic).
* **Semantic Analysis:** Goes beyond regex matching to understand the underlying context of strings.
* **Grammarly-Style Feedback Cards:** Color-coded threat alerts (`st.error`, `st.success`, `st.warning`) providing risk ratings, explanations, and fixes.
* **Secure Key Handling:** Built-in support for Streamlit secrets and manual fallback inputs.

### Technologies & Libraries:
* **Python 3.10+**
* **Streamlit:** For rapid, responsive web interface development.
* **Google GenAI SDK (`google-genai`):** Interfacing with `gemini-2.5-flash`.
* **JSON:** For structured communication between the LLM and UI parsing engine.

---

## 3. Installation and Setup Instructions
Follow these steps to run GuardAI locally:

1. **Clone the Repository:**
   ```bash
 
