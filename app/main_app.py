import os
import streamlit as st
from datetime import datetime
from parser import parse_file
from enrichment import enrich_indicators
from llm import call_llm
from reporting import generate_report
import logging
import traceback
import base64

# This is an internal Streamlit class, which is less stable.
# A more modern approach for getting session info might be needed in future Streamlit versions.
try:
    from streamlit.web.server.server import Server
    from streamlit.runtime.scriptrunner import get_script_run_ctx
except ImportError:
    Server = None
    get_script_run_ctx = None

# --- Error logging ---
logging.basicConfig(
    filename="/tmp/streamlit_errors.log",
    level=logging.ERROR,
    format="%(asctime)s %(levelname)s: %(message)s"
)

# --- Custom CSS for Styling ---
def load_css():
    """Injects custom CSS for a more polished look."""
    st.markdown("""
    <style>
        /* --- General Body & Font --- */
        body {
            background-color: #1a1a2e; /* Dark blue-purple background */
        }
        .stApp {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
        }
        h1, h2, h3 {
            color: #ffffff; /* Brighter titles */
        }
        
        /* --- Styled Containers (Cards) --- */
        .st-emotion-cache-1r4qj8v, .st-emotion-cache-1kyxreq {
             background-color: rgba(255, 255, 255, 0.05);
             border: 1px solid rgba(255, 255, 255, 0.1);
             border-radius: 15px;
             padding: 25px;
             box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }

        /* --- File Uploader Styling --- */
        .st-emotion-cache-1gulkj5 {
            border-color: #4a4a6a;
            background-color: #16213e;
        }

        /* --- Button Styling --- */
        .stButton>button {
            border-radius: 10px;
            border: 1px solid #0f3460;
            background-color: #16213e;
            color: #e94560;
            transition: all 0.3s ease-in-out;
        }
        .stButton>button:hover {
            background-color: #e94560;
            color: #ffffff;
            border-color: #e94560;
        }
        .stDownloadButton>button {
            background-color: #e94560;
            color: white;
            border-radius: 10px;
        }
        .stDownloadButton>button:hover {
            background-color: #c73b52;
            color: white;
        }

        /* --- Spinner --- */
        .stSpinner > div > div {
            border-top-color: #e94560; /* Spinner color */
        }
    </style>
    """, unsafe_allow_html=True)

# --- Function to get User IP ---
def get_real_ip():
    """Retrieves the client's real IP address."""
    try:
        if get_script_run_ctx:
            ctx = get_script_run_ctx()
            if ctx is None: return "127.0.0.1"
            
            session_info = Server.get_current()._get_session_info(ctx.session_id)
            if session_info:
                forwarded_for = session_info.ws.request.headers.get('X-Forwarded-For')
                if forwarded_for:
                    return forwarded_for.split(',')[0].strip()
                return session_info.ws.request.remote_ip
    except Exception as e:
        logging.error(f"Could not get user IP: {e}")
    return "127.0.0.1"

# --- Page configuration ---
st.set_page_config(
    page_title="AI Cyber Threat Analyzer", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Load custom CSS
load_css()

# --- Page Header ---
st.title("🛡️ AI Cyber Threat Analyzer")
st.markdown("""
*An intelligent agent for analyzing network captures and logs using local AI.*
""")

# --- Main app layout ---
col1, col2 = st.columns((1, 1), gap="large")

with col1:
    # --- Upload Section as a styled container ---
    with st.container():
        st.header("1. Upload Your File")
        uploaded_file = st.file_uploader(
            "Drag and drop a PCAP, PCAPNG, or Log file here.", 
            type=["pcap", "pcapng", "log", "txt"],
            label_visibility="collapsed"
        )

if uploaded_file:
    # --- Security & Size Checks ---
    MAX_FILE_SIZE_MB = 15
    file_size_mb = len(uploaded_file.getvalue()) / (1024 * 1024)
    uploaded_file.seek(0)

    if file_size_mb > MAX_FILE_SIZE_MB:
        st.error(f"❌ **File too large:** Must be under {MAX_FILE_SIZE_MB}MB.")
    elif any(shell in uploaded_file.name.lower() for shell in [".sh", ".exe", ".php"]):
        st.error("🚫 **Disallowed file type:** For security reasons, this file type is not allowed.")
    else:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        save_path = f"/tmp/{timestamp}_{uploaded_file.name}"
        with open(save_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with col2:
            # --- Analysis Section as a styled container ---
            with st.container():
                st.header("2. AI Analysis & Report")
                
                spinner_messages = [
                    "Engaging local AI model...",
                    "Deconstructing packet data...",
                    "Searching for digital ghosts...",
                    "Consulting with silicon oracles..."
                ]
                
                with st.spinner(text=random.choice(spinner_messages)):
                    # --- File parsing ---
                    log_text, indicators = parse_file(save_path)

                    if not log_text.strip() or "Error:" in log_text:
                        st.error(f"⚠️ **Processing Failed:** {log_text}")
                    else:
                        # --- Threat Scoring & LLM Analysis ---
                        enriched_data = enrich_indicators(indicators)
                        llm_response = ""
                        try:
                            llm_response = call_llm(log_text, enriched_data)
                        except Exception as e:
                            logging.error("LLM call failed: %s", traceback.format_exc())
                            st.error(f"⚠️ **AI Analysis Error:** Could not connect to the local AI model. {e}")

                        if llm_response and "Error connecting to Ollama" not in llm_response:
                            st.subheader("🧠 Threat Intelligence Summary")
                            st.markdown(llm_response)
                            
                            # --- Report Download ---
                            st.subheader("📄 Download Full Report")
                            user_ip = get_real_ip()
                            report_file = generate_report(
                                filename=os.path.basename(uploaded_file.name),
                                user_ip=user_ip,
                                enrichments=enriched_data,
                                gpt_output=llm_response
                            )
                            with open(report_file, "rb") as f:
                                st.download_button(
                                    label="Download PDF Report",
                                    data=f,
                                    file_name=os.path.basename(report_file),
                                    mime="application/pdf",
                                    use_container_width=True
                                )
                        elif llm_response:
                            st.error(f"⚠️ {llm_response}")
                        else:
                            st.warning("⚠️ Report generation was skipped due to an analysis error.")

# --- Footer ---
st.markdown("""
---
<p style='text-align: center; color: #888;'>
Developed by Adewale Olalekan © 2025
</p>
""", unsafe_allow_html=True)
