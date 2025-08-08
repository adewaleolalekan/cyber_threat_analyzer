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
import random

# --- Session State Initialization ---
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False
if 'llm_response' not in st.session_state:
    st.session_state.llm_response = ""
if 'enriched_data' not in st.session_state:
    st.session_state.enriched_data = []
if 'file_name' not in st.session_state:
    st.session_state.file_name = ""
if 'uploaded_file_data' not in st.session_state:
    st.session_state.uploaded_file_data = None


# This is an internal Streamlit class.
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
        body { background-color: #1a1a2e; }
        .stApp {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
        }
        h1, h2, h3 { color: #ffffff; }
        .st-emotion-cache-1r4qj8v, .st-emotion-cache-1kyxreq {
             background-color: rgba(255, 255, 255, 0.05);
             border: 1px solid rgba(255, 255, 255, 0.1);
             border-radius: 15px;
             padding: 25px;
        }
        .stButton>button {
            border-radius: 10px;
            border: 1px solid #e94560;
            background-color: #e94560;
            color: #ffffff;
            transition: all 0.3s ease-in-out;
        }
        .stButton>button:hover { background-color: transparent; color: #e94560; }
        .stDownloadButton>button {
            background-color: #16213e;
            color: #e94560;
            border: 1px solid #e94560;
            border-radius: 10px;
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

load_css()

# --- Page Header ---
st.title("🛡️ AI Cyber Threat Analyzer")
st.markdown("*Analyze network captures and logs with AI.*")

# --- Main app layout ---
col1, col2 = st.columns((1, 1), gap="large")

with col1:
    with st.container():
        st.header("1. Configure Analysis")
        
        uploaded_file = st.file_uploader(
            "Upload a PCAP, PCAPNG, or Log file.", 
            type=["pcap", "pcapng", "log", "txt"]
        )

        if uploaded_file and uploaded_file.name != st.session_state.file_name:
            st.session_state.file_name = uploaded_file.name
            st.session_state.uploaded_file_data = uploaded_file.getvalue()
            st.session_state.analysis_complete = False
            st.session_state.llm_response = ""

        api_key = st.text_input("Enter your OpenAI API Key", type="password")
        st.markdown(
            "<p style='font-size:0.8rem; color:#bbb;'>Don't have a key? Get one from the <a href='https://platform.openai.com/api-keys' target='_blank'>OpenAI Platform</a>.</p>", 
            unsafe_allow_html=True
        )
        
        analyze_button = st.button("Analyze File", use_container_width=True)

# --- Analysis Logic ---
if analyze_button:
    if not st.session_state.uploaded_file_data:
        st.warning("Please upload a file first.")
    elif not api_key:
        st.warning("Please enter your OpenAI API Key.")
    else:
        st.session_state.analysis_complete = True
        
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        save_path = f"/tmp/{timestamp}_{st.session_state.file_name}"
        
        try:
            with open(save_path, "wb") as f:
                f.write(st.session_state.uploaded_file_data)
            
            with col2:
                with st.container():
                    st.header("2. AI Analysis & Report")
                    with st.spinner("Parsing file..."):
                        log_text, indicators = parse_file(save_path)
                    
                    # --- FIX: Check for parsing errors BEFORE calling the AI ---
                    if "Error:" in log_text or not indicators:
                        st.error(f"⚠️ **Parsing Failed:** {log_text}")
                        st.session_state.analysis_complete = False # Stop further processing
                    else:
                        with st.spinner("Contacting AI for analysis..."):
                            enriched_data = enrich_indicators(indicators)
                            llm_response = call_llm(log_text, enriched_data, api_key)
                            
                            st.session_state.llm_response = llm_response
                            st.session_state.enriched_data = enriched_data
        finally:
            if os.path.exists(save_path):
                os.remove(save_path)

# --- Display Results ---
if st.session_state.analysis_complete and st.session_state.llm_response:
    with col2:
        with st.container():
            # This check prevents trying to display an empty header
            if st.session_state.llm_response:
                st.header("2. AI Analysis & Report")
                st.subheader("🧠 Threat Intelligence Summary")
                st.markdown(st.session_state.llm_response)
                
                st.subheader("📄 Download Full Report")
                user_ip = get_real_ip()
                report_file = generate_report(
                    filename=st.session_state.file_name,
                    user_ip=user_ip,
                    enrichments=st.session_state.enriched_data,
                    gpt_output=st.session_state.llm_response
                )
                with open(report_file, "rb") as f:
                    st.download_button(
                        label="Download PDF Report",
                        data=f,
                        file_name=os.path.basename(report_file),
                        mime="application/pdf",
                        use_container_width=True
                    )

# --- Footer ---
st.markdown("""
---
<p style='text-align: center; color: #888;'>
Developed by Adewale Olalekan © 2025
</p>
""", unsafe_allow_html=True)
