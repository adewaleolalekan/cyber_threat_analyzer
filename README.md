# 🛡️ AI Cyber Threat Analyzer

An intelligent agent for analyzing network captures and logs using a local AI model. This application provides a web-based interface to upload `.pcap`, `.pcapng`, or `.log` files, analyzes them for potential threats, and generates a comprehensive report.

---

## 🌐 Live Demo

You can see a live version of this agent in action here:

**[https://aiagent.viewdns.net](https://aiagent.viewdns.net)**

---

## ✨ About The App

This tool is designed for security analysts, network administrators, and cybersecurity enthusiasts who need a quick and efficient way to analyze network traffic or log files. By leveraging the power of local large language models (LLMs), it provides expert-level analysis without sending your sensitive data to third-party cloud services.

---

## ⚙️ How It Works

The application follows a simple yet powerful workflow:

1.  **File Upload**: The user uploads a network capture (`.pcap`, `.pcapng`) or a generic log file (`.log`, `.txt`) through the Streamlit web interface.

2.  **Parsing**:
    * **PCAP/PCAPNG Files**: The app uses **TShark** (the command-line tool for Wireshark) to convert the packet capture into a structured JSON format. This provides a detailed and reliable way to access every layer of the network packets.
    * **Log Files**: For text-based logs, the app uses regular expressions to find and extract indicators like IP addresses, domains, and URLs.

3.  **Indicator Enrichment**: Extracted indicators are assigned a simulated threat score (Low, Medium, High) to help prioritize the analysis.

4.  **AI Analysis**: The parsed text summary and the list of indicators are sent to a locally running AI model via **Ollama**. The `Llama 3` model analyzes the data and generates a threat summary, identifies key findings, and provides actionable recommendations.

5.  **Report Generation**: A detailed PDF report is created, containing the analysis overview, the AI-generated summary, and a color-coded table of all the threat indicators found in the file.

---

## 🚀 Features

* **Local First**: All analysis is done locally on your machine, ensuring data privacy and security.
* **No API Keys Needed**: Uses the open-source Ollama and Llama 3, eliminating the need for paid API keys.
* **Multiple File Types**: Supports both binary packet captures (`pcap`, `pcapng`) and text-based logs.
* **Rich PDF Reporting**: Generates a professional, easy-to-read PDF report for offline analysis and sharing.
* **Visually Appealing UI**: A modern, dark-themed interface built with Streamlit.
* **Secure**: Includes checks to prevent the upload of dangerous file types and oversized files.

---

## 🛠️ Tech Stack

* **Backend**: Python
* **Web Framework**: Streamlit
* **AI/LLM**: Ollama with Llama 3
* **Packet Analysis**: TShark
* **PDF Generation**: FPDF

---

## <caption>Deployment on Ubuntu 24.04</caption>

Follow these steps to deploy the application on a fresh Ubuntu 24.04 server.

### 1. Update System & Install Prerequisites

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv
```

### 2. Install TShark

```bash
sudo apt install -y tshark
```
> **Note:** During the installation, you will be asked if non-superusers should be able to capture packets. Select **<Yes>**.

### 3. Install Ollama and Llama 3

```bash
# Install Ollama
curl -fsSL [https://ollama.com/install.sh](https://ollama.com/install.sh) | sh

# Download the Llama 3 model (approx. 4.7 GB)
ollama run llama3
```
> After the model downloads, you can type `/bye` to exit the Ollama chat. The service will keep running in the background.

### 4. Set Up the Project

```bash
# Create a project directory
mkdir cyber-analyzer
cd cyber-analyzer

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required Python packages
pip install streamlit ollama fpdf
```

### 5. Add Application Files

Place all the application's Python files (`main_app.py`, `parser.py`, `llm.py`, `enrichment.py`, `reporting.py`, `prompts.py`) into the `cyber-analyzer` directory.

### 6. Run the Application

```bash
streamlit run main_app.py
```
Open your web browser and navigate to the **Local URL** provided by Streamlit (e.g., `http://localhost:8501`).

---

## ✍️ Author

* **Adewale Olalekan**
