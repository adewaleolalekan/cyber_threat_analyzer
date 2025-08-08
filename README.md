# 🛡️ AI Cyber Threat Analyzer

An intelligent agent for analyzing network captures and logs using OpenAI's GPT models. This application provides a web-based interface to upload `.pcap`, `.pcapng`, or `.log` files, analyzes them for potential threats, and generates a comprehensive report.

---

## 🌐 Live Demo

You can see a live version of this agent in action here:

**[https://adewale.viewdns.net](https://adewale.viewdns.net)**

---

## ✨ About The App

This tool is designed for security analysts, network administrators, and cybersecurity enthusiasts who need a quick and efficient way to analyze network traffic or log files. By leveraging the power of advanced AI, it provides expert-level analysis with a simple, user-friendly workflow.

---

## ⚙️ How It Works

The application follows a simple yet powerful workflow:

1.  **File Upload**: The user uploads a network capture (`.pcap`, `.pcapng`) or a generic log file (`.log`, `.txt`) through the Streamlit web interface.

2.  **API Key Entry**: The user enters their OpenAI API key.

3.  **Analysis Trigger**: The user clicks the "Analyze File" button to begin the process.

4.  **Parsing (PCAP/PCAPNG)**: The app uses **TShark** (the command-line tool for Wireshark) to convert the entire packet capture into a structured JSON format using the robust `tshark -T json` command. This method was chosen for its reliability in accurately extracting all packet data.

5.  **Parsing (Logs)**: For text-based logs, the app uses regular expressions to find and extract indicators like IP addresses, domains, and URLs.

6.  **AI Analysis**: The parsed text summary and the list of indicators are sent to an **OpenAI GPT model** (`gpt-4o-mini`). The model analyzes the data and generates a threat summary, identifies key findings, and provides actionable recommendations.

7.  **Report Generation**: A detailed PDF report is created, containing the analysis overview, the AI-generated summary, and a color-coded table of all the threat indicators found in the file.

---

## 🚀 Features

* **Advanced AI Analysis**: Leverages OpenAI's powerful models for in-depth threat intelligence.
* **User-Controlled Workflow**: Analysis begins only when you click the "Analyze" button.
* **Multiple File Types**: Supports both binary packet captures (`pcap`, `pcapng`) and text-based logs.
* **Rich PDF Reporting**: Generates a professional, easy-to-read PDF report for offline analysis and sharing.
* **Visually Appealing UI**: A modern, dark-themed interface built with Streamlit.
* **Secure**: Includes checks to prevent the upload of dangerous file types and oversized files. It also cleans up temporary files automatically.

---

## 🛠️ Tech Stack

* **Backend**: Python
* **Web Framework**: Streamlit
* **AI/LLM**: OpenAI (GPT-4o-mini)
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

### 3. Set Up the Project

```bash
# Create a project directory
mkdir cyber-analyzer
cd cyber-analyzer

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required Python packages
pip install streamlit openai fpdf
```

### 4. Add Application Files

Place all the application's Python files (`main_app.py`, `parser.py`, `llm.py`, `enrichment.py`, `reporting.py`, `prompts.py`) into the `cyber-analyzer` directory.

### 5. Run the Application

```bash
streamlit run main_app.py
```

> Open your web browser and navigate to the **Local URL** provided by Streamlit (e.g., `http://localhost:8501`). You will need a valid OpenAI API key to use the analysis feature.

---

## ✍️ Author

* **Adewale Olalekan**

