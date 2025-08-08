# app/llm.py
import ollama
import json

def call_llm(log_text: str, indicators: list) -> str:
    """
    Calls a local LLM using Ollama to analyze the log text and indicators.
    
    Args:
        log_text (str): The summary text from the parsed file.
        indicators (list): A list of enriched indicator dictionaries.

    Returns:
        str: The analysis response from the language model.
    """
    # Construct a detailed prompt for the local model
    indicator_summary = "\n".join([f"- {i['type'].upper()}: {i['indicator']} (Threat Score: {i['score']})" for i in indicators]) if indicators else "None found"
    
    prompt = f"""
As a senior cybersecurity analyst AI, your task is to analyze the following network traffic data and security indicators. Provide a concise, expert-level threat analysis.

**Input Data:**
A summary of network packets or log entries is provided below.
```
{log_text[:3500]}
```

**Extracted Indicators of Compromise (IOCs):**
{indicator_summary}

**Your Analysis:**
Based on all the provided information, please produce a brief but comprehensive report that includes:
1.  **Executive Summary:** A short overview of the potential threat.
2.  **Key Findings:** Bullet points highlighting the most suspicious activities (e.g., strange DNS queries, connections to high-risk IPs, unusual protocols).
3.  **Recommendations:** Actionable steps for mitigation (e.g., "Block IP address X," "Investigate domain Y," "Isolate host Z").

Provide a direct, professional response.
"""

    try:
        # Call the Ollama chat API
        response = ollama.chat(
            model='llama3',  # You can change this to another model like 'mistral'
            messages=[
                {'role': 'user', 'content': prompt},
            ]
        )
        return response['message']['content'].strip()

    except Exception as e:
        # Handle cases where Ollama service is not running or the model is not available
        error_message = (
            "Error connecting to Ollama. Please ensure that the Ollama application is running "
            "and that you have pulled the required model (e.g., 'ollama run llama3').\n\n"
            f"Details: {e}"
        )
        print(error_message) # Also print to console for debugging
        return error_message

