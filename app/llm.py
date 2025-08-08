# app/llm.py
import openai

def call_llm(log_text: str, indicators: list, api_key: str) -> str:
    """
    Calls the OpenAI API to analyze the log text and indicators.
    
    Args:
        log_text (str): The summary text from the parsed file.
        indicators (list): A list of enriched indicator dictionaries.
        api_key (str): The user's OpenAI API key.

    Returns:
        str: The analysis response from the language model.
    """
    if not api_key:
        raise ValueError("OpenAI API key is required for analysis.")

    client = openai.OpenAI(api_key=api_key)

    # Construct a detailed prompt for the model
    indicator_summary = "\n".join([f"- {i['type'].upper()}: {i['indicator']} (Threat Score: {i['score']})" for i in indicators]) if indicators else "None found"
    
    prompt = f"""
As a senior cybersecurity analyst AI, your task is to analyze the following network traffic data and security indicators. Provide a concise, expert-level threat analysis.

**Input Data:**
A summary of network packets or log entries is provided below.
```
{log_text[:4000]}
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
        messages = [
            {"role": "system", "content": "You are an expert cybersecurity analyst."},
            {"role": "user", "content": prompt}
        ]

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.3,
            max_tokens=800
        )
        return response.choices[0].message.content.strip()

    except openai.AuthenticationError:
        return "Error: Invalid OpenAI API Key. Please check your key and try again."
    except openai.RateLimitError:
        return "Error: You have exceeded your OpenAI API quota. Please check your plan and billing details."
    except Exception as e:
        return f"An unexpected error occurred with the OpenAI API: {e}"
