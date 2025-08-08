# app/prompts.py
def build_prompt(enriched_data):
    return f"""
You are a cybersecurity analyst. Below is a system log enriched with threat intelligence. 
Analyze the data, identify indicators of compromise (IOCs), suggest MITRE ATT&CK techniques involved, and give a risk summary.

Log and Intel:
{enriched_data}
"""

