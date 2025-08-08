# parser.py
import re
import json
import subprocess
import shutil

def check_tshark():
    """
    Checks if the tshark command-line tool is installed and available in the system's PATH.
    
    Returns:
        bool: True if tshark is found, False otherwise.
    """
    return shutil.which('tshark') is not None

def parse_pcap_with_tshark(filepath):
    """
    Parses a .pcap or .pcapng file by first converting it to JSON using tshark.
    This method is more robust and detailed than manual packet parsing.

    Args:
        filepath (str): The path to the .pcap or .pcapng file.

    Returns:
        tuple: A tuple containing a string of the summary text and a list of indicator dictionaries.
               Returns an error message and empty list if tshark fails or is not found.
    """
    # Check if tshark is available on the system
    if not check_tshark():
        error_message = "Error: tshark is not installed or not in the system's PATH. Please install it to analyze pcap files."
        return error_message, []

    try:
        # The tshark command to convert the pcap file to a JSON object array
        command = ['tshark', '-r', filepath, '-T', 'json']
        # Execute the command, capturing the output
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        
        # Load the JSON output from tshark's stdout
        packets_json = json.loads(result.stdout)

    except FileNotFoundError:
        # This handles the case where tshark is not found, though check_tshark should prevent this.
        return "Error: tshark command not found. Please ensure it is installed and in your PATH.", []
    except subprocess.CalledProcessError as e:
        # This error occurs if tshark returns a non-zero exit code (e.g., file is corrupt)
        return f"Error running tshark. The file might be corrupted or in an unsupported format.\nDetails: {e.stderr}", []
    except json.JSONDecodeError:
        # This happens if tshark's output is not valid JSON, which can occur with empty or malformed captures.
        return "Error: tshark produced invalid JSON. The pcap file might be empty or corrupted.", []
    except Exception as e:
        # Catch any other unexpected errors during the process.
        return f"An unexpected error occurred during pcap parsing: {e}", []

    pcap_summary_lines = []
    ips = set()
    domains = set()

    # Process each packet from the JSON output
    for packet in packets_json:
        layers = packet.get('_source', {}).get('layers', {})
        summary_parts = []

        # Extract basic frame info for context
        frame_info = layers.get('frame', {})
        timestamp = frame_info.get('frame.time', 'No Timestamp')
        frame_num = frame_info.get('frame.number', '')
        protocols = frame_info.get('frame.protocols', '')
        
        summary_parts.append(f"Frame {frame_num} ({protocols}) at {timestamp}")

        # Extract IP addresses from the IP layer
        if 'ip' in layers:
            src_ip = layers['ip'].get('ip.src')
            dst_ip = layers['ip'].get('ip.dst')
            if src_ip and dst_ip:
                ips.add(src_ip)
                ips.add(dst_ip)
                summary_parts.append(f"IP: {src_ip} -> {dst_ip}")

        # Extract DNS query information
        if 'dns' in layers:
            dns_layer = layers['dns']
            query_name = dns_layer.get('dns.qry.name')
            if query_name:
                domains.add(query_name)
                summary_parts.append(f"DNS Query: {query_name}")
            
            # Also capture DNS answers if they exist
            if 'dns.a' in dns_layer:
                answered_ip = dns_layer['dns.a']
                summary_parts.append(f"DNS Answer: {answered_ip}")

        # Extract HTTP host and request URI
        if 'http' in layers:
            http_layer = layers['http']
            host = http_layer.get('http.host')
            request_uri = http_layer.get('http.request.uri')
            if host:
                domains.add(host)
                summary_parts.append(f"HTTP Host: {host}")
            if request_uri:
                summary_parts.append(f"HTTP URI: {request_uri}")

        pcap_summary_lines.append(" | ".join(summary_parts))

    # Consolidate all found indicators into the required format
    indicators = []
    for ip in ips:
        indicators.append({"type": "ip", "value": ip})
    for domain in domains:
        # A simple check to avoid adding IP addresses to the domain list
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            indicators.append({"type": "domain", "value": domain})

    # Create the final text summary for the LLM
    full_text_summary = "\n".join(pcap_summary_lines)
    if not full_text_summary:
        return "No processable packets with IP layers were found in the PCAP file.", []
        
    return full_text_summary, indicators


def parse_log(filepath):
    """
    Parses a text-based log file using regular expressions.
    (This function remains unchanged)
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Regex to find IPs, URLs, and domains
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
    urls = re.findall(r"https?://[^\s\"']+", content)
    domains = re.findall(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b", content)

    indicators = []
    # Using sets to store unique values first
    for ip in set(ips):
        indicators.append({"type": "ip", "value": ip})
    for url in set(urls):
        indicators.append({"type": "url", "value": url})
    for domain in set(domains):
        # Exclude IPs and parts of URLs from the domain list for cleaner separation
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) and '.' in domain:
             if not any(url_part in domain for url_part in urls):
                indicators.append({"type": "domain", "value": domain})

    return content, indicators


def parse_file(filepath):
    """
    Determines the file type and calls the appropriate parser.
    This now uses the tshark-based function for pcap and pcapng files.
    """
    if filepath.lower().endswith(('.pcap', '.pcapng')):
        # Call the new, more robust tshark parser
        return parse_pcap_with_tshark(filepath)
    else:
        # The log parser remains the same
        return parse_log(filepath)

