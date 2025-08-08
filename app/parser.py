# parser.py
import re
import json
import subprocess
import shutil

def check_tshark():
    """
    Checks if the tshark command-line tool is installed and available in the system's PATH.
    """
    return shutil.which('tshark') is not None

def parse_pcap_with_tshark(filepath):
    """
    Parses a .pcap or .pcapng file using the proven tshark -T json command,
    which is more robust than previous streaming attempts.

    Args:
        filepath (str): The path to the .pcap or .pcapng file.

    Returns:
        tuple: A tuple containing a string of the summary text and a list of indicator dictionaries.
    """
    if not check_tshark():
        return "Error: tshark is not installed or not in the system's PATH. Please install it to analyze pcap files.", []

    # This is the same robust command used in the successful test script.
    command = ['tshark', '-r', filepath, '-T', 'json']
    
    pcap_summary_lines = []
    ips = set()
    domains = set()
    
    try:
        # Execute the command and capture the full output in memory.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        
        # Load the entire JSON output. This is more reliable than streaming.
        packets_json = json.loads(result.stdout)

    except FileNotFoundError:
        return "Error: tshark command not found. Please ensure it is installed and in your PATH.", []
    except subprocess.CalledProcessError as e:
        return f"Error running tshark. The file might be corrupted or in an unsupported format.\nDetails: {e.stderr}", []
    except json.JSONDecodeError:
        return "Error: tshark produced invalid JSON. The pcap file might be empty or corrupted.", []
    except Exception as e:
        return f"An unexpected error occurred during pcap parsing: {e}", []

    # Process each packet from the JSON array
    for packet_count, packet in enumerate(packets_json, 1):
        layers = packet.get('_source', {}).get('layers', {})
        summary_parts = []
        timestamp = layers.get('frame', {}).get('frame.time', 'No Timestamp')

        # --- Extract key information from the detailed JSON structure ---
        ip_layer = None
        if 'ip' in layers:
            ip_layer = layers['ip']
            src_ip = ip_layer.get('ip.src')
            dst_ip = ip_layer.get('ip.dst')
            if src_ip and dst_ip:
                ips.add(src_ip)
                ips.add(dst_ip)
                summary_parts.append(f"IPv4: {src_ip} -> {dst_ip}")
        
        if 'ipv6' in layers:
            ip_layer = layers['ipv6']
            src_ip = ip_layer.get('ipv6.src')
            dst_ip = ip_layer.get('ipv6.dst')
            if src_ip and dst_ip:
                ips.add(src_ip)
                ips.add(dst_ip)
                summary_parts.append(f"IPv6: {src_ip} -> {dst_ip}")

        if 'dns' in layers:
            query_name = layers['dns'].get('dns.qry.name')
            if query_name:
                domains.add(query_name)
                summary_parts.append(f"DNS Query: {query_name}")

        if 'http' in layers:
            host = layers['http'].get('http.host')
            if host:
                domains.add(host)
                summary_parts.append(f"HTTP Host: {host}")

        if summary_parts:
            pcap_summary_lines.append(f"Packet {packet_count} at {timestamp} | " + " | ".join(summary_parts))

    # Consolidate found indicators
    indicators = []
    for ip in ips:
        indicators.append({"type": "ip", "value": ip})
    for domain in domains:
        # A simple check to avoid adding IP addresses to the domain list
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            indicators.append({"type": "domain", "value": domain})

    summary_preview = "\n".join(pcap_summary_lines[:100])
    if len(pcap_summary_lines) > 100:
        summary_preview += f"\n... and {len(pcap_summary_lines) - 100} more packets."
    
    if not summary_preview:
        return "No processable packets with IP layers were found in the PCAP file.", []
        
    return summary_preview, indicators


def parse_log(filepath):
    """
    Parses a text-based log file using regular expressions.
    (This function remains unchanged)
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
    urls = re.findall(r"https?://[^\s\"']+", content)
    domains = re.findall(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b", content)

    indicators = []
    for ip in set(ips):
        indicators.append({"type": "ip", "value": ip})
    for url in set(urls):
        indicators.append({"type": "url", "value": url})
    for domain in set(domains):
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) and '.' in domain:
             if not any(url_part in domain for url_part in urls):
                indicators.append({"type": "domain", "value": domain})

    return content, indicators


def parse_file(filepath):
    """
    Determines the file type and calls the appropriate parser.
    """
    if filepath.lower().endswith(('.pcap', '.pcapng')):
        return parse_pcap_with_tshark(filepath)
    else:
        return parse_log(filepath)
