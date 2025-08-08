import subprocess
import sys
import os
import shutil

def check_tshark():
    """Checks if the tshark command-line tool is installed."""
    if not shutil.which('tshark'):
        print("Error: tshark is not installed or not in the system's PATH.")
        print("Please install Wireshark/TShark to run this script.")
        return False
    return True

def convert_pcap_to_json(pcap_path):
    """
    Converts a given PCAP file to a JSON file using tshark.

    Args:
        pcap_path (str): The full path to the input .pcap or .pcapng file.
    """
    if not os.path.exists(pcap_path):
        print(f"Error: The file '{pcap_path}' was not found.")
        return

    # Define the output path for the JSON file
    json_path = os.path.splitext(pcap_path)[0] + ".json"

    print(f"Converting '{pcap_path}' to JSON...")

    # The tshark command to execute
    command = ['tshark', '-r', pcap_path, '-T', 'json']

    try:
        # Open the output file to write the JSON to
        with open(json_path, 'w') as json_file:
            # Execute the tshark command, redirecting stdout to the file
            result = subprocess.run(
                command, 
                stdout=json_file, 
                stderr=subprocess.PIPE, 
                text=True, 
                check=True
            )
        
        print(f"✅ Success! JSON file created at: {json_path}")

    except FileNotFoundError:
        # This case is handled by check_tshark, but included for robustness
        print("Error: tshark command not found.")
    except subprocess.CalledProcessError as e:
        # This error occurs if tshark returns a non-zero exit code
        print("\n--- TShark Error ---")
        print(f"tshark failed to process the file. It might be corrupted or in an unsupported format.")
        print("Error details:")
        print(e.stderr)
        print("--------------------")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Check if tshark is installed before proceeding
    if not check_tshark():
        sys.exit(1)

    # Check if a file path was provided as a command-line argument
    if len(sys.argv) < 2:
        print("Usage: python pcap_to_json_converter.py <path_to_pcap_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    convert_pcap_to_json(input_file)

