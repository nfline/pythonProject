"""
Common utilities, constants and helper classes for IP NSG Finder.
"""
import os
import json
import subprocess
import ipaddress
from typing import List, Dict, Any, Optional, Tuple

# Terminal output colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_info(text: str) -> None:
    """Print informational message"""
    print(f"{Colors.BLUE}{text}{Colors.RESET}")

def print_success(text: str) -> None:
    """Print success message"""
    print(f"{Colors.GREEN}{text}{Colors.RESET}")

def print_warning(text: str) -> None:
    """Print warning message"""
    print(f"{Colors.YELLOW}{text}{Colors.RESET}")

def print_error(text: str) -> None:
    """Print error message"""
    print(f"{Colors.RED}{text}{Colors.RESET}")

def save_json(data: Any, file_path: str) -> None:
    """Save data to JSON file"""
    # Ensure output directory exists
    output_dir = os.path.dirname(file_path)
    if output_dir:  # Avoid error if saving to current directory
        os.makedirs(output_dir, exist_ok=True)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print_info(f"Saved data to {file_path}")
    except IOError as e:
        print_error(f"Failed to save JSON to {file_path}: {e}")
    except TypeError as e:
        print_error(f"Data is not JSON serializable for {file_path}: {e}")

def run_command(cmd: str) -> Optional[Dict]:
    """Run command and return JSON result"""
    try:
        print_info(f"Executing command: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False, encoding='utf-8')  # Specify encoding

        if result.returncode != 0:
            print_error(f"Command execution failed: {result.stderr}")
            return None

        if not result.stdout.strip():
            print_warning("Command executed successfully but returned no output")
            return None

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # Response might not be in JSON format
            print_info(f"Command output (non-JSON): {result.stdout[:500]}...")  # Show preview
            return {"raw_output": result.stdout.strip()}
    except Exception as e:
        print_error(f"Error running command: {str(e)}")
        return None

def ip_in_subnet(ip_address: str, subnet_prefix: str) -> bool:
    """Check if IP is within subnet range using ipaddress module"""
    try:
        network = ipaddress.ip_network(subnet_prefix, strict=False)
        ip = ipaddress.ip_address(ip_address)
        return ip in network
    except ValueError as e:
        print_warning(f"Error parsing IP or subnet prefix '{subnet_prefix}': {str(e)}")
        return False

def ensure_output_dir(base_dir: str = "output") -> str:
    """Ensure output directory exists and return its path"""
    os.makedirs(base_dir, exist_ok=True)
    return base_dir
