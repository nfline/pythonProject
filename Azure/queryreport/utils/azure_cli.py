import subprocess
import json
from .logger import ColorPrinter

def run_az_command(command):
    """Execute Azure CLI command and return JSON result"""
    try:
        result = subprocess.run(
            f"az {command} -o json",
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        ColorPrinter.print_error(f"Command execution failed: {e.stderr}")
        return None
    except json.JSONDecodeError:
        ColorPrinter.print_warning("Return result is not valid JSON")
        return result.stdout

def check_az_login():
    """Check Azure login status"""
    try:
        subprocess.run(
            "az account show",
            shell=True,
            check=True,
            capture_output=True
        )
        ColorPrinter.print_success("Azure CLI logged in")
        return True
    except subprocess.CalledProcessError:
        ColorPrinter.print_error("Please login using 'az login' first")
        return False