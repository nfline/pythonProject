"""
Main entry point for the IP NSG Finder tool.
"""
import sys
import os
import argparse
import logging
from datetime import datetime

from .common import print_info, print_error, print_warning, ensure_output_dir
from .analyzer import analyze_traffic
from .logging_utils import setup_logger

def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(description='Find NSGs and analyze flow logs for a specific IP address')
    parser.add_argument('--ip', '-i', required=True, help='Target IP address to analyze')
    parser.add_argument('--time-range', '-t', type=int, default=24, 
                        help='Time range in hours to query flow logs (default: 24)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    target_ip = args.ip
    time_range_hours = args.time_range
    verbose = args.verbose
    
    # Setup logging
    output_dir = ensure_output_dir()
    log_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file_path = os.path.join(log_dir, f"ip_nsg_finder_{datetime.now().strftime('%Y%m%d')}.log")
    logger = setup_logger(log_file_path)
    
    if verbose:
        # Set console handler to INFO level if verbose
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.INFO)
    
    try:
        # Check for Azure CLI before starting
        import subprocess
        print_info("Checking Azure CLI installation...")
        result = subprocess.run(['az', '--version'], shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print_error("Azure CLI not found. Please install Azure CLI and log in before running this script.")
            print_error("Installation guide: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
            sys.exit(1)
            
        # Check if logged in to Azure
        print_info("Checking Azure CLI login status...")
        result = subprocess.run(['az', 'account', 'show'], shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print_error("Not logged in to Azure. Please run 'az login' first.")
            sys.exit(1)
            
        print_info("Pre-checks passed, starting analysis...")
        
        # Perform main analysis
        analyze_traffic(target_ip, time_range_hours, logger)
        
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        logger.exception("An unexpected error occurred:")
        sys.exit(1)
        
    print_info("Analysis completed. Results saved to 'output' directory.")
    
if __name__ == "__main__":
    # Check for required dependencies first
    try:
        import pandas as pd
    except ImportError:
        print_error("Missing required dependency: pandas")
        print_error("Please install with: pip install pandas")
        sys.exit(1)
        
    main()
