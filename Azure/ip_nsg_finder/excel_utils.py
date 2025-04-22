"""Excel handling utilities for IP NSG Finder."""
import logging
import pandas as pd
from typing import List, Optional

from .common import print_info, print_error, print_warning

def read_ip_from_excel(excel_file: str, logger: Optional[logging.Logger] = None) -> List[str]:
    """Read IP addresses from an Excel file.
    
    Args:
        excel_file: Path to the Excel file
        logger: Logger object
        
    Returns:
        List of IP addresses
    """
    try:
        logger.info(f"Reading IP addresses from {excel_file}")
        print_info(f"Reading IP addresses from {excel_file}")
        
        # Read Excel file
        df = pd.read_excel(excel_file)
        
        # Look for a column that might contain IP addresses
        ip_columns = [col for col in df.columns if 'ip' in col.lower() or 'address' in col.lower()]
        
        if not ip_columns:
            # If no obvious IP column, use the first column
            ip_column = df.columns[0]
            logger.warning(f"No column with 'ip' or 'address' in name found. Using first column: {ip_column}")
            print_warning(f"No column with 'ip' or 'address' in name found. Using first column: {ip_column}")
        else:
            ip_column = ip_columns[0]
            logger.info(f"Using column '{ip_column}' for IP addresses")
            print_info(f"Using column '{ip_column}' for IP addresses")
        
        # Extract IP addresses and clean them
        ip_list = df[ip_column].astype(str).str.strip().unique().tolist()
        
        # Filter out invalid entries
        ip_list = [ip for ip in ip_list if len(ip.split('.')) == 4 and not ip.lower().startswith('nan')]
        
        if not ip_list:
            logger.error("No valid IP addresses found in the Excel file")
            print_error("No valid IP addresses found in the Excel file")
            return []
            
        logger.info(f"Found {len(ip_list)} unique IP addresses")
        print_info(f"Found {len(ip_list)} unique IP addresses")
        return ip_list
        
    except Exception as e:
        logger.exception(f"Error reading Excel file: {e}")
        print_error(f"Error reading Excel file: {e}")
        return []