"""
Logging utilities for the IP NSG Finder.
"""
import os
import logging
from .common import print_error, ensure_output_dir

def setup_logger(log_file_path: str = None):
    """Configure logger
    
    Args:
        log_file_path: Path to log file. If None, log file will be created in log/temp directory
    """
    # If log_file_path is not provided, create a default one in log/temp
    if log_file_path is None:
        temp_dir = ensure_output_dir("log", "temp")
        log_file_path = os.path.join(temp_dir, f"ip_nsg_finder_{os.path.basename(os.getcwd())}_{os.getpid()}.log")
    
    # Use log_file_path as logger name to ensure uniqueness and avoid conflicts
    logger = logging.getLogger(log_file_path)
    
    # Return existing logger if already configured
    if logger.hasHandlers():
        # Ensure level is still appropriate if re-retrieved
        logger.setLevel(logging.INFO)
        for handler in logger.handlers:
             if isinstance(handler, logging.FileHandler):
                 handler.setLevel(logging.INFO)
             elif isinstance(handler, logging.StreamHandler):
                 handler.setLevel(logging.WARNING)
        return logger

    logger.setLevel(logging.INFO)  # Set minimum level for the logger

    # Always use log/temp directory for logs
    temp_dir = ensure_output_dir("log", "temp")
    log_file_name = os.path.basename(log_file_path)
    actual_log_path = os.path.join(temp_dir, log_file_name)

    # Create file handler (INFO and above)
    try:
        fh = logging.FileHandler(actual_log_path, encoding='utf-8')
        fh.setLevel(logging.INFO)
        # Create console handler (WARNING and above)
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        # Define formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # Add handlers
        logger.addHandler(fh)
        logger.addHandler(ch)
    except Exception as e:
        print_error(f"Failed to configure logging to {log_file_path}: {e}")
        # Fallback to basic console logging if file setup fails
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logger = logging.getLogger("fallback_logger")  # Get the fallback logger

    return logger
