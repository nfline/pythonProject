"""
Logging utilities for the IP NSG Finder.
"""
import os
import logging
from .common import print_error, ensure_output_dir

def setup_logger(log_file_path: str):
    """Configure logger"""
    logger = logging.getLogger(log_file_path)  # Use file path as logger name to avoid conflicts
    if logger.hasHandlers():  # Return existing logger if already configured
        # Ensure level is still appropriate if re-retrieved
        logger.setLevel(logging.INFO)
        for handler in logger.handlers:
             if isinstance(handler, logging.FileHandler):
                 handler.setLevel(logging.INFO)
             elif isinstance(handler, logging.StreamHandler):
                 handler.setLevel(logging.WARNING)
        return logger

    logger.setLevel(logging.INFO)  # Set minimum level for the logger

    # Ensure log directory exists
    log_dir = os.path.dirname(log_file_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # Create file handler (INFO and above)
    try:
        fh = logging.FileHandler(log_file_path, encoding='utf-8')
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
