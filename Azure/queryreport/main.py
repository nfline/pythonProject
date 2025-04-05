#!/usr/bin/env python3
"""
Self-contained entry point for NSG Traffic Analyzer
Allows running from any directory structure
"""
import os
import sys

def bootstrap():
    """
    Set up the environment and launch the main application
    Ensures proper path resolution regardless of execution directory
    """
    # Ensure package root directory is in Python path
    package_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, package_root)
    
    # Import and run the main function
    from ip_nsg_finder import main
    main()

if __name__ == "__main__":
    bootstrap()
