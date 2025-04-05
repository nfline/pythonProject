"""
Shared utilities for NSG analysis

Exports:
- run_az_command: Execute Azure CLI commands
- check_az_login: Verify Azure authentication
- ColorPrinter: Colored console output
- setup_logger: Configure logging system
"""

from .azure_cli import run_az_command, check_az_login
from .logger import ColorPrinter, setup_logger

__all__ = [
    'run_az_command',
    'check_az_login',
    'ColorPrinter',
    'setup_logger'
]
