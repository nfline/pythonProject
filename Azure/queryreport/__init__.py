"""
Azure NSG Traffic Analyzer Package

Top-level package for analyzing NSG traffic flows by IP address.
Self-contained module that can be copied and run from any location.
"""
import os
import sys

# 自动识别包根目录并添加到Python路径
_PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

__version__ = "2.1.0"
__all__ = ['ip_nsg_finder']
