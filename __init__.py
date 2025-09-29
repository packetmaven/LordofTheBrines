"""
LordofTheBrines - A security framework for detecting malicious Python pickle files.
"""

from detector import LordofTheBrines
from config import Config
from result import DetectionResult

__version__ = "0.1.0"
__author__ = "LordofTheBrines Team"

__all__ = ["LordofTheBrines", "Config", "DetectionResult"]
