"""
Configuration module for providig the config class that holds configuration settings for the LordofTheBrines.
"""

import json
import logging
import os
from typing import Dict, Any


class Config:
    """
    Configuration settings for LordofTheBrines.
    
    This class holds all configuration settings for the LordofTheBrines, including detection thresholds, feature selection methods, and model weights.
    
    Attributes:
        detection_threshold: Threshold for malicious detection (0.0-1.0)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        feature_selection_method: Method for feature selection
        enable_behavioral_analysis: Whether to enable behavioral analysis
        enable_threat_intelligence: Whether to enable threat intelligence
        custom_model_path: Path to custom model file
        model_ensemble_weights: Weights for model ensemble
        threat_intelligence_sources: List of threat intelligence sources
        suspicious_opcodes: List of opcodes considered suspicious
        suspicious_modules: List of modules considered suspicious
        suspicious_functions: List of functions considered suspicious
    """

    def __init__(self):
        """
        Initialize configuration with default values.
        """
        # Detection settings
        self.detection_threshold = 0.8
        
        # Logging settings
        self.log_level = "INFO"
        
        # Feature selection settings
        self.feature_selection_method = "hybrid"
        
        # Analysis settings
        self.enable_behavioral_analysis = False
        self.enable_threat_intelligence = False
        self.strict_torch = False
        # Archive/container parsing toggles
        self.enable_zip_scanning = True
        self.enable_nested_zip_scanning = True
        self.enable_tar_scanning = True
        self.enable_7z_scanning = True  # requires optional py7zr
        # Optional advanced modules
        self.enable_ml_detector = True
        self.enable_bayesian_detector = True
        self.enable_drift_monitor = False
        self.enable_unicode_normalization = True
        self.enable_yara = False
        self.yara_rules_path = os.path.join(os.path.dirname(__file__), "rules", "pickle_rules.yar")
        self.enable_fickling_hook = False
        self.fickling_allow_globals = [
            # safe-ish deserialization targets you explicitly trust
            # e.g., "collections.OrderedDict", "numpy.core.multiarray._reconstruct"
        ]
        # Confidence calibration
        self.enable_confidence_calibration = True
        # 'static' uses calibration_temperature; 'rule_based' adapts temperature by rule severity
        self.calibration_strategy = "rule_based"
        self.calibration_temperature = 1.15
        # Explanations
        self.max_explanations = 3
        # Performance
        self.enable_feature_cache = True
        self.feature_cache_size = 2048
        self.enable_parallel_archive_scanning = True
        self.max_parallel_workers = 4
        # ADWIN concept drift
        self.enable_adwin_drift = True
        self.adwin_delta = 0.002
        
        # Model settings
        self.custom_model_path = None
        self.model_ensemble_weights = {
            "gradient_boosting": 1.0,
            "random_forest": 0.8,
            "neural_network": 0.6,
            "ml_detector": 0.5,
            "bayesian_detector": 0.4,
            "yara": 0.6,
        }
        
        # Threat intelligence settings
        self.threat_intelligence_sources = [
            "local_database",
            "community_feed",
        ]

        # Suspicious indicators for feature extraction
        self.suspicious_opcodes = [
            # Classic and modern opcodes indicative of object creation / code paths
            "GLOBAL", "STACK_GLOBAL", "REDUCE", "BUILD", "INST", "NEWOBJ", "EXT1", "EXT2", "EXT4"
        ]
        self.suspicious_modules = [
            "os", "subprocess", "sys", "__main__", "pickle", "shutil", "requests",
            "urllib", "socket", "webbrowser", "tempfile", "ctypes", "exec", "eval"
        ]
        self.suspicious_functions = [
            "system", "call", "Popen", "__import__", "getattr", "__reduce__",
            "__setstate__", "load", "loads", "read", "write", "decode", "encode"
        ]
        # Optional capabilities
        self.enable_ml_detector = True
        # Simple drift baseline (optional): mean/std for key features
        self.drift_baseline = {
            "entropy": {"mean": 4.8, "std": 0.8},
            "suspicious_opcode_ratio": {"mean": 0.05, "std": 0.05},
            "opcode_count": {"mean": 20.0, "std": 15.0},
        }

    @classmethod
    def from_file(cls, file_path: str) -> "Config":
        """
        Load configuration from a JSON file.
        
        Args:
            file_path: Path to the configuration file
            
        Returns:
            Config object with settings from the file
            
        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If the file is not valid JSON
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        with open(file_path, 'r') as f:
            try:
                config_dict = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in configuration file: {e}")
        
        return cls.from_dict(config_dict)

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "Config":
        """
        Create configuration from a dictionary.
        
        Args:
            config_dict: Dictionary of configuration settings
            
        Returns:
            Config object with settings from the dictionary
        """
        config = cls()
        
        # Update attributes from dictionary
        for key, value in config_dict.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                logging.warning(f"Unknown configuration setting: {key}")
        
        return config

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary of configuration settings
        """
        return {
            "detection_threshold": self.detection_threshold,
            "log_level": self.log_level,
            "feature_selection_method": self.feature_selection_method,
            "enable_behavioral_analysis": self.enable_behavioral_analysis,
            "enable_threat_intelligence": self.enable_threat_intelligence,
            "enable_zip_scanning": self.enable_zip_scanning,
            "enable_nested_zip_scanning": self.enable_nested_zip_scanning,
            "enable_tar_scanning": self.enable_tar_scanning,
            "enable_7z_scanning": self.enable_7z_scanning,
            "enable_ml_detector": self.enable_ml_detector,
            "enable_bayesian_detector": self.enable_bayesian_detector,
            "enable_drift_monitor": self.enable_drift_monitor,
            "enable_yara": self.enable_yara,
            "yara_rules_path": self.yara_rules_path,
            "enable_fickling_hook": self.enable_fickling_hook,
            "custom_model_path": self.custom_model_path,
            "model_ensemble_weights": self.model_ensemble_weights,
            "threat_intelligence_sources": self.threat_intelligence_sources,
            "suspicious_opcodes": self.suspicious_opcodes,
            "suspicious_modules": self.suspicious_modules,
            "suspicious_functions": self.suspicious_functions,
            "strict_torch": self.strict_torch,
            "enable_confidence_calibration": self.enable_confidence_calibration,
            "calibration_strategy": self.calibration_strategy,
            "calibration_temperature": self.calibration_temperature,
            "max_explanations": self.max_explanations,
            "enable_feature_cache": self.enable_feature_cache,
            "feature_cache_size": self.feature_cache_size,
            "enable_parallel_archive_scanning": self.enable_parallel_archive_scanning,
            "max_parallel_workers": self.max_parallel_workers,
        }

    def to_json(self) -> str:
        """
        Convert configuration to JSON string.
        
        Returns:
            JSON string of configuration settings
        """
        return json.dumps(self.to_dict(), indent=2)

    def save_to_file(self, file_path: str) -> None:
        """
        Save configuration to a JSON file.
        
        Args:
            file_path: Path to the output file
            
        Raises:
            PermissionError: If the file cannot be written
        """
        with open(file_path, 'w') as f:
            f.write(self.to_json())

    def __str__(self) -> str:
        """
        Return string representation of configuration.
        
        Returns:
            String representation of configuration settings
        """
        return f"Config(detection_threshold={self.detection_threshold}, " \
               f"feature_selection_method={self.feature_selection_method}, " \
               f"enable_behavioral_analysis={self.enable_behavioral_analysis}, " \
               f"enable_threat_intelligence={self.enable_threat_intelligence})"


