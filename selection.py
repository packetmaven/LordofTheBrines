"""
This module provides functions for selecting the most relevant features from the extracted feature set for optimal malicious pickle detection.
"""

import logging
from typing import Dict, List, Any, Optional, Union
import numpy as np

logger = logging.getLogger(__name__)

def select_features(features: Dict[str, Any], method: str = "hybrid") -> Dict[str, Any]:
    """
    Select the most relevant features using the specified method.
    
    Args:
        features: Dictionary of extracted features
        method: Feature selection method ('hybrid', 'anova', 'rfe', 'rfa', 'mwts-ca')
        
    Returns:
        Dictionary of selected features
        
    Raises:
        ValueError: If the method is not supported
    """
    logger.info(f"Selecting features using method: {method}")
    
    if method == "none":
        return features
    
    if method == "hybrid":
        return _hybrid_feature_selection(features)
    elif method == "anova":
        return _anova_feature_selection(features)
    elif method == "rfe":
        return _rfe_feature_selection(features)
    elif method == "rfa":
        return _rfa_feature_selection(features)
    elif method == "mwts-ca":
        return _mwts_ca_feature_selection(features)
    else:
        raise ValueError(f"Unsupported feature selection method: {method}")

def _hybrid_feature_selection(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply hybrid feature selection combining multiple methods.
    
    This method combines ANOVA, RFE, RFA, and MWTS-CA algorithms to select
    the most discriminative features for malicious pickle detection.
    
    Args:
        features: Dictionary of extracted features
        
    Returns:
        Dictionary of selected features
    """
    logger.debug("Applying hybrid feature selection")
    
    # In a real implementation, this would apply sophisticated hybrid selection
    # For this prototype, we'll implement a simplified version
    
    # Start with high-importance features that should always be included
    selected_features = {}
    
    # Always include metadata features
    metadata_keys = [
        "size_bytes", "protocol_version", "entropy", "compression_ratio"
    ]
    
    for key in metadata_keys:
        if key in features:
            selected_features[key] = features[key]
    
    # Always include suspicious opcode features
    opcode_keys = [
        "opcode_count", "unique_opcodes", "suspicious_opcode_count", 
        "suspicious_opcode_ratio"
    ]
    
    for key in opcode_keys:
        if key in features:
            selected_features[key] = features[key]
    
    # Include specific opcode counts for suspicious opcodes
    suspicious_opcodes = [
        "GLOBAL", "REDUCE", "INST", "NEWOBJ", "POSIX", "BINUNICODE", "PROTO"
    ]
    
    for opcode in suspicious_opcodes:
        key = f"opcode_{opcode}"
        ratio_key = f"opcode_ratio_{opcode}"
        
        if key in features:
            selected_features[key] = features[key]
        
        if ratio_key in features:
            selected_features[ratio_key] = features[ratio_key]
    
    # Include structural features
    structural_keys = [
        "max_depth", "object_count", "container_count", "has_modules",
        "has_functions", "has_classes", "module_count", "function_count",
        "class_count", "has_suspicious_modules"
    ]
    
    for key in structural_keys:
        if key in features:
            selected_features[key] = features[key]
    
    # Include statistical features
    statistical_keys = [
        "unique_bytes", "byte_diversity", "printable_ratio",
        "null_byte_ratio", "high_bit_ratio", "control_char_ratio"
    ]
    
    for key in statistical_keys:
        if key in features:
            selected_features[key] = features[key]
    
    # Include module names if available
    if "module_names" in features:
        selected_features["module_names"] = features["module_names"]
    
    # Include opcodes if available
    if "opcodes" in features:
        selected_features["opcodes"] = features["opcodes"]
    
    logger.debug(f"Selected {len(selected_features)} features out of {len(features)}")
    return selected_features

def _anova_feature_selection(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply ANOVA-based feature selection.
    
    Args:
        features: Dictionary of extracted features
        
    Returns:
        Dictionary of selected features
    """
    logger.debug("Applying ANOVA feature selection")
    
    # In a real implementation, this would apply ANOVA selection
    # For this prototype, we'll return a subset of features
    
    selected_features = {}
    
    # Select a subset of features
    important_keys = [
        "size_bytes", "protocol_version", "entropy", "compression_ratio",
        "opcode_count", "unique_opcodes", "suspicious_opcode_count", 
        "suspicious_opcode_ratio", "max_depth", "object_count",
        "has_modules", "has_functions", "has_classes",
        "unique_bytes", "byte_diversity", "printable_ratio"
    ]
    
    for key in important_keys:
        if key in features:
            selected_features[key] = features[key]
    
    logger.debug(f"Selected {len(selected_features)} features out of {len(features)}")
    return selected_features

def _rfe_feature_selection(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply Recursive Feature Elimination selection.
    
    Args:
        features: Dictionary of extracted features
        
    Returns:
        Dictionary of selected features
    """
    logger.debug("Applying RFE feature selection")
    
    # In a real implementation, this would apply RFE selection
    # For this prototype, we'll return a subset of features
    
    selected_features = {}
    
    # Select a subset of features
    important_keys = [
        "size_bytes", "entropy", "compression_ratio",
        "opcode_count", "suspicious_opcode_count", 
        "suspicious_opcode_ratio", "max_depth",
        "has_modules", "has_functions", "has_classes",
        "byte_diversity", "printable_ratio"
    ]
    
    for key in important_keys:
        if key in features:
            selected_features[key] = features[key]
    
    logger.debug(f"Selected {len(selected_features)} features out of {len(features)}")
    return selected_features

def _rfa_feature_selection(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply Random Forest Attribute selection.
    
    Args:
        features: Dictionary of extracted features
        
    Returns:
        Dictionary of selected features
    """
    logger.debug("Applying RFA feature selection")
    
    # In a real implementation, this would apply RFA selection
    # For this prototype, we'll return a subset of features
    
    selected_features = {}
    
    # Select a subset of features
    important_keys = [
        "size_bytes", "protocol_version", "entropy",
        "opcode_count", "unique_opcodes", "suspicious_opcode_count", 
        "max_depth", "object_count", "container_count",
        "has_modules", "has_functions",
        "unique_bytes", "printable_ratio", "null_byte_ratio"
    ]
    
    for key in important_keys:
        if key in features:
            selected_features[key] = features[key]
    
    logger.debug(f"Selected {len(selected_features)} features out of {len(features)}")
    return selected_features

def _mwts_ca_feature_selection(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply Multi-Weight Threshold Selection with Correlation Analysis.
    
    Args:
        features: Dictionary of extracted features
        
    Returns:
        Dictionary of selected features
    """
    logger.debug("Applying MWTS-CA feature selection")
    
    # In a real implementation, this would apply MWTS-CA selection
    # For this prototype, we'll return a subset of features
    
    selected_features = {}
    
    # Select a subset of features
    important_keys = [
        "size_bytes", "protocol_version", "entropy", "compression_ratio",
        "opcode_count", "unique_opcodes", "suspicious_opcode_count", 
        "suspicious_opcode_ratio", "max_depth", "object_count",
        "has_modules", "has_functions", "has_classes",
        "unique_bytes", "byte_diversity", "printable_ratio",
        "null_byte_ratio", "high_bit_ratio"
    ]
    
    for key in important_keys:
        if key in features:
            selected_features[key] = features[key]
    
    logger.debug(f"Selected {len(selected_features)} features out of {len(features)}")
    return selected_features
