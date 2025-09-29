"""
Logger utility providing logging setup and configuration for the LordofTheBrines.
"""

import logging
import sys
from typing import Optional


def setup_logger(log_level: str = "INFO") -> None:
    """
    Set up logging configuration for LordofTheBrines.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers to avoid duplicate logs
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    root_logger.addHandler(console_handler)
    
    # Configure lordofthebrines logger
    logger = logging.getLogger("lordofthebrines")
    logger.setLevel(numeric_level)
    
    # Log setup completion
    logger.debug(f"Logger initialized with level {log_level}")


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance for the specified name.
    
    Args:
        name: Logger name (if None, returns the lordofthebrines logger)
        
    Returns:
        Logger instance
    """
    if name is None:
        return logging.getLogger('lordofthebrines')
    else:
        return logging.getLogger(f'lordofthebrines.{name}')


