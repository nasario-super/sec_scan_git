"""
Secure logging utilities.

Provides logging filters and formatters that automatically
mask sensitive data like tokens, passwords, and secrets.
"""

import logging
import re
from typing import Any


# Patterns for sensitive data that should be masked
SENSITIVE_PATTERNS = [
    # GitHub tokens
    (r'(gh[pousr]_)[A-Za-z0-9]{36,}', r'\1****'),
    (r'(github_pat_)[A-Za-z0-9_]+', r'\1****'),
    
    # AWS keys
    (r'(AKIA)[A-Z0-9]{16}', r'\1****'),
    (r'([A-Za-z0-9/+=]{40})(?=.*(?:aws|secret|key))', r'****'),
    
    # Bearer tokens
    (r'(Bearer\s+)[A-Za-z0-9_\-\.]+', r'\1****'),
    (r'(Authorization["\']?\s*:\s*["\']?)[^"\']+', r'\1****'),
    
    # API keys
    (r'(api[_-]?key["\']?\s*[:=]\s*["\']?)[A-Za-z0-9_\-]+', r'\1****'),
    (r'(token["\']?\s*[:=]\s*["\']?)[A-Za-z0-9_\-\.]+', r'\1****'),
    
    # Passwords
    (r'(password["\']?\s*[:=]\s*["\']?)[^\s"\']+', r'\1****'),
    (r'(passwd["\']?\s*[:=]\s*["\']?)[^\s"\']+', r'\1****'),
    (r'(secret["\']?\s*[:=]\s*["\']?)[^\s"\']+', r'\1****'),
    
    # Connection strings with passwords
    (r'(://[^:]+:)[^@]+(@)', r'\1****\2'),
    
    # Private keys
    (r'(-----BEGIN[^-]+PRIVATE KEY-----)[^-]+(-----END)', r'\1\n****\n\2'),
    
    # Stripe keys
    (r'(sk_(?:live|test)_)[A-Za-z0-9]+', r'\1****'),
    (r'(pk_(?:live|test)_)[A-Za-z0-9]+', r'\1****'),
    
    # Slack tokens
    (r'(xox[baprs]-)[A-Za-z0-9\-]+', r'\1****'),
    
    # SendGrid
    (r'(SG\.)[A-Za-z0-9_\-\.]+', r'\1****'),
    
    # Generic long alphanumeric strings that might be secrets (with context)
    (r'(secret|token|key|password|credential)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', r'\1****'),
]

# Compile patterns for efficiency
COMPILED_PATTERNS = [(re.compile(pattern, re.IGNORECASE), repl) for pattern, repl in SENSITIVE_PATTERNS]


def mask_sensitive_string(text: str) -> str:
    """
    Mask sensitive data in a string.
    
    Args:
        text: Text to sanitize
        
    Returns:
        Text with sensitive data masked
    """
    if not text:
        return text
    
    result = text
    for pattern, replacement in COMPILED_PATTERNS:
        result = pattern.sub(replacement, result)
    
    return result


def mask_dict_values(data: dict[str, Any], depth: int = 0, max_depth: int = 10) -> dict[str, Any]:
    """
    Recursively mask sensitive values in a dictionary.
    
    Args:
        data: Dictionary to sanitize
        depth: Current recursion depth
        max_depth: Maximum recursion depth
        
    Returns:
        Sanitized dictionary
    """
    if depth >= max_depth:
        return data
    
    sensitive_keys = {
        'token', 'password', 'secret', 'key', 'credential',
        'authorization', 'auth', 'api_key', 'apikey',
        'access_token', 'refresh_token', 'private_key',
        'client_secret', 'bearer', 'passwd', 'pwd',
    }
    
    result = {}
    for key, value in data.items():
        key_lower = key.lower()
        
        # Check if key contains sensitive word
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            if isinstance(value, str) and len(value) > 0:
                # Show first and last 4 chars for debugging
                if len(value) > 8:
                    result[key] = f"{value[:4]}****{value[-4:]}"
                else:
                    result[key] = "****"
            else:
                result[key] = "****"
        elif isinstance(value, dict):
            result[key] = mask_dict_values(value, depth + 1, max_depth)
        elif isinstance(value, list):
            result[key] = [
                mask_dict_values(v, depth + 1, max_depth) if isinstance(v, dict)
                else mask_sensitive_string(str(v)) if isinstance(v, str)
                else v
                for v in value
            ]
        elif isinstance(value, str):
            result[key] = mask_sensitive_string(value)
        else:
            result[key] = value
    
    return result


class SensitiveDataFilter(logging.Filter):
    """
    Logging filter that masks sensitive data in log messages.
    
    Use with any logger to automatically mask tokens, passwords,
    and other sensitive information.
    """
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and modify the log record to mask sensitive data."""
        # Mask the main message
        if isinstance(record.msg, str):
            record.msg = mask_sensitive_string(record.msg)
        
        # Mask arguments if they exist
        if record.args:
            if isinstance(record.args, dict):
                record.args = mask_dict_values(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    mask_sensitive_string(str(arg)) if isinstance(arg, str)
                    else mask_dict_values(arg) if isinstance(arg, dict)
                    else arg
                    for arg in record.args
                )
        
        return True


class SecureFormatter(logging.Formatter):
    """
    Logging formatter that masks sensitive data.
    
    Extends the standard formatter to sanitize output.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with sensitive data masked."""
        # Get the formatted message
        formatted = super().format(record)
        
        # Apply additional masking
        return mask_sensitive_string(formatted)


def setup_secure_logging(
    level: int = logging.INFO,
    format_string: str | None = None,
    log_file: str | None = None,
) -> logging.Logger:
    """
    Set up secure logging for the application.
    
    Args:
        level: Logging level
        format_string: Custom format string
        log_file: Optional file to write logs to
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger("github_security_scanner")
    logger.setLevel(level)
    
    # Default format
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Create secure formatter
    formatter = SecureFormatter(format_string)
    
    # Add filter to mask sensitive data
    sensitive_filter = SensitiveDataFilter()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(sensitive_filter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(sensitive_filter)
        logger.addHandler(file_handler)
    
    return logger


def get_secure_logger(name: str) -> logging.Logger:
    """
    Get a logger with secure filtering enabled.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger with sensitive data filter
    """
    logger = logging.getLogger(name)
    
    # Add filter if not already present
    if not any(isinstance(f, SensitiveDataFilter) for f in logger.filters):
        logger.addFilter(SensitiveDataFilter())
    
    return logger


# Export a pre-configured secure logger
secure_logger = get_secure_logger("github_security_scanner")
