"""
Utility functions for SSTI Vulnerability Scanner.
Provides helper functions for various scanner components.
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Set

def extract_input_fields(html_content: str) -> Set[str]:
    """
    Extract input field names from HTML content.
    
    Args:
        html_content: HTML content to extract from
        
    Returns:
        Set of input field names
    """
    input_fields = set()
    
    # Extract input tags
    input_pattern = r'<input[^>]+name=[\'"](.*?)[\'"][^>]*>'
    inputs = re.findall(input_pattern, html_content, re.IGNORECASE)
    input_fields.update(inputs)
    
    # Extract textarea tags
    textarea_pattern = r'<textarea[^>]+name=[\'"](.*?)[\'"][^>]*>'
    textareas = re.findall(textarea_pattern, html_content, re.IGNORECASE)
    input_fields.update(textareas)
    
    # Extract select tags
    select_pattern = r'<select[^>]+name=[\'"](.*?)[\'"][^>]*>'
    selects = re.findall(select_pattern, html_content, re.IGNORECASE)
    input_fields.update(selects)
    
    return input_fields

def normalize_params(params: Dict[str, str]) -> Dict[str, str]:
    """
    Normalize parameter values for consistent testing.
    
    Args:
        params: Dictionary of parameters
        
    Returns:
        Normalized parameter dictionary
    """
    normalized = {}
    for name, value in params.items():
        # URL decode the value if needed
        try:
            decoded_value = urllib.parse.unquote(value)
            if decoded_value != value:
                logging.debug(f"Decoded parameter {name} from {value} to {decoded_value}")
                normalized[name] = decoded_value
            else:
                normalized[name] = value
        except Exception:
            normalized[name] = value
    
    return normalized

def is_likely_injectable(param_name: str) -> bool:
    """
    Check if a parameter name is likely to be injectable.
    Some parameters are more likely to be processed by template engines.
    
    Args:
        param_name: Name of the parameter
        
    Returns:
        True if the parameter is likely injectable, False otherwise
    """
    # List of parameter names that are commonly used in templates
    likely_names = [
        'template', 'page', 'view', 'theme', 'layout', 'lang', 'language',
        'display', 'content', 'include', 'file', 'folder', 'path', 'style',
        'callback', 'return', 'redirect', 'next', 'url', 'uri', 'source',
        'target', 'site', 'html', 'text', 'message', 'load', 'debug'
    ]
    
    param_lower = param_name.lower()
    
    # Check for exact match
    if param_lower in likely_names:
        return True
    
    # Check for partial match
    for name in likely_names:
        if name in param_lower:
            return True
    
    return False

def detect_template_engine_from_response(response: str) -> List[str]:
    """
    Try to detect the template engine from response content.
    
    Args:
        response: HTTP response content
        
    Returns:
        List of possible template engines
    """
    engines = []
    
    # Jinja2 / Flask patterns
    if any(pattern in response for pattern in ['Jinja2', 'werkzeug', 'flask']):
        engines.append('jinja2')
    
    # Django patterns
    if any(pattern in response for pattern in ['Django', 'csrfmiddlewaretoken']):
        engines.append('django')
    
    # Twig patterns
    if any(pattern in response for pattern in ['Twig', 'Symfony']):
        engines.append('twig')
    
    # Ruby/ERB patterns
    if any(pattern in response for pattern in ['Ruby', 'Rails', 'ActiveRecord']):
        engines.append('erb')
    
    # Java patterns
    if any(pattern in response for pattern in ['springframework', 'java.lang']):
        java_engines = ['freemarker', 'velocity', 'pebble']
        engines.extend(java_engines)
    
    # PHP patterns
    if any(pattern in response for pattern in ['PHP', 'Fatal error']):
        engines.append('twig')  # Twig is commonly used with PHP
    
    return engines

def parse_cookies(cookie_string: str) -> Dict[str, str]:
    """
    Parse a cookie string into a dictionary.
    
    Args:
        cookie_string: Cookie string in format "name1=value1; name2=value2"
        
    Returns:
        Dictionary of cookie names and values
    """
    cookies = {}
    if not cookie_string:
        return cookies
    
    parts = cookie_string.split(';')
    for part in parts:
        part = part.strip()
        if '=' in part:
            name, value = part.split('=', 1)
            cookies[name.strip()] = value.strip()
    
    return cookies
