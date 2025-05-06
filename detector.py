"""
Response analysis module for detecting SSTI vulnerabilities.
Analyzes HTTP responses to identify successful injections.
"""

import re
import logging
from typing import Dict, List, Optional, Set, Tuple, Any

class AnalysisResult:
    """Class to store the results of response analysis."""
    
    def __init__(self, is_vulnerable: bool, evidence: str = "", confidence: float = 0.0):
        """
        Initialize the analysis result.
        
        Args:
            is_vulnerable: Whether a vulnerability was detected
            evidence: Evidence of the vulnerability
            confidence: Confidence level (0.0 to 1.0)
        """
        self.is_vulnerable = is_vulnerable
        self.evidence = evidence
        self.confidence = confidence

class ResponseAnalyzer:
    """
    Analyzes HTTP responses to detect successful SSTI injections.
    Uses pattern matching and content comparison to identify vulnerabilities.
    """
    
    def __init__(self):
        """Initialize the response analyzer with detection patterns."""
        # Patterns to look for in responses
        self._patterns = {
            # Generic patterns
            "generic": [
                # Basic math calculation results
                r"49",             # Result of 7*7
                r"7777777",        # Result of 7*'7'
                
                # Unique markers combined with results
                r"49_SSTI_TEST_",  # 7*7 followed by a marker
            ],
            
            # Engine-specific patterns
            "jinja2": [
                # Jinja2 specific object outputs
                r"<Config\s+", 
                r"<flask\.config\.",
                # Command execution results
                r"uid=\d+\(.+\)\s+gid=\d+\(.+\)",  # 'id' command output  
            ],
            
            "twig": [
                # Twig specific patterns
                r"<twig\\",
                r"Twig_Environment",
            ],
            
            "pebble": [
                # Pebble/Java specific patterns
                r"java\.util\.",
                r"java\.lang\.",
            ],
            
            "velocity": [
                # Velocity specific patterns
                r"org\.apache\.velocity",
            ],
            
            "freemarker": [
                # FreeMarker specific patterns
                r"freemarker\.template\.",
            ],
            
            "mako": [
                # Mako specific patterns
                r"mako\.runtime\.",
            ],
            
            "erb": [
                # ERB/Ruby specific patterns
                r"ruby|Rails|erb",
            ]
        }
        
        # Error patterns that might indicate templating issues
        self._error_patterns = [
            r"Template\s+Error",
            r"ParseError",
            r"SyntaxError",
            r"compilation\s+error",
            r"template\s+exception",
            r"undefined\s+variable",
            r"undefined\s+method",
            r"TemplateSyntaxError",
            r"UncaughtException",
        ]
    
    def analyze(self, response_content: str, baseline_content: str, 
                payload: str, template_engine: str) -> AnalysisResult:
        """
        Analyze response content to detect SSTI vulnerabilities.
        
        Args:
            response_content: HTTP response content to analyze
            baseline_content: Original response content to compare against
            payload: The payload that was used
            template_engine: The template engine being tested
            
        Returns:
            AnalysisResult object with detection results
        """
        # Initialize result with default values
        result = AnalysisResult(is_vulnerable=False)
        
        # Simple check: did the response change from the baseline?
        if response_content == baseline_content and not self._contains_error_pattern(response_content):
            return result
        
        # Check for common error patterns
        if self._contains_error_pattern(response_content):
            # This could indicate a template engine is present
            logging.debug("Template error detected, possible template engine presence")
            result.confidence = 0.3
            result.evidence = "Template error detected"
            
            # Get error details
            error_evidence = self._extract_error_evidence(response_content)
            if error_evidence:
                result.evidence = error_evidence
                result.confidence = 0.4
                # We don't set is_vulnerable=True just because of an error
            
            return result
        
        # Check for calculation results
        if "7*7" in payload and "49" in response_content:
            # Basic test - if payload contains 7*7 and response contains 49
            result.is_vulnerable = True
            result.evidence = "Mathematical expression evaluated: 7*7 = 49"
            result.confidence = 0.7
            
            # Higher confidence if the result is not in baseline
            if "49" not in baseline_content:
                result.confidence = 0.9
        
        # Check for generic pattern matches
        for pattern in self._patterns["generic"]:
            match = re.search(pattern, response_content)
            if match and not re.search(pattern, baseline_content):
                result.is_vulnerable = True
                result.evidence = f"Generic pattern match: {match.group(0)}"
                result.confidence = 0.6
        
        # Check for template-specific pattern matches
        if template_engine in self._patterns:
            for pattern in self._patterns[template_engine]:
                match = re.search(pattern, response_content)
                if match and not re.search(pattern, baseline_content):
                    result.is_vulnerable = True
                    result.evidence = f"{template_engine} pattern match: {match.group(0)}"
                    result.confidence = 0.8
        
        # Check for command execution results (highest confidence)
        if any(cmd_pattern in response_content for cmd_pattern in ["uid=", "gid=", "groups="]):
            if not any(cmd_pattern in baseline_content for cmd_pattern in ["uid=", "gid=", "groups="]):
                result.is_vulnerable = True
                result.evidence = "Command execution detected"
                result.confidence = 1.0
        
        # Check for specific markers in the response
        marker = f"SSTI_TEST_{template_engine.upper()}"
        if marker in response_content and marker not in baseline_content:
            result.is_vulnerable = True
            result.evidence = f"Template engine marker detected: {marker}"
            result.confidence = 0.95
        
        return result
    
    def _contains_error_pattern(self, content: str) -> bool:
        """
        Check if the content contains any error patterns.
        
        Args:
            content: The content to check
            
        Returns:
            True if an error pattern is found, False otherwise
        """
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in self._error_patterns)
    
    def _extract_error_evidence(self, content: str) -> str:
        """
        Extract error details from content.
        
        Args:
            content: The content to extract from
            
        Returns:
            Extracted error message or empty string
        """
        for pattern in self._error_patterns:
            match = re.search(pattern + r"[:\s]*(.*?)(?:<br|</p|</div|\n\n|\.\s)", content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)[:200]  # Limit length
        return ""
    
    def get_patterns(self) -> Dict[str, List[str]]:
        """
        Get all detection patterns.
        
        Returns:
            Dictionary of detection patterns
        """
        return self._patterns
