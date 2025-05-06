"""
Scanner module for SSTI Vulnerability detection.
Handles the core scanning functionality and orchestrates the testing process.
"""

import logging
import time
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple, Any

import requests
from requests.exceptions import RequestException

from payloads import PayloadGenerator
from detector import ResponseAnalyzer
from utils import extract_input_fields, normalize_params

class ScanResult:
    """Class to store scanning results for a parameter."""
    
    def __init__(self, parameter: str, payload: str, template_engine: str,
                 evidence: str, confidence: float):
        self.parameter = parameter
        self.payload = payload
        self.template_engine = template_engine
        self.evidence = evidence
        self.confidence = confidence
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        return {
            'parameter': self.parameter,
            'payload': self.payload,
            'template_engine': self.template_engine,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'timestamp': self.timestamp
        }

class Scanner:
    """
    SSTI Vulnerability Scanner class that handles:
    - Target URL analysis
    - Parameter identification
    - Payload generation
    - Injection testing
    - Response analysis
    """
    
    def __init__(self, url: str, method: str = 'GET', data: Optional[str] = None,
                headers: Optional[Dict[str, str]] = None, parameters: Optional[List[str]] = None,
                template_engines: str = 'all', timeout: int = 10, delay: float = 0.1,
                retries: int = 3, use_color: bool = True):
        """
        Initialize the scanner with target and scanning settings.
        
        Args:
            url: Target URL to scan
            method: HTTP method (GET or POST)
            data: Data for POST requests
            headers: Custom HTTP headers
            parameters: Specific parameters to test
            template_engines: Template engines to test
            timeout: Request timeout in seconds
            delay: Delay between requests
            retries: Number of retry attempts
            use_color: Enable/disable colored output
        """
        self.url = url
        self.method = method.upper()
        self.data = data
        self.headers = headers or {}
        # Set a default User-Agent if not provided
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = 'SSTI-Scanner/1.0'
            
        self.parameters = parameters
        self.template_engines = template_engines
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.use_color = use_color
        
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        
        # Add Content-Type header for POST requests if not provided
        if self.method == 'POST' and 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    
    def scan(self) -> Dict[str, Any]:
        """
        Execute the SSTI vulnerability scan.
        
        Returns:
            Dict containing scan results and statistics
        """
        start_time = time.time()
        logging.info(f"Starting scan on {self.url}")
        
        results = {
            'target_url': self.url,
            'scan_method': self.method,
            'timestamp': start_time,
            'parameters_tested': [],
            'vulnerabilities': [],
            'potential_vulnerabilities': [],
            'errors': [],
            'statistics': {
                'parameters_tested': 0,
                'payloads_sent': 0,
                'vulnerabilities_found': 0,
                'potential_vulnerabilities': 0,
                'errors': 0
            }
        }
        
        try:
            # Verify target is reachable
            baseline_response = self._send_request(self.url, self.method, self.data, self.headers)
            if not baseline_response:
                results['errors'].append({
                    'message': 'Target URL is not reachable',
                    'url': self.url
                })
                return results
            
            # Extract parameters from URL and data
            parameters = self._extract_parameters()
            if not parameters:
                logging.warning("No parameters found to test")
                results['errors'].append({
                    'message': 'No parameters found to test',
                    'url': self.url
                })
                return results
            
            # Filter parameters if specific ones were requested
            if self.parameters:
                parameters = {k: v for k, v in parameters.items() if k in self.parameters}
                if not parameters:
                    logging.warning("None of the specified parameters were found")
                    results['errors'].append({
                        'message': 'None of the specified parameters were found',
                        'parameters': self.parameters
                    })
                    return results
            
            # Select template engines for testing
            engines = self._select_template_engines()
            
            # Test each parameter
            for param_name, param_value in parameters.items():
                results['parameters_tested'].append(param_name)
                results['statistics']['parameters_tested'] += 1
                
                logging.info(f"Testing parameter: {param_name}")
                
                param_results = self._test_parameter(param_name, param_value, engines, baseline_response)
                
                for result in param_results:
                    if result.confidence >= 0.8:
                        results['vulnerabilities'].append(result.to_dict())
                        results['statistics']['vulnerabilities_found'] += 1
                    elif result.confidence >= 0.5:
                        results['potential_vulnerabilities'].append(result.to_dict())
                        results['statistics']['potential_vulnerabilities'] += 1
                
                # Add a small delay between parameter tests
                time.sleep(self.delay)
        
        except Exception as e:
            logging.error(f"Error during scan: {str(e)}")
            results['errors'].append({
                'message': f"Error during scan: {str(e)}",
                'exception': str(e.__class__.__name__)
            })
            results['statistics']['errors'] += 1
        
        # Calculate scan duration
        results['duration'] = time.time() - start_time
        
        return results
    
    def _extract_parameters(self) -> Dict[str, str]:
        """
        Extract parameters from URL query string and POST data.
        
        Returns:
            Dictionary of parameter names and values
        """
        parameters = {}
        
        # Extract parameters from URL query string
        parsed_url = urllib.parse.urlparse(self.url)
        if parsed_url.query:
            url_params = dict(urllib.parse.parse_qsl(parsed_url.query))
            parameters.update(url_params)
        
        # Extract parameters from POST data if applicable
        if self.method == 'POST' and self.data:
            content_type = self.headers.get('Content-Type', '').lower()
            
            if 'application/x-www-form-urlencoded' in content_type:
                data_params = dict(urllib.parse.parse_qsl(self.data))
                parameters.update(data_params)
            elif 'application/json' in content_type:
                # For demonstration - in a real implementation, we'd parse JSON
                logging.warning("JSON data parsing is not implemented in this version")
            else:
                logging.warning(f"Unsupported Content-Type for parameter extraction: {content_type}")
        
        # If no parameters found, try to identify input fields from HTML response
        if not parameters:
            logging.info("No parameters found in URL or data, attempting to extract from HTML form")
            try:
                response = self._send_request(self.url, 'GET', None, self.headers)
                if response and response.status_code == 200:
                    form_params = extract_input_fields(response.text)
                    parameters.update({name: '' for name in form_params})
            except Exception as e:
                logging.error(f"Error extracting form parameters: {str(e)}")
        
        return parameters
    
    def _select_template_engines(self) -> List[str]:
        """
        Select which template engines to test based on user configuration.
        
        Returns:
            List of template engine names to test
        """
        all_engines = ['jinja2', 'twig', 'pebble', 'velocity', 'freemarker', 'mako', 'erb']
        
        if self.template_engines == 'all':
            return all_engines
        else:
            return [self.template_engines]
    
    def _test_parameter(self, param_name: str, param_value: str, 
                        engines: List[str], baseline_response: requests.Response) -> List[ScanResult]:
        """
        Test a specific parameter for SSTI vulnerabilities with different payloads.
        
        Args:
            param_name: Name of the parameter to test
            param_value: Current value of the parameter
            engines: List of template engines to test
            baseline_response: Original response for comparison
            
        Returns:
            List of ScanResult objects for vulnerable parameters
        """
        results = []
        
        # Get baseline information for comparison
        baseline_content = baseline_response.text
        baseline_status = baseline_response.status_code
        
        # Test each template engine
        for engine in engines:
            payloads = self.payload_generator.generate_payloads(engine)
            
            for payload in payloads:
                logging.debug(f"Testing {param_name} with payload [{payload}] for {engine}")
                
                # Prepare request with the payload
                if self.method == 'GET':
                    # For GET requests, modify URL query parameters
                    parsed_url = urllib.parse.urlparse(self.url)
                    query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
                    query_params[param_name] = payload
                    
                    # Rebuild the URL with the new query parameters
                    new_query = urllib.parse.urlencode(query_params)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                    test_data = None
                else:
                    # For POST requests, modify the data payload
                    test_url = self.url
                    if self.data:
                        data_params = dict(urllib.parse.parse_qsl(self.data))
                        data_params[param_name] = payload
                        test_data = urllib.parse.urlencode(data_params)
                    else:
                        test_data = urllib.parse.urlencode({param_name: payload})
                
                # Send the test request
                response = self._send_request(test_url, self.method, test_data, self.headers)
                
                if not response:
                    continue
                
                # Analyze the response for SSTI evidence
                analysis = self.response_analyzer.analyze(
                    response.text, 
                    baseline_content,
                    payload, 
                    engine
                )
                
                if analysis.is_vulnerable:
                    logging.info(f"Found vulnerability in {param_name}: {analysis.evidence}")
                    results.append(ScanResult(
                        parameter=param_name,
                        payload=payload,
                        template_engine=engine,
                        evidence=analysis.evidence,
                        confidence=analysis.confidence
                    ))
                    # No need to test more payloads for this engine if we found a vulnerability
                    break
            
            # Add a small delay between template engine tests
            time.sleep(self.delay)
                
        return results
    
    def _send_request(self, url: str, method: str, data: Optional[str], 
                     headers: Dict[str, str], attempt: int = 1) -> Optional[requests.Response]:
        """
        Send an HTTP request with retry mechanism.
        
        Args:
            url: Target URL
            method: HTTP method
            data: Request data for POST
            headers: HTTP headers
            attempt: Current attempt number
            
        Returns:
            Response object or None if failed
        """
        try:
            if method == 'GET':
                response = requests.get(
                    url, 
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:  # POST
                response = requests.post(
                    url, 
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            
            return response
            
        except RequestException as e:
            if attempt <= self.retries:
                logging.warning(f"Request failed (attempt {attempt}/{self.retries}): {str(e)}")
                # Exponential backoff
                backoff_time = self.delay * (2 ** (attempt - 1))
                time.sleep(backoff_time)
                return self._send_request(url, method, data, headers, attempt + 1)
            else:
                logging.error(f"Request failed after {self.retries} attempts: {str(e)}")
                return None
