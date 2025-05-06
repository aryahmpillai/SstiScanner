"""
Reporter module for SSTI vulnerability scanner.
Handles results formatting and output.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, Any

try:
    from colorama import init, Fore, Style
    colorama_available = True
except ImportError:
    colorama_available = False

class Reporter:
    """
    Handles formatting and reporting of scan results.
    Provides both console output and file export capabilities.
    """
    
    def __init__(self, use_color: bool = True):
        """
        Initialize the reporter.
        
        Args:
            use_color: Whether to use colored output
        """
        self.use_color = use_color and colorama_available
        
        if self.use_color:
            init()  # Initialize colorama
    
    def print_results(self, results: Dict[str, Any]) -> None:
        """
        Print scan results to the console.
        
        Args:
            results: Scan results dictionary
        """
        self._print_header("SSTI Vulnerability Scan Results")
        
        # Print scan information
        self._print_section("Scan Information")
        self._print_info("Target URL", results["target_url"])
        self._print_info("Method", results["scan_method"])
        self._print_info("Timestamp", datetime.fromtimestamp(results["timestamp"]).strftime('%Y-%m-%d %H:%M:%S'))
        self._print_info("Duration", f"{results.get('duration', 0):.2f} seconds")
        
        # Print statistics
        self._print_section("Scan Statistics")
        stats = results.get("statistics", {})
        self._print_info("Parameters Tested", stats.get("parameters_tested", 0))
        self._print_info("Payloads Sent", stats.get("payloads_sent", 0))
        self._print_info("Vulnerabilities Found", stats.get("vulnerabilities_found", 0))
        self._print_info("Potential Vulnerabilities", stats.get("potential_vulnerabilities", 0))
        self._print_info("Errors", stats.get("errors", 0))
        
        # Print vulnerabilities
        if results.get("vulnerabilities"):
            self._print_section("Confirmed Vulnerabilities", Fore.RED if self.use_color else None)
            for i, vuln in enumerate(results["vulnerabilities"]):
                self._print_vulnerability(i+1, vuln, is_confirmed=True)
        
        # Print potential vulnerabilities
        if results.get("potential_vulnerabilities"):
            self._print_section("Potential Vulnerabilities", Fore.YELLOW if self.use_color else None)
            for i, vuln in enumerate(results["potential_vulnerabilities"]):
                self._print_vulnerability(i+1, vuln, is_confirmed=False)
        
        # Print errors
        if results.get("errors"):
            self._print_section("Errors", Fore.YELLOW if self.use_color else None)
            for i, error in enumerate(results["errors"]):
                self._print_error(i+1, error)
        
        # Print summary
        self._print_section("Summary")
        if stats.get("vulnerabilities_found", 0) > 0:
            self._print_alert(f"Found {stats.get('vulnerabilities_found', 0)} confirmed SSTI vulnerabilities!")
        elif stats.get("potential_vulnerabilities", 0) > 0:
            self._print_warning(f"Found {stats.get('potential_vulnerabilities', 0)} potential SSTI vulnerabilities.")
        else:
            self._print_success("No SSTI vulnerabilities detected.")
        
        print()  # Add final newline
    
    def save_to_file(self, results: Dict[str, Any], filename: str) -> None:
        """
        Save scan results to a file.
        
        Args:
            results: Scan results dictionary
            filename: Output filename
            
        Raises:
            IOError: If the file cannot be written
        """
        try:
            # Ensure the directory exists
            directory = os.path.dirname(filename)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
            
            # Determine file format based on extension
            ext = os.path.splitext(filename)[1].lower()
            
            if ext == '.json':
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
            else:
                # Default to text format
                with open(filename, 'w') as f:
                    f.write(self._format_results_as_text(results))
            
            logging.info(f"Results saved to {filename}")
        except Exception as e:
            logging.error(f"Error saving results to file: {str(e)}")
            raise
    
    def _format_results_as_text(self, results: Dict[str, Any]) -> str:
        """
        Format results as plain text.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Formatted text
        """
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append(f"SSTI Vulnerability Scan Results")
        lines.append("=" * 80)
        lines.append("")
        
        # Scan information
        lines.append("Scan Information")
        lines.append("-" * 80)
        lines.append(f"Target URL: {results['target_url']}")
        lines.append(f"Method: {results['scan_method']}")
        lines.append(f"Timestamp: {datetime.fromtimestamp(results['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Duration: {results.get('duration', 0):.2f} seconds")
        lines.append("")
        
        # Statistics
        lines.append("Scan Statistics")
        lines.append("-" * 80)
        stats = results.get("statistics", {})
        lines.append(f"Parameters Tested: {stats.get('parameters_tested', 0)}")
        lines.append(f"Payloads Sent: {stats.get('payloads_sent', 0)}")
        lines.append(f"Vulnerabilities Found: {stats.get('vulnerabilities_found', 0)}")
        lines.append(f"Potential Vulnerabilities: {stats.get('potential_vulnerabilities', 0)}")
        lines.append(f"Errors: {stats.get('errors', 0)}")
        lines.append("")
        
        # Vulnerabilities
        if results.get("vulnerabilities"):
            lines.append("Confirmed Vulnerabilities")
            lines.append("-" * 80)
            for i, vuln in enumerate(results["vulnerabilities"]):
                lines.append(f"[{i+1}] Parameter: {vuln.get('parameter')}")
                lines.append(f"    Template Engine: {vuln.get('template_engine')}")
                lines.append(f"    Payload: {vuln.get('payload')}")
                lines.append(f"    Evidence: {vuln.get('evidence')}")
                lines.append(f"    Confidence: {vuln.get('confidence', 0):.2f}")
                lines.append("")
        
        # Potential vulnerabilities
        if results.get("potential_vulnerabilities"):
            lines.append("Potential Vulnerabilities")
            lines.append("-" * 80)
            for i, vuln in enumerate(results["potential_vulnerabilities"]):
                lines.append(f"[{i+1}] Parameter: {vuln.get('parameter')}")
                lines.append(f"    Template Engine: {vuln.get('template_engine')}")
                lines.append(f"    Payload: {vuln.get('payload')}")
                lines.append(f"    Evidence: {vuln.get('evidence')}")
                lines.append(f"    Confidence: {vuln.get('confidence', 0):.2f}")
                lines.append("")
        
        # Errors
        if results.get("errors"):
            lines.append("Errors")
            lines.append("-" * 80)
            for i, error in enumerate(results["errors"]):
                lines.append(f"[{i+1}] {error.get('message', 'Unknown error')}")
                lines.append("")
        
        # Summary
        lines.append("Summary")
        lines.append("-" * 80)
        if stats.get("vulnerabilities_found", 0) > 0:
            lines.append(f"Found {stats.get('vulnerabilities_found', 0)} confirmed SSTI vulnerabilities!")
        elif stats.get("potential_vulnerabilities", 0) > 0:
            lines.append(f"Found {stats.get('potential_vulnerabilities', 0)} potential SSTI vulnerabilities.")
        else:
            lines.append("No SSTI vulnerabilities detected.")
        
        return "\n".join(lines)
    
    def _print_header(self, text: str) -> None:
        """Print a header with decoration."""
        if self.use_color:
            print(f"\n{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * len(text)}{Style.RESET_ALL}\n")
        else:
            print(f"\n{text}")
            print(f"{'=' * len(text)}\n")
    
    def _print_section(self, text: str, color=None) -> None:
        """Print a section header."""
        if self.use_color:
            color = color or Fore.BLUE
            print(f"\n{color}{Style.BRIGHT}{text}{Style.RESET_ALL}")
            print(f"{color}{'-' * len(text)}{Style.RESET_ALL}")
        else:
            print(f"\n{text}")
            print(f"{'-' * len(text)}")
    
    def _print_info(self, label: str, value: Any) -> None:
        """Print an information line with label and value."""
        if self.use_color:
            print(f"{Fore.WHITE}{Style.BRIGHT}{label}: {Style.RESET_ALL}{value}")
        else:
            print(f"{label}: {value}")
    
    def _print_vulnerability(self, index: int, vuln: Dict[str, Any], is_confirmed: bool = True) -> None:
        """Print vulnerability details."""
        if self.use_color:
            color = Fore.RED if is_confirmed else Fore.YELLOW
            print(f"{color}[{index}] Parameter: {vuln.get('parameter')}{Style.RESET_ALL}")
            print(f"    Template Engine: {vuln.get('template_engine')}")
            print(f"    Payload: {vuln.get('payload')}")
            print(f"    Evidence: {vuln.get('evidence')}")
            print(f"    Confidence: {vuln.get('confidence', 0):.2f}")
            print()
        else:
            print(f"[{index}] Parameter: {vuln.get('parameter')}")
            print(f"    Template Engine: {vuln.get('template_engine')}")
            print(f"    Payload: {vuln.get('payload')}")
            print(f"    Evidence: {vuln.get('evidence')}")
            print(f"    Confidence: {vuln.get('confidence', 0):.2f}")
            print()
    
    def _print_error(self, index: int, error: Dict[str, Any]) -> None:
        """Print error details."""
        if self.use_color:
            print(f"{Fore.YELLOW}[{index}] {error.get('message', 'Unknown error')}{Style.RESET_ALL}")
            if 'exception' in error:
                print(f"    Exception: {error['exception']}")
            print()
        else:
            print(f"[{index}] {error.get('message', 'Unknown error')}")
            if 'exception' in error:
                print(f"    Exception: {error['exception']}")
            print()
    
    def _print_alert(self, message: str) -> None:
        """Print an alert message."""
        if self.use_color:
            print(f"{Fore.RED}{Style.BRIGHT}{message}{Style.RESET_ALL}")
        else:
            print(f"ALERT: {message}")
    
    def _print_warning(self, message: str) -> None:
        """Print a warning message."""
        if self.use_color:
            print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")
        else:
            print(f"WARNING: {message}")
    
    def _print_success(self, message: str) -> None:
        """Print a success message."""
        if self.use_color:
            print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")
        else:
            print(f"SUCCESS: {message}")
