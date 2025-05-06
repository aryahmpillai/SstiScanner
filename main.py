#!/usr/bin/env python3
"""
SSTI Vulnerability Scanner
A tool for detecting Server-Side Template Injection vulnerabilities in web applications.
"""

import argparse
import logging
import sys
from scanner import Scanner
from reporter import Reporter

def setup_logging(verbose):
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='SSTI Vulnerability Scanner - Detect template injection vulnerabilities',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('url', help='Target URL to scan for SSTI vulnerabilities')
    
    # Request configuration
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET',
                       help='HTTP method to use for testing')
    parser.add_argument('-d', '--data', help='Data for POST requests (URL-encoded format)')
    parser.add_argument('-H', '--headers', action='append', default=[],
                       help='Custom HTTP headers (format: "Header: Value")')
    parser.add_argument('-c', '--cookie', help='Cookies to include with requests')
    
    # Scan configuration
    parser.add_argument('-p', '--parameter', action='append', dest='parameters',
                       help='Specific parameters to test (default: test all)')
    parser.add_argument('-t', '--template-engines', choices=['all', 'jinja2', 'twig', 'pebble', 'velocity', 'freemarker', 'mako', 'erb'],
                       default='all', help='Template engines to test')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between requests in seconds')
    parser.add_argument('--retries', type=int, default=3,
                       help='Number of retry attempts for failed requests')
    
    # Output configuration
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    return parser.parse_args()

def process_headers(header_list):
    """Process header list into a dictionary."""
    headers = {}
    for header in header_list:
        if ':' in header:
            name, value = header.split(':', 1)
            headers[name.strip()] = value.strip()
        else:
            logging.warning(f"Ignoring invalid header format: {header}")
    return headers

def main():
    """Main entry point for the SSTI scanner."""
    args = parse_arguments()
    setup_logging(args.verbose)
    
    logging.info("Starting SSTI Vulnerability Scanner")
    logging.debug(f"Target URL: {args.url}")
    
    # Process request configuration
    headers = process_headers(args.headers)
    if args.cookie:
        headers['Cookie'] = args.cookie
    
    # Initialize scanner with provided options
    scanner = Scanner(
        url=args.url,
        method=args.method,
        data=args.data,
        headers=headers,
        parameters=args.parameters,
        template_engines=args.template_engines,
        timeout=args.timeout,
        delay=args.delay,
        retries=args.retries,
        use_color=not args.no_color
    )
    
    # Run the scan
    try:
        results = scanner.scan()
        
        # Report results
        reporter = Reporter(use_color=not args.no_color)
        reporter.print_results(results)
        
        if args.output:
            reporter.save_to_file(results, args.output)
            
        # Return non-zero if vulnerabilities found
        return 0 if not results.get('vulnerabilities') else 1
    
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        return 130
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        if args.verbose:
            logging.exception("Exception details:")
        return 1

if __name__ == "__main__":
    sys.exit(main())
