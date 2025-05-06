#!/usr/bin/env python3
"""
SSTI Vulnerability Scanner
A tool for detecting Server-Side Template Injection vulnerabilities in web applications.
"""

import argparse
import logging
import sys
import os
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

    # Single URL or file input
    parser.add_argument('url', nargs='?', help='Target URL to scan for SSTI vulnerabilities')
    parser.add_argument('-f', '--file', dest='url_file', help="File containing target URLs (one per line)")

    # Request config
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET', help='HTTP method')
    parser.add_argument('-d', '--data', help='POST data (URL-encoded)')
    parser.add_argument('-H', '--headers', action='append', default=[], help='Custom headers ("Header: Value")')
    parser.add_argument('-c', '--cookie', help='Cookies for request')

    # Scan options
    parser.add_argument('-p', '--parameter', action='append', dest='parameters', help='Parameters to test')
    parser.add_argument('-t', '--template-engines',
                        choices=['all', 'jinja2', 'twig', 'pebble', 'velocity', 'freemarker', 'mako', 'erb'],
                        default='all', help='Template engines to test')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests')
    parser.add_argument('--retries', type=int, default=3, help='Retry count')

    # Output options
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-o', '--output', help='Save results to a file')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    return parser.parse_args()

def process_headers(header_list):
    """Convert list of headers to dict."""
    headers = {}
    for header in header_list:
        if ':' in header:
            name, value = header.split(':', 1)
            headers[name.strip()] = value.strip()
        else:
            logging.warning(f"Ignoring invalid header: {header}")
    return headers

def load_urls_from_file(path):
    """Read URLs from file."""
    if not os.path.isfile(path):
        logging.error(f"File not found: {path}")
        sys.exit(1)
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    args = parse_arguments()
    setup_logging(args.verbose)

    logging.info("🚀 Starting SSTI Vulnerability Scanner")

    # Prepare headers
    headers = process_headers(args.headers)
    if args.cookie:
        headers['Cookie'] = args.cookie

    # Get list of URLs to scan
    if args.url:
        urls = [args.url]
    elif args.url_file:
        urls = load_urls_from_file(args.url_file)
    else:
        logging.error("❌ Please provide a URL or a URL file (-f).")
        return 1

    # Reporter instance
    reporter = Reporter(use_color=not args.no_color)
    all_results = []

    status_code = 0
    for url in urls:
        logging.info(f"🔍 Scanning: {url}")
        scanner = Scanner(
            url=url,
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
        try:
            results = scanner.scan()
            all_results.append(results)
            reporter.print_results(results)
            if results.get('vulnerabilities'):
                logging.warning(f"⚠️ Vulnerabilities found for {url}")
                status_code = 1
        except Exception as e:
            logging.error(f"💥 Error scanning {url}: {e}")
            status_code = 1

    if args.output:
        reporter.save_to_file(all_results, args.output)

    return status_code

if __name__ == "__main__":
    sys.exit(main())
