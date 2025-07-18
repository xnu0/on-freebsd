#!/usr/bin/env python3
"""
Bug Bounty Scanner - Main Entry Point
======================================

A comprehensive bug bounty automation tool inspired by:
- Osmedeus: https://github.com/j3ssie/osmedeus
- reNgine: https://github.com/yogeshojha/rengine
- reconFTW: https://github.com/six2dez/reconftw
- gospider: https://github.com/jaeles-project/gospider
- hakrawler: https://github.com/hakluke/hakrawler
- secretfinder: https://github.com/m4ll0k/SecretFinder
- trufflehog: https://github.com/trufflesecurity/trufflehog
- nuclei-templates: https://github.com/projectdiscovery/nuclei-templates

Usage:
    python -m bugbounty_scan --target example.com --mode quick
    python -m bugbounty_scan --target example.com --mode full --out /tmp/scan/
"""

import argparse
import sys
import os
import logging
from pathlib import Path

# Add the package to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.utils import setup_dirs, check_tools, setup_logging
from scanner.subdomains import enum_subdomains
from scanner.dns import resolve_domains
from scanner.http import detect_waf, probe_http, group_by_status
from scanner.ports import scan_ports
from scanner.urls import harvest_urls_quick, filter_urls
from scanner.js import crawl_js_urls, download_and_beautify
from scanner.vuln import run_nuclei, run_ffuf, run_gf, run_secretfinder
from scanner.report import compile_summary


def main():
    """Main entry point for the bug bounty scanner."""
    parser = argparse.ArgumentParser(
        description="Comprehensive Bug Bounty Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com --mode quick
  %(prog)s --target example.com --mode full --out /tmp/scan/
        """
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target domain to scan"
    )
    
    parser.add_argument(
        "--out",
        default="/bugbounty/targets/",
        help="Output directory (default: /bugbounty/targets/)"
    )
    
    parser.add_argument(
        "--mode",
        choices=["quick", "full"],
        default="quick",
        help="Scan mode: quick (subdomain enum + live check + basic URL harvest) or full (comprehensive scan)"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    logger = logging.getLogger(__name__)
    
    # Create output directory structure
    base_dir = Path(args.out) / args.target
    setup_dirs(base_dir)
    
    logger.info(f"Starting bug bounty scan for {args.target}")
    logger.info(f"Mode: {args.mode}")
    logger.info(f"Output directory: {base_dir}")
    
    try:
        if args.mode == "quick":
            run_quick_scan(args.target, base_dir)
        else:
            run_full_scan(args.target, base_dir)
            
        logger.info("Scan completed successfully!")
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        sys.exit(1)


def run_quick_scan(target, base_dir):
    """Run quick scan: subdomain enumeration + live check + basic URL harvest."""
    logger = logging.getLogger(__name__)
    
    # Required tools for quick scan
    required_tools = ["subfinder", "amass", "httpx", "gau", "waybackurls"]
    if not check_tools(required_tools):
        logger.error("Required tools not found. Please install missing tools.")
        sys.exit(1)
    
    logger.info("=== Starting Quick Scan ===")
    
    # Step 1: Subdomain enumeration
    logger.info("Step 1: Subdomain enumeration")
    subdomains_file = enum_subdomains(target, base_dir)
    
    # Step 2: HTTP probing
    logger.info("Step 2: HTTP probing")
    live_file = probe_http(subdomains_file, base_dir, stealth=True)
    group_by_status(live_file, base_dir)
    
    # Step 3: Basic URL harvesting
    logger.info("Step 3: Basic URL harvesting")
    harvest_urls_quick(target, base_dir)
    
    logger.info("=== Quick Scan Complete ===")


def run_full_scan(target, base_dir):
    """Run full comprehensive scan."""
    logger = logging.getLogger(__name__)
    
    # Required tools for full scan
    required_tools = [
        "subfinder", "amass", "dnsx", "httpx", "naabu", "gau", "waybackurls",
        "gospider", "nuclei", "ffuf", "trufflehog", "wafw00f"
    ]
    if not check_tools(required_tools):
        logger.error("Required tools not found. Please install missing tools.")
        sys.exit(1)
    
    logger.info("=== Starting Full Scan ===")
    
    # Step 1: Subdomain enumeration
    logger.info("Step 1: Subdomain enumeration")
    subdomains_file = enum_subdomains(target, base_dir)
    
    # Step 2: DNS resolution
    logger.info("Step 2: DNS resolution")
    resolved_file = resolve_domains(subdomains_file, base_dir)
    
    # Step 3: WAF detection
    logger.info("Step 3: WAF detection")
    waf_detected = detect_waf(target)
    if waf_detected:
        logger.warning(f"WAF detected on {target}. Enabling stealth mode.")
    
    # Step 4: HTTP probing
    logger.info("Step 4: HTTP probing")
    live_file = probe_http(resolved_file, base_dir, stealth=True)
    group_by_status(live_file, base_dir)
    
    # Step 5: Port scanning
    logger.info("Step 5: Port scanning")
    scan_ports(live_file, base_dir)
    
    # Step 6: URL harvesting
    logger.info("Step 6: URL harvesting")
    harvest_urls_quick(target, base_dir)
    
    # Step 7: URL filtering
    logger.info("Step 7: URL filtering")
    filtered_urls = filter_urls(base_dir / "urls" / "raw", base_dir, stealth=True)
    
    # Step 8: JavaScript crawling
    logger.info("Step 8: JavaScript crawling")
    js_urls = crawl_js_urls(filtered_urls)
    download_and_beautify(js_urls, base_dir / "js" / "raw", base_dir / "js" / "beautified", stealth=True)
    
    # Step 9: Vulnerability scanning
    logger.info("Step 9: Vulnerability scanning")
    run_nuclei(filtered_urls, base_dir)
    
    # Step 10: Directory/file fuzzing
    logger.info("Step 10: Directory/file fuzzing")
    run_ffuf(live_file, base_dir)
    
    # Step 11: Pattern matching with gf
    logger.info("Step 11: Pattern matching with gf")
    run_gf(filtered_urls, base_dir)
    
    # Step 12: Secret detection
    logger.info("Step 12: Secret detection")
    run_secretfinder(base_dir / "js" / "beautified", base_dir)
    
    # Step 13: Generate report
    logger.info("Step 13: Generating report")
    compile_summary(base_dir)
    
    logger.info("=== Full Scan Complete ===")


if __name__ == "__main__":
    main()