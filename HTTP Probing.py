#!/usr/bin/env python3
"""
Bug Bounty Scanner - HTTP Probing
=================================

HTTP probing, WAF detection, and response analysis.
"""

import logging
import re
from pathlib import Path
from typing import List, Dict, Set, Optional
from .utils import run_command, read_file_lines, write_file_lines, stealth_request


def detect_waf(target: str) -> bool:
    """
    Detect Web Application Firewall (WAF) using wafw00f.
    
    Args:
        target: Target domain
        
    Returns:
        True if WAF is detected, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        logger.debug(f"Detecting WAF for {target}")
        cmd = ["wafw00f", f"http://{target}", "-a"]
        
        result = run_command(cmd, timeout=60)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            if "is behind" in output or "protected by" in output:
                waf_match = re.search(r'is behind (.+?) \(', output)
                if waf_match:
                    waf_name = waf_match.group(1)
                    logger.warning(f"WAF detected: {waf_name}")
                else:
                    logger.warning("WAF detected (unknown type)")
                return True
            else:
                logger.info("No WAF detected")
                return False
        else:
            logger.debug("wafw00f failed or no WAF detected")
            return False
            
    except Exception as e:
        logger.debug(f"Error detecting WAF: {str(e)}")
        return False


def probe_http(resolved_file: Path, outdir: Path, stealth: bool = False) -> Path:
    """
    Probe HTTP services using httpx.
    
    Args:
        resolved_file: File containing resolved domains
        outdir: Output directory
        stealth: Enable stealth mode
        
    Returns:
        Path to live HTTP services file
    """
    logger = logging.getLogger(__name__)
    logger.info("Starting HTTP probing")
    
    live_dir = outdir / "live"
    live_dir.mkdir(parents=True, exist_ok=True)
    
    # Run httpx for HTTP probing
    httpx_file = run_httpx(resolved_file, live_dir, stealth)
    
    # Also run basic HTTP check as backup
    python_file = run_python_http(resolved_file, live_dir)
    
    # Merge results
    merged_file = live_dir / "httpx.txt"
    merge_http_results([httpx_file, python_file], merged_file)
    
    # Statistics
    total_live = len(read_file_lines(merged_file))
    total_input = len(read_file_lines(resolved_file))
    logger.info(f"Found {total_live} live HTTP services out of {total_input}")
    
    return merged_file


def run_httpx(resolved_file: Path, outdir: Path, stealth: bool = False) -> Path:
    """Run httpx for HTTP probing."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "httpx_raw.txt"
    
    try:
        logger.debug("Running httpx")
        cmd = [
            "httpx",
            "-l", str(resolved_file),
            "-status-code",
            "-title",
            "-tech-detect",
            "-silent",
            "-o", str(output_file)
        ]
        
        if stealth:
            cmd.extend(["-timeout", "10", "-retries", "2", "-rate-limit", "10"])
        else:
            cmd.extend(["-timeout", "5", "-threads", "50"])
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            count = len(read_file_lines(output_file))
            logger.info(f"httpx found {count} live HTTP services")
        else:
            logger.warning("httpx failed")
            
    except Exception as e:
        logger.error(f"Error running httpx: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_python_http(resolved_file: Path, outdir: Path) -> Path:
    """Run Python HTTP check as backup."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "python_http.txt"
    
    domains = read_file_lines(resolved_file)
    live_services = []
    
    logger.debug("Running Python HTTP check")
    
    for domain in domains:
        # Try both HTTP and HTTPS
        for scheme in ['http', 'https']:
            url = f"{scheme}://{domain}"
            try:
                response = stealth_request(url, timeout=10)
                if response and response.status_code < 400:
                    live_services.append(f"{url} [{response.status_code}]")
                    break  # Found working scheme, no need to try the other
                    
            except Exception:
                continue
    
    write_file_lines(output_file, live_services)
    logger.info(f"Python HTTP check found {len(live_services)} live services")
    
    return output_file


def merge_http_results(input_files: List[Path], output_file: Path):
    """Merge HTTP probing results from multiple tools."""
    logger = logging.getLogger(__name__)
    
    all_urls = set()
    
    for file_path in input_files:
        if file_path.exists():
            lines = read_file_lines(file_path)
            for line in lines:
                # Extract URL from various formats
                if line.startswith('http'):
                    url = line.split()[0]  # Take first part (URL)
                    all_urls.add(url)
    
    # Write merged results
    sorted_urls = sorted(list(all_urls))
    write_file_lines(output_file, sorted_urls)
    
    logger.debug(f"Merged {len(all_urls)} unique live HTTP services")


def group_by_status(live_file: Path, outdir: Path):
    """Group live HTTP services by status code."""
    logger = logging.getLogger(__name__)
    
    lines = read_file_lines(live_file)
    status_groups = {}
    
    for line in lines:
        # Extract status code from line
        status_match = re.search(r'\[(\d{3})\]', line)
        if status_match:
            status_code = status_match.group(1)
            if status_code not in status_groups:
                status_groups[status_code] = []
            
            # Extract URL
            url = line.split()[0]
            status_groups[status_code].append(url)
        else:
            # No status code found, assume 200
            if '200' not in status_groups:
                status_groups['200'] = []
            status_groups['200'].append(line)
    
    # Write grouped results
    for status_code, urls in status_groups.items():
        status_file = outdir / f"status-{status_code}.txt"
        write_file_lines(status_file, urls)
        logger.info(f"Status {status_code}: {len(urls)} URLs")


def run_httprobe(resolved_file: Path, outdir: Path) -> Path:
    """Run httprobe for HTTP probing (if available)."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "httprobe.txt"
    
    try:
        logger.debug("Running httprobe")
        cmd = ["httprobe", "-c", "50", "-t", "3000"]
        
        # Use cat to pipe domains to httprobe
        domains = read_file_lines(resolved_file)
        input_text = '\n'.join(domains)
        
        result = run_command(cmd, timeout=300)
        
        if result.returncode == 0:
            urls = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            write_file_lines(output_file, urls)
            logger.info(f"httprobe found {len(urls)} live HTTP services")
        else:
            logger.warning("httprobe failed")
            
    except Exception as e:
        logger.debug(f"httprobe not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def check_http_methods(url: str) -> List[str]:
    """Check allowed HTTP methods for a URL."""
    logger = logging.getLogger(__name__)
    allowed_methods = []
    
    try:
        # Send OPTIONS request
        response = stealth_request(url, timeout=10)
        if response and 'Allow' in response.headers:
            allowed_methods = [method.strip() for method in response.headers['Allow'].split(',')]
            
        # Test common methods
        methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        for method in methods_to_test:
            try:
                import requests
                session = requests.Session()
                resp = session.request(method, url, timeout=5)
                if resp.status_code != 405:  # Method not allowed
                    if method not in allowed_methods:
                        allowed_methods.append(method)
            except Exception:
                continue
                
    except Exception as e:
        logger.debug(f"Error checking HTTP methods for {url}: {str(e)}")
    
    return allowed_methods


def get_http_headers(url: str) -> Dict[str, str]:
    """Get HTTP headers for a URL."""
    logger = logging.getLogger(__name__)
    
    try:
        response = stealth_request(url, timeout=10)
        if response:
            return dict(response.headers)
    except Exception as e:
        logger.debug(f"Error getting headers for {url}: {str(e)}")
    
    return {}


def detect_technologies(url: str) -> List[str]:
    """Detect technologies used by a web application."""
    logger = logging.getLogger(__name__)
    technologies = []
    
    try:
        response = stealth_request(url, timeout=10)
        if not response:
            return technologies
        
        headers = response.headers
        content = response.text.lower()
        
        # Check headers for technology indicators
        tech_headers = {
            'server': ['nginx', 'apache', 'iis', 'cloudflare'],
            'x-powered-by': ['php', 'asp.net', 'express'],
            'x-generator': ['drupal', 'wordpress', 'joomla'],
        }
        
        for header, techs in tech_headers.items():
            if header in headers:
                header_value = headers[header].lower()
                for tech in techs:
                    if tech in header_value:
                        technologies.append(tech)
        
        # Check content for technology indicators
        content_patterns = {
            'wordpress': ['wp-content', 'wp-includes'],
            'drupal': ['drupal.js', 'drupal.css'],
            'joomla': ['joomla', 'option=com_'],
            'react': ['react', '__react'],
            'angular': ['angular', 'ng-'],
            'vue': ['vue.js', '__vue'],
            'jquery': ['jquery', '$'],
            'bootstrap': ['bootstrap'],
        }
        
        for tech, patterns in content_patterns.items():
            if any(pattern in content for pattern in patterns):
                technologies.append(tech)
                
    except Exception as e:
        logger.debug(f"Error detecting technologies for {url}: {str(e)}")
    
    return list(set(technologies))


def check_security_headers(url: str) -> Dict[str, bool]:
    """Check for security headers."""
    logger = logging.getLogger(__name__)
    security_headers = {
        'Strict-Transport-Security': False,
        'Content-Security-Policy': False,
        'X-Frame-Options': False,
        'X-Content-Type-Options': False,
        'X-XSS-Protection': False,
        'Referrer-Policy': False,
        'Permissions-Policy': False,
    }
    
    try:
        response = stealth_request(url, timeout=10)
        if response:
            headers = response.headers
            for header in security_headers:
                if header in headers:
                    security_headers[header] = True
                    
    except Exception as e:
        logger.debug(f"Error checking security headers for {url}: {str(e)}")
    
    return security_headers


def screenshot_urls(urls_file: Path, outdir: Path) -> Path:
    """Take screenshots of URLs using aquatone or similar tool."""
    logger = logging.getLogger(__name__)
    screenshots_dir = outdir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        logger.debug("Taking screenshots with aquatone")
        cmd = [
            "aquatone",
            "-ports", "80,443,8080,8443",
            "-out", str(screenshots_dir)
        ]
        
        # Read URLs and create input for aquatone
        urls = read_file_lines(urls_file)
        input_text = '\n'.join(urls)
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            logger.info(f"Screenshots saved to {screenshots_dir}")
        else:
            logger.warning("Screenshot capture failed")
            
    except Exception as e:
        logger.debug(f"Screenshot tool not available or failed: {str(e)}")
    
    return screenshots_dir


def filter_interesting_urls(urls_file: Path, outdir: Path) -> Path:
    """Filter URLs for interesting endpoints."""
    logger = logging.getLogger(__name__)
    
    urls = read_file_lines(urls_file)
    interesting_urls = []
    
    # Patterns for interesting endpoints
    interesting_patterns = [
        r'/admin',
        r'/api',
        r'/login',
        r'/dashboard',
        r'/config',
        r'/backup',
        r'/test',
        r'/dev',
        r'/staging',
        r'/debug',
        r'\.git',
        r'\.env',
        r'\.config',
        r'/swagger',
        r'/docs',
        r'/wp-admin',
        r'/phpmyadmin',
    ]
    
    for url in urls:
        for pattern in interesting_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                interesting_urls.append(url)
                break
    
    # Write filtered results
    interesting_file = outdir / "interesting.txt"
    write_file_lines(interesting_file, list(set(interesting_urls)))
    
    logger.info(f"Found {len(interesting_urls)} interesting URLs")
    return interesting_file