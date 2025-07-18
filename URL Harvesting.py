#!/usr/bin/env python3
"""
Bug Bounty Scanner - URL Harvesting
===================================

URL harvesting using various sources and tools.
"""

import logging
import re
from pathlib import Path
from typing import List, Dict, Set
from .utils import run_command, read_file_lines, write_file_lines, stealth_request


def harvest_urls_quick(target: str, outdir: Path) -> Path:
    """
    Quick URL harvesting using gau and waybackurls.
    
    Args:
        target: Target domain
        outdir: Output directory
        
    Returns:
        Path to harvested URLs file
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting URL harvesting for {target}")
    
    urls_dir = outdir / "urls" / "raw"
    urls_dir.mkdir(parents=True, exist_ok=True)
    
    # Run different URL harvesting tools
    gau_file = run_gau(target, urls_dir)
    wayback_file = run_waybackurls(target, urls_dir)
    
    # Merge all results
    all_file = urls_dir / "all.txt"
    merge_url_results([gau_file, wayback_file], all_file)
    
    # Statistics
    total_urls = len(read_file_lines(all_file))
    logger.info(f"Harvested {total_urls} URLs")
    
    return all_file


def run_gau(target: str, outdir: Path) -> Path:
    """Run gau for URL harvesting."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "gau.txt"
    
    try:
        logger.debug("Running gau")
        cmd = [
            "gau",
            target,
            "--o", str(output_file),
            "--threads", "5"
        ]
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            count = len(read_file_lines(output_file))
            logger.info(f"gau found {count} URLs")
        else:
            logger.warning("gau failed")
            
    except Exception as e:
        logger.error(f"Error running gau: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_waybackurls(target: str, outdir: Path) -> Path:
    """Run waybackurls for URL harvesting."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "waybackurls.txt"
    
    try:
        logger.debug("Running waybackurls")
        cmd = [
            "waybackurls", target
        ]
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            urls = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            write_file_lines(output_file, urls)
            logger.info(f"waybackurls found {len(urls)} URLs")
        else:
            logger.warning("waybackurls failed")
            
    except Exception as e:
        logger.error(f"Error running waybackurls: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def merge_url_results(input_files: List[Path], output_file: Path):
    """Merge URL harvesting results from multiple tools."""
    logger = logging.getLogger(__name__)
    
    all_urls = set()
    
    for file_path in input_files:
        if file_path.exists():
            urls = read_file_lines(file_path)
            for url in urls:
                url = url.strip()
                if url and url.startswith('http'):
                    all_urls.add(url)
    
    # Write merged results
    sorted_urls = sorted(list(all_urls))
    write_file_lines(output_file, sorted_urls)
    
    logger.debug(f"Merged {len(all_urls)} unique URLs")


def filter_urls(raw_urls_dir: Path, outdir: Path, stealth: bool = False) -> Path:
    """Filter URLs to remove duplicates and uninteresting ones."""
    logger = logging.getLogger(__name__)
    logger.info("Filtering URLs")
    
    filtered_dir = outdir / "urls" / "filtered"
    filtered_dir.mkdir(parents=True, exist_ok=True)
    
    # Read all URLs from raw directory
    all_urls = set()
    for file_path in raw_urls_dir.glob("*.txt"):
        urls = read_file_lines(file_path)
        all_urls.update(urls)
    
    # Filter URLs
    interesting_urls = []
    for url in all_urls:
        if is_interesting_url(url):
            interesting_urls.append(url)
    
    # Group URLs by type
    group_urls_by_type(interesting_urls, filtered_dir)
    
    # Write all filtered URLs
    filtered_file = filtered_dir / "all.txt"
    write_file_lines(filtered_file, sorted(interesting_urls))
    
    logger.info(f"Filtered {len(all_urls)} URLs to {len(interesting_urls)} interesting ones")
    
    return filtered_file


def is_interesting_url(url: str) -> bool:
    """Check if URL is interesting for bug bounty."""
    # Skip common static files
    static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2']
    if any(url.lower().endswith(ext) for ext in static_extensions):
        return False
    
    # Skip very long URLs (likely base64 or noise)
    if len(url) > 200:
        return False
    
    # Interesting patterns
    interesting_patterns = [
        r'/api/',
        r'/admin',
        r'/login',
        r'/signup',
        r'/register',
        r'/dashboard',
        r'/profile',
        r'/user',
        r'/account',
        r'/config',
        r'/settings',
        r'/upload',
        r'/download',
        r'/search',
        r'/debug',
        r'/test',
        r'/dev',
        r'/staging',
        r'\.php',
        r'\.jsp',
        r'\.asp',
        r'\.aspx',
        r'\.json',
        r'\.xml',
        r'\.do',
        r'\.action',
        r'id=',
        r'user=',
        r'email=',
        r'token=',
        r'key=',
        r'password=',
        r'redirect=',
        r'url=',
        r'file=',
        r'path=',
        r'callback=',
        r'jsonp=',
    ]
    
    return any(re.search(pattern, url, re.IGNORECASE) for pattern in interesting_patterns)


def group_urls_by_type(urls: List[str], outdir: Path):
    """Group URLs by type/category."""
    logger = logging.getLogger(__name__)
    
    categories = {
        'api': [],
        'admin': [],
        'auth': [],
        'files': [],
        'params': [],
        'other': []
    }
    
    for url in urls:
        url_lower = url.lower()
        
        if '/api/' in url_lower or url_lower.endswith('.json'):
            categories['api'].append(url)
        elif any(pattern in url_lower for pattern in ['/admin', '/dashboard', '/config']):
            categories['admin'].append(url)
        elif any(pattern in url_lower for pattern in ['/login', '/signup', '/register', '/auth']):
            categories['auth'].append(url)
        elif any(pattern in url_lower for pattern in ['/upload', '/download', '/file']):
            categories['files'].append(url)
        elif any(char in url for char in ['=', '&']):
            categories['params'].append(url)
        else:
            categories['other'].append(url)
    
    # Write categorized results
    for category, urls_list in categories.items():
        if urls_list:
            category_file = outdir / f"{category}.txt"
            write_file_lines(category_file, urls_list)
            logger.info(f"Category {category}: {len(urls_list)} URLs")


def run_gospider(target: str, outdir: Path) -> Path:
    """Run gospider for URL crawling."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "gospider.txt"
    
    try:
        logger.debug("Running gospider")
        cmd = [
            "gospider",
            "-s", f"https://{target}",
            "-d", "3",
            "-c", "10",
            "-t", "20",
            "-o", str(outdir / "gospider_output")
        ]
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            # Parse gospider output
            urls = []
            output_dir = outdir / "gospider_output"
            if output_dir.exists():
                for file_path in output_dir.glob("*.txt"):
                    file_urls = read_file_lines(file_path)
                    urls.extend(file_urls)
            
            write_file_lines(output_file, urls)
            logger.info(f"gospider found {len(urls)} URLs")
        else:
            logger.warning("gospider failed")
            
    except Exception as e:
        logger.debug(f"gospider not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_hakrawler(target: str, outdir: Path) -> Path:
    """Run hakrawler for URL crawling."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "hakrawler.txt"
    
    try:
        logger.debug("Running hakrawler")
        cmd = [
            "hakrawler",
            "-url", f"https://{target}",
            "-depth", "2",
            "-plain"
        ]
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            urls = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            write_file_lines(output_file, urls)
            logger.info(f"hakrawler found {len(urls)} URLs")
        else:
            logger.warning("hakrawler failed")
            
    except Exception as e:
        logger.debug(f"hakrawler not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def extract_urls_from_js(js_content: str) -> List[str]:
    """Extract URLs from JavaScript content."""
    urls = []
    
    # Common URL patterns in JavaScript
    patterns = [
        r'["\']https?://[^"\']+["\']',
        r'["\'][^"\']*\.[a-zA-Z]{2,}[^"\']*["\']',
        r'["\'][^"\']*\/[^"\']*["\']',
        r'url\s*[:=]\s*["\']([^"\']+)["\']',
        r'src\s*[:=]\s*["\']([^"\']+)["\']',
        r'href\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            url = match.strip('"\'')
            if url and (url.startswith('http') or url.startswith('/')):
                urls.append(url)
    
    return list(set(urls))


def extract_endpoints_from_js(js_content: str) -> List[str]:
    """Extract API endpoints from JavaScript content."""
    endpoints = []
    
    # Common endpoint patterns
    patterns = [
        r'["\']\/api\/[^"\']+["\']',
        r'["\']\/v\d+\/[^"\']+["\']',
        r'["\']\/[^"\']*\.php[^"\']*["\']',
        r'["\']\/[^"\']*\.json[^"\']*["\']',
        r'["\']\/[^"\']*\.xml[^"\']*["\']',
        r'["\']\/[^"\']*\.do[^"\']*["\']',
        r'["\']\/[^"\']*\.action[^"\']*["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            endpoint = match.strip('"\'')
            if endpoint:
                endpoints.append(endpoint)
    
    return list(set(endpoints))


def deduplicate_urls(urls_file: Path) -> Path:
    """Remove duplicate URLs while preserving order."""
    logger = logging.getLogger(__name__)
    
    urls = read_file_lines(urls_file)
    unique_urls = list(dict.fromkeys(urls))  # Preserve order
    
    # Write back to same file
    write_file_lines(urls_file, unique_urls)
    
    removed_count = len(urls) - len(unique_urls)
    if removed_count > 0:
        logger.info(f"Removed {removed_count} duplicate URLs")
    
    return urls_file


def get_url_parameters(url: str) -> Dict[str, str]:
    """Extract parameters from URL."""
    import urllib.parse
    
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    # Convert list values to single values
    result = {}
    for key, values in params.items():
        if values:
            result[key] = values[0]
    
    return result


def find_sensitive_urls(urls_file: Path, outdir: Path) -> Path:
    """Find URLs that might contain sensitive information."""
    logger = logging.getLogger(__name__)
    
    urls = read_file_lines(urls_file)
    sensitive_urls = []
    
    # Sensitive patterns
    sensitive_patterns = [
        r'password',
        r'token',
        r'key',
        r'secret',
        r'api_key',
        r'access_token',
        r'auth',
        r'login',
        r'admin',
        r'config',
        r'backup',
        r'dump',
        r'debug',
        r'test',
        r'dev',
        r'staging',
        r'private',
        r'internal',
        r'\.env',
        r'\.git',
        r'\.svn',
        r'\.bak',
        r'\.old',
        r'\.tmp',
    ]
    
    for url in urls:
        for pattern in sensitive_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                sensitive_urls.append(url)
                break
    
    # Write sensitive URLs
    sensitive_file = outdir / "sensitive.txt"
    write_file_lines(sensitive_file, list(set(sensitive_urls)))
    
    logger.info(f"Found {len(sensitive_urls)} potentially sensitive URLs")
    return sensitive_file