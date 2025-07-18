#!/usr/bin/env python3
"""
Bug Bounty Scanner - Utilities
==============================

Utility functions for logging, tool checking, configuration, and stealth operations.
"""

import logging
import shutil
import subprocess
import time
import random
import requests
from pathlib import Path
from typing import List, Dict, Optional
import urllib.robotparser
import urllib.parse


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # Reduce noise from requests library
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def check_tools(tool_list: List[str]) -> bool:
    """Check if required tools are installed and available in PATH."""
    logger = logging.getLogger(__name__)
    missing_tools = []
    
    for tool in tool_list:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        logger.error(f"Missing required tools: {', '.join(missing_tools)}")
        logger.error("Please install missing tools before running the scan.")
        return False
    
    logger.info(f"All required tools are available: {', '.join(tool_list)}")
    return True


def setup_dirs(base_dir: Path):
    """Create directory structure for scan output."""
    dirs = [
        "subdomains",
        "resolved",
        "live",
        "ports",
        "urls/raw",
        "urls/filtered",
        "js/raw",
        "js/beautified",
        "nuclei/results",
        "ffuf",
        "gf",
        "secrets",
        "reports"
    ]
    
    for dir_path in dirs:
        (base_dir / dir_path).mkdir(parents=True, exist_ok=True)


def rotate_user_agent() -> str:
    """Return a random user agent string."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    ]
    return random.choice(user_agents)


def stealth_request(url: str, timeout: int = 10, retries: int = 3) -> Optional[requests.Response]:
    """Make a stealth HTTP request with random delays and user agent rotation."""
    logger = logging.getLogger(__name__)
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': rotate_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    
    for attempt in range(retries):
        try:
            # Random delay between requests
            if attempt > 0:
                delay = random.uniform(1, 3)
                time.sleep(delay)
            
            response = session.get(url, timeout=timeout, allow_redirects=True)
            return response
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed (attempt {attempt + 1}/{retries}): {str(e)}")
            if attempt == retries - 1:
                logger.warning(f"All requests failed for {url}")
                return None
    
    return None


def check_robots_txt(base_url: str) -> List[str]:
    """Check robots.txt and return disallowed paths."""
    logger = logging.getLogger(__name__)
    disallowed_paths = []
    
    try:
        robots_url = urllib.parse.urljoin(base_url, '/robots.txt')
        response = stealth_request(robots_url)
        
        if response and response.status_code == 200:
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            
            # Extract disallowed paths
            for line in response.text.split('\n'):
                line = line.strip()
                if line.startswith('Disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        disallowed_paths.append(path)
            
            logger.debug(f"Found {len(disallowed_paths)} disallowed paths in robots.txt")
        
    except Exception as e:
        logger.debug(f"Error checking robots.txt: {str(e)}")
    
    return disallowed_paths


def run_command(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a command with timeout and error handling."""
    logger = logging.getLogger(__name__)
    
    try:
        logger.debug(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        if result.returncode != 0:
            logger.warning(f"Command failed with return code {result.returncode}")
            logger.debug(f"STDERR: {result.stderr}")
        
        return result
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds")
        raise
    except Exception as e:
        logger.error(f"Error running command: {str(e)}")
        raise


def read_file_lines(file_path: Path) -> List[str]:
    """Read lines from a file and return as list, filtering empty lines."""
    if not file_path.exists():
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines
    except Exception as e:
        logging.getLogger(__name__).error(f"Error reading file {file_path}: {str(e)}")
        return []


def write_file_lines(file_path: Path, lines: List[str]):
    """Write lines to a file."""
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            for line in lines:
                f.write(f"{line}\n")
    except Exception as e:
        logging.getLogger(__name__).error(f"Error writing file {file_path}: {str(e)}")


def get_file_size(file_path: Path) -> int:
    """Get file size in bytes."""
    try:
        return file_path.stat().st_size if file_path.exists() else 0
    except Exception:
        return 0


def count_file_lines(file_path: Path) -> int:
    """Count lines in a file."""
    try:
        if not file_path.exists():
            return 0
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def merge_files(input_files: List[Path], output_file: Path, deduplicate: bool = True):
    """Merge multiple files into one, optionally deduplicating."""
    logger = logging.getLogger(__name__)
    
    try:
        all_lines = []
        for file_path in input_files:
            if file_path.exists():
                lines = read_file_lines(file_path)
                all_lines.extend(lines)
        
        if deduplicate:
            all_lines = list(dict.fromkeys(all_lines))  # Preserve order while deduplicating
        
        write_file_lines(output_file, all_lines)
        logger.info(f"Merged {len(input_files)} files into {output_file} ({len(all_lines)} lines)")
        
    except Exception as e:
        logger.error(f"Error merging files: {str(e)}")


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc
    except Exception:
        return url


def is_valid_url(url: str) -> bool:
    """Check if URL is valid."""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def clean_url(url: str) -> str:
    """Clean and normalize URL."""
    try:
        # Remove fragments and normalize
        parsed = urllib.parse.urlparse(url)
        cleaned = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            ''  # Remove fragment
        ))
        return cleaned
    except Exception:
        return url