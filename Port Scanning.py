#!/usr/bin/env python3
"""
Bug Bounty Scanner - Port Scanning
==================================

Port scanning using naabu and other tools.
"""

import logging
import socket
from pathlib import Path
from typing import List, Dict, Set
from .utils import run_command, read_file_lines, write_file_lines, extract_domain


def scan_ports(live_file: Path, outdir: Path, stealth: bool = False) -> Path:
    """
    Scan ports using naabu and other tools.
    
    Args:
        live_file: File containing live HTTP services
        outdir: Output directory
        stealth: Enable stealth mode
        
    Returns:
        Path to port scan results file
    """
    logger = logging.getLogger(__name__)
    logger.info("Starting port scanning")
    
    ports_dir = outdir / "ports"
    ports_dir.mkdir(parents=True, exist_ok=True)
    
    # Extract domains from live URLs
    domains = extract_domains_from_urls(live_file)
    domains_file = ports_dir / "domains.txt"
    write_file_lines(domains_file, domains)
    
    # Run naabu for port scanning
    naabu_file = run_naabu(domains_file, ports_dir, stealth)
    
    # Also run basic Python port scan as backup
    python_file = run_python_portscan(domains_file, ports_dir)
    
    # Merge results
    merged_file = ports_dir / "open_ports.txt"
    merge_port_results([naabu_file, python_file], merged_file)
    
    # Statistics
    total_ports = len(read_file_lines(merged_file))
    logger.info(f"Found {total_ports} open ports")
    
    return merged_file


def extract_domains_from_urls(live_file: Path) -> List[str]:
    """Extract unique domains from live URLs."""
    urls = read_file_lines(live_file)
    domains = set()
    
    for url in urls:
        domain = extract_domain(url)
        if domain:
            domains.add(domain)
    
    return sorted(list(domains))


def run_naabu(domains_file: Path, outdir: Path, stealth: bool = False) -> Path:
    """Run naabu for port scanning."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "naabu_raw.txt"
    
    try:
        logger.debug("Running naabu")
        cmd = [
            "naabu",
            "-l", str(domains_file),
            "-o", str(output_file),
            "-silent"
        ]
        
        if stealth:
            cmd.extend(["-rate", "100", "-retries", "2"])
        else:
            cmd.extend(["-rate", "1000", "-retries", "3"])
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            count = len(read_file_lines(output_file))
            logger.info(f"naabu found {count} open ports")
        else:
            logger.warning("naabu failed")
            
    except Exception as e:
        logger.error(f"Error running naabu: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_python_portscan(domains_file: Path, outdir: Path) -> Path:
    """Run Python port scan as backup."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "python_portscan.txt"
    
    domains = read_file_lines(domains_file)
    open_ports = []
    
    # Common ports to scan
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 9000, 9443]
    
    logger.debug("Running Python port scan")
    
    for domain in domains:
        for port in common_ports:
            if check_port(domain, port):
                open_ports.append(f"{domain}:{port}")
    
    write_file_lines(output_file, open_ports)
    logger.info(f"Python port scan found {len(open_ports)} open ports")
    
    return output_file


def check_port(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def merge_port_results(input_files: List[Path], output_file: Path):
    """Merge port scan results from multiple tools."""
    logger = logging.getLogger(__name__)
    
    all_ports = set()
    
    for file_path in input_files:
        if file_path.exists():
            lines = read_file_lines(file_path)
            for line in lines:
                # Normalize format to host:port
                if ':' in line:
                    all_ports.add(line.strip())
    
    # Write merged results
    sorted_ports = sorted(list(all_ports))
    write_file_lines(output_file, sorted_ports)
    
    logger.debug(f"Merged {len(all_ports)} unique open ports")


def run_masscan(domains_file: Path, outdir: Path) -> Path:
    """Run masscan for port scanning (if available)."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "masscan.txt"
    
    try:
        logger.debug("Running masscan")
        cmd = [
            "masscan",
            "-iL", str(domains_file),
            "-p", "1-65535",
            "--rate", "1000",
            "-oG", str(output_file)
        ]
        
        result = run_command(cmd, timeout=1200)
        
        if result.returncode == 0:
            # Parse masscan output
            open_ports = []
            lines = read_file_lines(output_file)
            
            for line in lines:
                if line.startswith("Host:"):
                    parts = line.split()
                    if len(parts) >= 5:
                        host = parts[1]
                        port = parts[4].split('/')[0]
                        open_ports.append(f"{host}:{port}")
            
            # Write clean output
            clean_output = outdir / "masscan_clean.txt"
            write_file_lines(clean_output, open_ports)
            
            logger.info(f"masscan found {len(open_ports)} open ports")
            return clean_output
            
        else:
            logger.warning("masscan failed")
            
    except Exception as e:
        logger.debug(f"masscan not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def get_service_banner(host: str, port: int) -> str:
    """Get service banner for a host:port."""
    logger = logging.getLogger(__name__)
    banner = ""
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # Try to get banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        
        sock.close()
        
    except Exception as e:
        logger.debug(f"Error getting banner for {host}:{port}: {str(e)}")
    
    return banner


def categorize_ports(ports_file: Path, outdir: Path):
    """Categorize ports by service type."""
    logger = logging.getLogger(__name__)
    
    lines = read_file_lines(ports_file)
    categories = {
        'web': [],
        'ssh': [],
        'ftp': [],
        'mail': [],
        'dns': [],
        'database': [],
        'other': []
    }
    
    port_categories = {
        80: 'web', 443: 'web', 8080: 'web', 8443: 'web', 9000: 'web', 9443: 'web',
        22: 'ssh',
        21: 'ftp',
        25: 'mail', 110: 'mail', 143: 'mail', 993: 'mail', 995: 'mail',
        53: 'dns',
        3306: 'database', 5432: 'database', 1433: 'database', 27017: 'database'
    }
    
    for line in lines:
        if ':' in line:
            host, port_str = line.split(':', 1)
            try:
                port = int(port_str)
                category = port_categories.get(port, 'other')
                categories[category].append(line)
            except ValueError:
                categories['other'].append(line)
    
    # Write categorized results
    for category, ports in categories.items():
        if ports:
            category_file = outdir / f"ports-{category}.txt"
            write_file_lines(category_file, ports)
            logger.info(f"Category {category}: {len(ports)} ports")


def scan_specific_ports(domains_file: Path, ports: List[int], outdir: Path) -> Path:
    """Scan specific ports on domains."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "specific_ports.txt"
    
    domains = read_file_lines(domains_file)
    open_ports = []
    
    for domain in domains:
        for port in ports:
            if check_port(domain, port):
                open_ports.append(f"{domain}:{port}")
    
    write_file_lines(output_file, open_ports)
    logger.info(f"Specific port scan found {len(open_ports)} open ports")
    
    return output_file


def run_nmap_service_scan(ports_file: Path, outdir: Path) -> Path:
    """Run nmap service detection on open ports."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "nmap_services.txt"
    
    try:
        logger.debug("Running nmap service scan")
        cmd = [
            "nmap",
            "-sV",
            "-T4",
            "-iL", str(ports_file),
            "-oN", str(output_file)
        ]
        
        result = run_command(cmd, timeout=1800)
        
        if result.returncode == 0:
            logger.info("nmap service scan completed")
        else:
            logger.warning("nmap service scan failed")
            
    except Exception as e:
        logger.debug(f"nmap not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file