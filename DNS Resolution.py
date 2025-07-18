#!/usr/bin/env python3
"""
Bug Bounty Scanner - DNS Resolution
===================================

DNS resolution and validation using dnsx and other tools.
"""

import logging
import socket
from pathlib import Path
from typing import List, Dict, Set
from .utils import run_command, read_file_lines, write_file_lines


def resolve_domains(subdomains_file: Path, outdir: Path) -> Path:
    """
    Resolve domains using dnsx to get A and AAAA records.
    
    Args:
        subdomains_file: File containing subdomains to resolve
        outdir: Output directory
        
    Returns:
        Path to resolved domains file
    """
    logger = logging.getLogger(__name__)
    logger.info("Starting DNS resolution")
    
    resolved_dir = outdir / "resolved"
    resolved_dir.mkdir(parents=True, exist_ok=True)
    
    # Run dnsx for DNS resolution
    dnsx_file = run_dnsx(subdomains_file, resolved_dir)
    
    # Also run basic Python DNS resolution as backup
    python_file = run_python_dns(subdomains_file, resolved_dir)
    
    # Merge results
    merged_file = resolved_dir / "dnsx.txt"
    merge_dns_results([dnsx_file, python_file], merged_file)
    
    # Statistics
    total_resolved = len(read_file_lines(merged_file))
    total_input = len(read_file_lines(subdomains_file))
    logger.info(f"Resolved {total_resolved} domains out of {total_input}")
    
    return merged_file


def run_dnsx(subdomains_file: Path, outdir: Path) -> Path:
    """Run dnsx for DNS resolution."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "dnsx_raw.txt"
    
    try:
        logger.debug("Running dnsx")
        cmd = [
            "dnsx",
            "-l", str(subdomains_file),
            "-a", "-aaaa",
            "-silent",
            "-o", str(output_file)
        ]
        
        result = run_command(cmd, timeout=300)
        
        if result.returncode == 0:
            count = len(read_file_lines(output_file))
            logger.info(f"dnsx resolved {count} domains")
        else:
            logger.warning("dnsx failed")
            
    except Exception as e:
        logger.error(f"Error running dnsx: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_python_dns(subdomains_file: Path, outdir: Path) -> Path:
    """Run Python DNS resolution as backup."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "python_dns.txt"
    
    subdomains = read_file_lines(subdomains_file)
    resolved_domains = []
    
    logger.debug("Running Python DNS resolution")
    
    for subdomain in subdomains:
        try:
            # Try to resolve the domain
            socket.gethostbyname(subdomain)
            resolved_domains.append(subdomain)
            
        except socket.gaierror:
            # Domain doesn't resolve
            continue
        except Exception as e:
            logger.debug(f"Error resolving {subdomain}: {str(e)}")
            continue
    
    write_file_lines(output_file, resolved_domains)
    logger.info(f"Python DNS resolved {len(resolved_domains)} domains")
    
    return output_file


def merge_dns_results(input_files: List[Path], output_file: Path):
    """Merge DNS resolution results from multiple tools."""
    logger = logging.getLogger(__name__)
    
    all_domains = set()
    
    for file_path in input_files:
        if file_path.exists():
            domains = read_file_lines(file_path)
            for domain in domains:
                # Extract domain from dnsx output format (domain [IP])
                if '[' in domain and ']' in domain:
                    domain = domain.split('[')[0].strip()
                
                domain = domain.strip()
                if domain:
                    all_domains.add(domain)
    
    # Write merged results
    sorted_domains = sorted(list(all_domains))
    write_file_lines(output_file, sorted_domains)
    
    logger.debug(f"Merged {len(all_domains)} unique resolved domains")


def run_massdns(subdomains_file: Path, outdir: Path) -> Path:
    """Run massdns for bulk DNS resolution (if available)."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "massdns.txt"
    
    try:
        logger.debug("Running massdns")
        
        # Create resolvers file
        resolvers_file = outdir / "resolvers.txt"
        resolvers = [
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
            "208.67.222.222",
            "208.67.220.220"
        ]
        write_file_lines(resolvers_file, resolvers)
        
        cmd = [
            "massdns",
            "-r", str(resolvers_file),
            "-t", "A",
            "-o", "S",
            "-w", str(output_file),
            str(subdomains_file)
        ]
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            # Parse massdns output
            resolved_domains = []
            lines = read_file_lines(output_file)
            
            for line in lines:
                if line and not line.startswith(';'):
                    parts = line.split()
                    if len(parts) >= 1:
                        domain = parts[0].rstrip('.')
                        if domain:
                            resolved_domains.append(domain)
            
            # Write clean output
            clean_output = outdir / "massdns_clean.txt"
            write_file_lines(clean_output, list(set(resolved_domains)))
            
            logger.info(f"massdns resolved {len(resolved_domains)} domains")
            return clean_output
            
        else:
            logger.warning("massdns failed")
            
    except Exception as e:
        logger.debug(f"massdns not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_puredns(subdomains_file: Path, outdir: Path) -> Path:
    """Run puredns for DNS resolution (if available)."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "puredns.txt"
    
    try:
        logger.debug("Running puredns")
        cmd = [
            "puredns", "resolve",
            str(subdomains_file),
            "-w", str(output_file)
        ]
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            count = len(read_file_lines(output_file))
            logger.info(f"puredns resolved {count} domains")
        else:
            logger.warning("puredns failed")
            
    except Exception as e:
        logger.debug(f"puredns not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def get_dns_records(domain: str, record_type: str = "A") -> List[str]:
    """Get DNS records for a domain using dig."""
    logger = logging.getLogger(__name__)
    records = []
    
    try:
        cmd = ["dig", "+short", domain, record_type]
        result = run_command(cmd, timeout=10)
        
        if result.returncode == 0:
            records = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
    except Exception as e:
        logger.debug(f"Error getting DNS records for {domain}: {str(e)}")
    
    return records


def check_dns_wildcards(domain: str) -> bool:
    """Check if domain has wildcard DNS records."""
    logger = logging.getLogger(__name__)
    
    try:
        # Generate random subdomain
        import random
        import string
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=10))
        test_domain = f"{random_sub}.{domain}"
        
        # Try to resolve it
        try:
            socket.gethostbyname(test_domain)
            logger.warning(f"Wildcard DNS detected for {domain}")
            return True
        except socket.gaierror:
            return False
            
    except Exception as e:
        logger.debug(f"Error checking wildcard DNS for {domain}: {str(e)}")
        return False


def resolve_with_multiple_resolvers(domain: str) -> Dict[str, List[str]]:
    """Resolve domain using multiple DNS resolvers."""
    resolvers = {
        "google": "8.8.8.8",
        "cloudflare": "1.1.1.1",
        "quad9": "9.9.9.9",
        "opendns": "208.67.222.222"
    }
    
    results = {}
    
    for name, resolver in resolvers.items():
        try:
            cmd = ["dig", f"@{resolver}", "+short", domain, "A"]
            result = run_command(cmd, timeout=10)
            
            if result.returncode == 0:
                ips = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                results[name] = ips
                
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error with resolver {name}: {str(e)}")
            results[name] = []
    
    return results


def get_cname_records(domain: str) -> List[str]:
    """Get CNAME records for a domain."""
    logger = logging.getLogger(__name__)
    
    try:
        cmd = ["dig", "+short", domain, "CNAME"]
        result = run_command(cmd, timeout=10)
        
        if result.returncode == 0:
            cnames = [line.strip().rstrip('.') for line in result.stdout.split('\n') if line.strip()]
            return cnames
            
    except Exception as e:
        logger.debug(f"Error getting CNAME records for {domain}: {str(e)}")
    
    return []


def check_dns_zone_transfer(domain: str) -> bool:
    """Check if DNS zone transfer is possible."""
    logger = logging.getLogger(__name__)
    
    try:
        # First get nameservers
        cmd = ["dig", "+short", domain, "NS"]
        result = run_command(cmd, timeout=10)
        
        if result.returncode == 0:
            nameservers = [line.strip().rstrip('.') for line in result.stdout.split('\n') if line.strip()]
            
            for ns in nameservers:
                try:
                    # Try zone transfer
                    cmd = ["dig", f"@{ns}", domain, "AXFR"]
                    result = run_command(cmd, timeout=30)
                    
                    if result.returncode == 0 and "Transfer failed" not in result.stdout:
                        logger.warning(f"Zone transfer possible from {ns}")
                        return True
                        
                except Exception:
                    continue
                    
    except Exception as e:
        logger.debug(f"Error checking zone transfer for {domain}: {str(e)}")
    
    return False


def extract_ips_from_resolved(resolved_file: Path, outdir: Path) -> Path:
    """Extract IP addresses from resolved domains."""
    logger = logging.getLogger(__name__)
    
    domains = read_file_lines(resolved_file)
    ips = set()
    
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            ips.add(ip)
        except Exception:
            continue
    
    # Write IPs to file
    ips_file = outdir / "ips.txt"
    write_file_lines(ips_file, sorted(list(ips)))
    
    logger.info(f"Extracted {len(ips)} unique IP addresses")
    return ips_file