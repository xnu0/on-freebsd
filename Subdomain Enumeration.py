#!/usr/bin/env python3
"""
Bug Bounty Scanner - Subdomain Enumeration
==========================================

Subdomain enumeration using multiple tools and sources.
"""

import logging
import json
import requests
from pathlib import Path
from typing import List, Set
from .utils import run_command, read_file_lines, write_file_lines, merge_files, stealth_request


def enum_subdomains(target: str, outdir: Path) -> Path:
    """
    Enumerate subdomains using multiple tools and sources.
    
    Args:
        target: Target domain
        outdir: Output directory
        
    Returns:
        Path to merged subdomains file
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting subdomain enumeration for {target}")
    
    subdomains_dir = outdir / "subdomains"
    subdomains_dir.mkdir(parents=True, exist_ok=True)
    
    # Run different subdomain enumeration tools
    subfinder_file = run_subfinder(target, subdomains_dir)
    amass_file = run_amass(target, subdomains_dir)
    crtsh_file = run_crtsh(target, subdomains_dir)
    
    # Merge all results
    all_file = subdomains_dir / "all.txt"
    input_files = [subfinder_file, amass_file, crtsh_file]
    merge_files(input_files, all_file, deduplicate=True)
    
    # Statistics
    total_subdomains = len(read_file_lines(all_file))
    logger.info(f"Found {total_subdomains} unique subdomains")
    
    return all_file


def run_subfinder(target: str, outdir: Path) -> Path:
    """Run subfinder for subdomain enumeration."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "subfinder.txt"
    
    try:
        logger.debug("Running subfinder")
        cmd = [
            "subfinder",
            "-d", target,
            "-o", str(output_file),
            "-silent"
        ]
        
        result = run_command(cmd, timeout=300)
        
        if result.returncode == 0:
            count = len(read_file_lines(output_file))
            logger.info(f"Subfinder found {count} subdomains")
        else:
            logger.warning("Subfinder failed")
            
    except Exception as e:
        logger.error(f"Error running subfinder: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_amass(target: str, outdir: Path) -> Path:
    """Run amass for subdomain enumeration."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "amass.txt"
    
    try:
        logger.debug("Running amass")
        cmd = [
            "amass", "enum",
            "-d", target,
            "-o", str(output_file),
            "-silent"
        ]
        
        result = run_command(cmd, timeout=600)
        
        if result.returncode == 0:
            count = len(read_file_lines(output_file))
            logger.info(f"Amass found {count} subdomains")
        else:
            logger.warning("Amass failed")
            
    except Exception as e:
        logger.error(f"Error running amass: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_crtsh(target: str, outdir: Path) -> Path:
    """Query crt.sh for subdomain enumeration."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "crtsh.txt"
    subdomains = set()
    
    try:
        logger.debug("Querying crt.sh")
        
        # Query crt.sh API
        url = f"https://crt.sh/?q=%.{target}&output=json"
        response = stealth_request(url, timeout=30)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                for entry in data:
                    if 'name_value' in entry:
                        names = entry['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if name and name.endswith(f".{target}"):
                                # Remove wildcards
                                name = name.replace('*.', '')
                                if name != target:
                                    subdomains.add(name)
                
                logger.info(f"crt.sh found {len(subdomains)} subdomains")
                
            except json.JSONDecodeError:
                logger.warning("Failed to parse crt.sh response")
                
        else:
            logger.warning("Failed to query crt.sh")
            
    except Exception as e:
        logger.error(f"Error querying crt.sh: {str(e)}")
    
    # Write results
    write_file_lines(output_file, sorted(list(subdomains)))
    
    return output_file


def run_assetfinder(target: str, outdir: Path) -> Path:
    """Run assetfinder for subdomain enumeration (if available)."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "assetfinder.txt"
    
    try:
        logger.debug("Running assetfinder")
        cmd = [
            "assetfinder", target
        ]
        
        result = run_command(cmd, timeout=300)
        
        if result.returncode == 0:
            subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            write_file_lines(output_file, subdomains)
            logger.info(f"Assetfinder found {len(subdomains)} subdomains")
        else:
            logger.warning("Assetfinder failed")
            
    except Exception as e:
        logger.debug(f"Assetfinder not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def run_findomain(target: str, outdir: Path) -> Path:
    """Run findomain for subdomain enumeration (if available)."""
    logger = logging.getLogger(__name__)
    output_file = outdir / "findomain.txt"
    
    try:
        logger.debug("Running findomain")
        cmd = [
            "findomain",
            "-t", target,
            "-o", str(outdir)
        ]
        
        result = run_command(cmd, timeout=300)
        
        # Findomain creates a file named after the target
        findomain_output = outdir / f"{target}.txt"
        if findomain_output.exists():
            # Move to our naming convention
            findomain_output.rename(output_file)
            count = len(read_file_lines(output_file))
            logger.info(f"Findomain found {count} subdomains")
        else:
            logger.warning("Findomain failed")
            output_file.touch()
            
    except Exception as e:
        logger.debug(f"Findomain not available or failed: {str(e)}")
        # Create empty file if command failed
        output_file.touch()
    
    return output_file


def filter_subdomains(subdomains_file: Path, outdir: Path, target: str) -> Path:
    """Filter subdomains to remove invalid entries."""
    logger = logging.getLogger(__name__)
    
    input_subdomains = read_file_lines(subdomains_file)
    valid_subdomains = []
    
    for subdomain in input_subdomains:
        subdomain = subdomain.strip().lower()
        
        # Skip empty lines
        if not subdomain:
            continue
            
        # Skip wildcards
        if subdomain.startswith('*.'):
            subdomain = subdomain[2:]
            
        # Skip if doesn't end with target domain
        if not subdomain.endswith(f".{target}") and subdomain != target:
            continue
            
        # Skip if contains invalid characters
        if any(char in subdomain for char in ['<', '>', '"', "'"]):
            continue
            
        # Add to valid list
        if subdomain not in valid_subdomains:
            valid_subdomains.append(subdomain)
    
    # Write filtered results
    filtered_file = outdir / "filtered.txt"
    write_file_lines(filtered_file, valid_subdomains)
    
    logger.info(f"Filtered {len(input_subdomains)} subdomains to {len(valid_subdomains)} valid entries")
    
    return filtered_file


def deduplicate_subdomains(subdomains_file: Path) -> Path:
    """Remove duplicate subdomains while preserving order."""
    logger = logging.getLogger(__name__)
    
    subdomains = read_file_lines(subdomains_file)
    unique_subdomains = list(dict.fromkeys(subdomains))  # Preserve order
    
    # Write back to same file
    write_file_lines(subdomains_file, unique_subdomains)
    
    removed_count = len(subdomains) - len(unique_subdomains)
    if removed_count > 0:
        logger.info(f"Removed {removed_count} duplicate subdomains")
    
    return subdomains_file


def sort_subdomains(subdomains_file: Path) -> Path:
    """Sort subdomains alphabetically."""
    subdomains = read_file_lines(subdomains_file)
    sorted_subdomains = sorted(subdomains)
    write_file_lines(subdomains_file, sorted_subdomains)
    return subdomains_file


def validate_subdomains(subdomains_file: Path, target: str) -> List[str]:
    """Validate that subdomains are properly formatted."""
    logger = logging.getLogger(__name__)
    
    subdomains = read_file_lines(subdomains_file)
    valid_subdomains = []
    
    for subdomain in subdomains:
        subdomain = subdomain.strip().lower()
        
        # Basic validation
        if not subdomain:
            continue
            
        # Check if it's a valid subdomain format
        if '.' not in subdomain:
            continue
            
        # Check if it belongs to the target domain
        if not (subdomain.endswith(f".{target}") or subdomain == target):
            continue
            
        # Check for invalid characters
        if any(char in subdomain for char in [' ', '<', '>', '"', "'", '\\', '|']):
            continue
            
        valid_subdomains.append(subdomain)
    
    logger.debug(f"Validated {len(valid_subdomains)} subdomains out of {len(subdomains)}")
    return valid_subdomains