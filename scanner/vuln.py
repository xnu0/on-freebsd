import json
import logging
from pathlib import Path
from typing import List, Optional

from .utils import run_command, read_file_lines, write_file_lines

logger = logging.getLogger(__name__)


def run_nuclei(urls_file: Path, outdir: Path, templates: Optional[str] = None, stealth: bool = False) -> Path:
    """Run nuclei scanner against URLs."""
    results_dir = outdir / "nuclei" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    output_file = results_dir / "nuclei.txt"

    cmd = ["nuclei", "-l", str(urls_file), "-o", str(output_file), "-json"]
    if templates:
        cmd.extend(["-t", templates])
    if stealth:
        cmd.extend(["-rate", "50"])

    try:
        result = run_command(cmd, timeout=1800)
        if result.returncode != 0:
            logger.warning("nuclei execution failed")
    except Exception as exc:
        logger.error(f"Error running nuclei: {exc}")
        output_file.touch()

    return output_file


def run_ffuf(live_file: Path, outdir: Path, wordlist: Optional[str] = None) -> None:
    """Run ffuf for directory and file fuzzing on live services."""
    ffuf_dir = outdir / "ffuf"
    ffuf_dir.mkdir(parents=True, exist_ok=True)
    wordlist = wordlist or "/usr/share/seclists/Discovery/Web-Content/common.txt"
    urls = read_file_lines(live_file)

    for url in urls:
        safe = url.replace("://", "_").replace("/", "_")
        output_file = ffuf_dir / f"{safe}.json"
        cmd = [
            "ffuf",
            "-u", f"{url.rstrip('/')}/FUZZ",
            "-w", wordlist,
            "-o", str(output_file),
            "-of", "json",
        ]
        try:
            result = run_command(cmd, timeout=900)
            if result.returncode != 0:
                logger.warning(f"ffuf failed for {url}")
        except Exception as exc:
            logger.error(f"Error running ffuf on {url}: {exc}")
            output_file.touch()


def run_gf(urls_file: Path, outdir: Path, patterns: Optional[List[str]] = None) -> None:
    """Run gf patterns against URLs."""
    gf_dir = outdir / "gf"
    gf_dir.mkdir(parents=True, exist_ok=True)
    patterns = patterns or ["xss", "sqli", "lfi", "ssrf", "redirect", "rce"]

    for pattern in patterns:
        output_file = gf_dir / f"{pattern}.txt"
        cmd = ["bash", "-c", f"cat {urls_file} | gf {pattern}"]
        try:
            result = run_command(cmd, timeout=300)
            if result.returncode == 0:
                lines = [l for l in result.stdout.splitlines() if l.strip()]
                write_file_lines(output_file, lines)
            else:
                output_file.touch()
        except Exception as exc:
            logger.error(f"gf pattern {pattern} failed: {exc}")
            output_file.touch()


def run_secretfinder(js_dir: Path, outdir: Path) -> None:
    """Run trufflehog and SecretFinder on JavaScript files to detect secrets."""
    secrets_dir = outdir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    truffle_file = secrets_dir / "trufflehog.json"
    cmd = ["trufflehog", "filesystem", str(js_dir), "--json"]
    try:
        result = run_command(cmd, timeout=900)
        if result.returncode == 0:
            with open(truffle_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
        else:
            truffle_file.touch()
    except Exception as exc:
        logger.error(f"trufflehog failed: {exc}")
        truffle_file.touch()

    secretfinder_file = secrets_dir / "secretfinder.txt"
    for js_file in js_dir.glob("*.js"):
        cmd = ["python3", "SecretFinder.py", "-i", str(js_file), "-o", "cli"]
        try:
            result = run_command(cmd, timeout=300)
            if result.returncode == 0:
                with open(secretfinder_file, "a", encoding="utf-8") as f:
                    f.write(result.stdout)
            else:
                logger.debug(f"SecretFinder returned {result.returncode} for {js_file}")
        except Exception as exc:
            logger.debug(f"SecretFinder error on {js_file}: {exc}")


