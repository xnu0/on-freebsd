import json
import logging
from datetime import datetime
from pathlib import Path

from .utils import read_file_lines, count_file_lines, write_file_lines

logger = logging.getLogger(__name__)


def _get_time_bounds(base_dir: Path) -> tuple[datetime, datetime]:
    files = [p.stat().st_mtime for p in base_dir.rglob('*') if p.exists()]
    if not files:
        now = datetime.now()
        return now, now
    start = min(files)
    end = max(files)
    return datetime.fromtimestamp(start), datetime.fromtimestamp(end)


def compile_summary(base_dir: Path) -> None:
    """Generate a summary report of gathered data."""
    report_dir = base_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "target": base_dir.name,
    }

    start_time, end_time = _get_time_bounds(base_dir)
    summary["scan_start"] = start_time.isoformat()
    summary["scan_end"] = end_time.isoformat()
    summary["duration_seconds"] = int((end_time - start_time).total_seconds())

    summary["subdomains"] = count_file_lines(base_dir / "subdomains" / "all.txt")
    summary["resolved_domains"] = count_file_lines(base_dir / "resolved" / "dnsx.txt")
    summary["live_services"] = count_file_lines(base_dir / "live" / "all.txt")
    summary["open_ports"] = count_file_lines(base_dir / "ports" / "open_ports.txt")
    summary["urls"] = count_file_lines(base_dir / "urls" / "filtered" / "all.txt")

    port_categories = {}
    for f in (base_dir / "ports").glob("ports-*.txt"):
        port_categories[f.stem.replace("ports-", "")] = count_file_lines(f)
    summary["port_categories"] = port_categories

    url_categories = {}
    for f in (base_dir / "urls" / "filtered").glob("*.txt"):
        if f.name != "all.txt":
            url_categories[f.stem] = count_file_lines(f)
    summary["url_categories"] = url_categories

    nuclei_count = 0
    for f in (base_dir / "nuclei" / "results").glob("*.txt"):
        nuclei_count += count_file_lines(f)
    summary["vulnerabilities"] = nuclei_count

    secrets_count = 0
    for f in (base_dir / "secrets").glob("*"):
        secrets_count += count_file_lines(f)
    summary["secrets"] = secrets_count

    # Write plaintext summary
    text_lines = [
        f"Target: {summary['target']}",
        f"Start: {summary['scan_start']}",
        f"End: {summary['scan_end']}",
        f"Duration: {summary['duration_seconds']} seconds",
        f"Subdomains: {summary['subdomains']}",
        f"Resolved Domains: {summary['resolved_domains']}",
        f"Live Services: {summary['live_services']}",
        f"Open Ports: {summary['open_ports']}",
        f"URLs: {summary['urls']}",
        f"Vulnerabilities: {summary['vulnerabilities']}",
        f"Secrets Found: {summary['secrets']}",
    ]
    write_file_lines(report_dir / "summary.txt", text_lines)

    with open(report_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    try:
        html_file = report_dir / "summary.html"
        html = ["<html><body><h1>Scan Summary</h1><ul>"]
        for key, value in summary.items():
            if isinstance(value, dict):
                html.append(f"<li>{key}<ul>")
                for k, v in value.items():
                    html.append(f"<li>{k}: {v}</li>")
                html.append("</ul></li>")
            else:
                html.append(f"<li>{key}: {value}</li>")
        html.append("</ul></body></html>")
        with open(html_file, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
    except Exception as exc:
        logger.debug(f"Failed to generate HTML report: {exc}")

    logger.info("Summary report created")

