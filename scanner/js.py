import logging
import re
from pathlib import Path
from typing import List
from urllib.parse import urljoin

import jsbeautifier
import requests

from .utils import read_file_lines, write_file_lines, stealth_request
from .urls import extract_urls_from_js, extract_endpoints_from_js

logger = logging.getLogger(__name__)


def crawl_js_urls(urls_file: Path, stealth: bool = False) -> List[str]:
    """Crawl pages listed in ``urls_file`` for linked JavaScript URLs."""
    js_urls: set[str] = set()
    urls = read_file_lines(urls_file)

    for url in urls:
        try:
            resp = stealth_request(url) if stealth else requests.get(url, timeout=10)
            if not resp or resp.status_code >= 400:
                continue
            matches = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', resp.text, re.I)
            for match in matches:
                js_urls.add(urljoin(url, match))
        except Exception as exc:
            logger.debug(f"Failed to crawl {url}: {exc}")

    logger.info(f"Discovered {len(js_urls)} JavaScript URLs")
    return sorted(js_urls)


def _write_text(file_path: Path, content: str) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(content)


def download_and_beautify(js_urls: List[str], raw_dir: Path, beautified_dir: Path, stealth: bool = False) -> None:
    """Download JavaScript files, beautify them, and extract data."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    beautified_dir.mkdir(parents=True, exist_ok=True)

    options = jsbeautifier.default_options()
    options.indent_size = 2

    extracted_urls: set[str] = set()
    extracted_endpoints: set[str] = set()

    for url in js_urls:
        safe_name = re.sub(r'[^a-zA-Z0-9_\.]+', '_', url.split('/')[-1])
        if not safe_name.endswith('.js'):
            safe_name += '.js'
        raw_path = raw_dir / safe_name
        beaut_path = beautified_dir / safe_name

        try:
            resp = stealth_request(url) if stealth else requests.get(url, timeout=15)
            if not resp or resp.status_code >= 400:
                logger.debug(f"Failed to download {url}")
                continue
            raw_content = resp.text
            _write_text(raw_path, raw_content)

            beautified = jsbeautifier.beautify(raw_content, options)
            _write_text(beaut_path, beautified)

            extracted_urls.update(extract_urls_from_js(beautified))
            extracted_endpoints.update(extract_endpoints_from_js(beautified))
        except Exception as exc:
            logger.debug(f"Error processing {url}: {exc}")
            continue

    write_file_lines(beautified_dir / 'extracted_urls.txt', sorted(extracted_urls))
    write_file_lines(beautified_dir / 'api_endpoints.txt', sorted(extracted_endpoints))
    write_file_lines(raw_dir.parent / 'js_urls.txt', js_urls)
    logger.info(f"Downloaded and processed {len(js_urls)} JavaScript files")

