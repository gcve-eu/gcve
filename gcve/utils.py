import importlib.metadata
import os
from pathlib import Path
from typing import Mapping

import requests

try:
    gcve_version = importlib.metadata.version("gcve")
except Exception:
    gcve_version = ""


def load_cached_headers(headers_file: str) -> dict[str, str]:
    """Load cached headers from file."""
    if not os.path.exists(headers_file):
        return {}
    with open(headers_file) as f:
        return dict(line.strip().split(":", 1) for line in f if ":" in line)


def save_cached_headers(headers: Mapping[str, str], headers_file: str) -> None:
    """Save selected headers to a cache file."""
    keys_to_store = ["ETag", "Last-Modified"]
    with open(headers_file, "w") as f:
        for key in keys_to_store:
            if key in headers:
                f.write(f"{key}:{headers[key]}\n")


USER_AGENT = f"GCVE Python Client/{gcve_version} (+https://github.com/gcve-eu/gcve)"


def fetch_file(url: str, destination_path: Path, timeout: int = 10) -> bool:
    """Download a file only if it has changed on the server.

    Returns True if the file was downloaded, False if the cached copy is still current.
    Raises requests.RequestException if the request fails."""
    cached_headers = load_cached_headers(f"{destination_path}.headers.cache")

    request_headers = {"User-Agent": USER_AGENT}
    # Conditional headers are only useful if the cached file is still there.
    if destination_path.exists():
        if "ETag" in cached_headers:
            request_headers["If-None-Match"] = cached_headers["ETag"]
        if "Last-Modified" in cached_headers:
            request_headers["If-Modified-Since"] = cached_headers["Last-Modified"]

    response = requests.get(url, headers=request_headers, timeout=timeout)

    if response.status_code == 304:
        return False  # File unchanged

    response.raise_for_status()

    # Ensure parent directory exists
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    with open(destination_path, "wb") as f:
        f.write(response.content)

    save_cached_headers(response.headers, f"{destination_path}.headers.cache")
    return True  # File was updated


def download_file(url: str, destination_path: Path) -> bool:
    """Download gcve.json only if it has changed on the server."""
    try:
        if fetch_file(url, destination_path):
            print(f"Downloaded updated {url} to {destination_path.as_posix()}")
            return True
        print(f"No changes — using cached {destination_path.as_posix()}.")
        return False
    except requests.RequestException as e:
        print(f"Failed to download {url}: {e}")
        return False
