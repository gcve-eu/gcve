import os
from pathlib import Path

import requests  # type: ignore[import-untyped]


def load_cached_headers(headers_file: str) -> dict[str, str]:
    """Load cached headers from file."""
    if not os.path.exists(headers_file):
        return {}
    with open(headers_file) as f:
        return dict(line.strip().split(":", 1) for line in f if ":" in line)


def save_cached_headers(headers: dict[str, str], headers_file: str) -> None:
    """Save selected headers to a cache file."""
    keys_to_store = ["ETag", "Last-Modified"]
    with open(headers_file, "w") as f:
        for key in keys_to_store:
            if key in headers:
                f.write(f"{key}:{headers[key]}\n")


def download_file(url: str, destination_path: Path) -> bool:
    """Download gcve.json only if it has changed on the server."""
    cached_headers = load_cached_headers(f"{destination_path}.headers.cache")

    request_headers = {}
    if "ETag" in cached_headers:
        request_headers["If-None-Match"] = cached_headers["ETag"]
    if "Last-Modified" in cached_headers:
        request_headers["If-Modified-Since"] = cached_headers["Last-Modified"]

    try:
        response = requests.get(url, headers=request_headers, timeout=10)

        if response.status_code == 304:
            print(f"No changes — using cached {destination_path.as_posix()}.")
            return False  # File unchanged

        response.raise_for_status()

        # Ensure parent directory exists
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        with open(destination_path, "wb") as f:
            f.write(response.content)

        save_cached_headers(dict(response.headers), f"{destination_path}.headers.cache")
        print(f"Downloaded updated {url} to {destination_path.as_posix()}")
        return True  # File was updated

    except requests.RequestException as e:
        print(f"Failed to download {url}: {e}")
        return False
