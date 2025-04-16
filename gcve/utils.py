import json
import os

import requests

HEADERS_FILE = "gcve_headers.cache"
DEFAULT_DESTINATION = "gcve.json"


def load_gcve_json(file_path: str = "gcve.json"):
    """Load the downloaded gcve.json into a Python object."""
    with open(file_path, encoding="utf-8") as f:
        return json.load(f)


def load_cached_headers() -> dict:
    """Load cached headers from file."""
    if not os.path.exists(HEADERS_FILE):
        return {}
    with open(HEADERS_FILE) as f:
        return dict(line.strip().split(":", 1) for line in f if ":" in line)


def save_cached_headers(headers: dict) -> None:
    """Save selected headers to a cache file."""
    keys_to_store = ["ETag", "Last-Modified"]
    with open(HEADERS_FILE, "w") as f:
        for key in keys_to_store:
            if key in headers:
                f.write(f"{key}:{headers[key]}\n")


def download_gcve_json_if_changed(destination_path: str = DEFAULT_DESTINATION) -> bool:
    """Download gcve.json only if it has changed on the server."""
    url = "https://gcve.eu/dist/gcve.json"
    cached_headers = load_cached_headers()

    request_headers = {}
    if "ETag" in cached_headers:
        request_headers["If-None-Match"] = cached_headers["ETag"]
    if "Last-Modified" in cached_headers:
        request_headers["If-Modified-Since"] = cached_headers["Last-Modified"]

    try:
        response = requests.get(url, headers=request_headers, timeout=10)

        if response.status_code == 304:
            print("No changes — using cached gcve.json.")
            return False  # File unchanged

        response.raise_for_status()
        with open(destination_path, "wb") as f:
            f.write(response.content)

        save_cached_headers(response.headers)
        print(f"Downloaded updated gcve.json to {destination_path}")
        return True  # File was updated

    except requests.RequestException as e:
        print(f"Failed to download gcve.json: {e}")
        return False
