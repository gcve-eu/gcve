import base64
import json
import os
from pathlib import Path
from typing import List

import requests  # type: ignore[import-untyped]
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from gcve.gna import GNAEntry

GCVE_PATH: Path = Path("data/gcve.json")
SIG_PATH: Path = Path("data/gcve.json.sigsha512")
PUBKEY_PATH: Path = Path("data/public.pem")


def load_gcve_json(file_path: str = "data/gcve.json") -> List[GNAEntry]:
    """Load the downloaded gcve.json into a Python object."""
    with open(file_path, encoding="utf-8") as f:
        return json.load(f)


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


def download_file_if_changed(url: str, destination_path: str) -> bool:
    """Download gcve.json only if it has changed on the server."""
    data = Path("data")
    data.mkdir(parents=True, exist_ok=True)

    cached_headers = load_cached_headers(f"{(data / destination_path)}.headers.cache")

    request_headers = {}
    if "ETag" in cached_headers:
        request_headers["If-None-Match"] = cached_headers["ETag"]
    if "Last-Modified" in cached_headers:
        request_headers["If-Modified-Since"] = cached_headers["Last-Modified"]

    try:
        response = requests.get(url, headers=request_headers, timeout=10)

        if response.status_code == 304:
            print(f"No changes — using cached {(data / destination_path).as_posix()}.")
            return False  # File unchanged

        response.raise_for_status()
        with open((data / destination_path), "wb") as f:
            f.write(response.content)

        save_cached_headers(
            dict(response.headers), f"{(data / destination_path)}.headers.cache"
        )
        print(f"Downloaded updated {url} to {(data / destination_path).as_posix()}")
        return True  # File was updated

    except requests.RequestException as e:
        print(f"Failed to download {url}: {e}")
        return False


def download_gcve_json_if_changed() -> bool:
    """Download gcve.json only if it has changed on the server."""
    return download_file_if_changed("https://gcve.eu/dist/gcve.json", "gcve.json")


def download_public_key_if_changed() -> bool:
    """Download gcve.json only if it has changed on the server."""
    return download_file_if_changed("https://gcve.eu/dist/key/public.pem", "public.pem")


def download_directory_signature_if_changed() -> bool:
    """Download gcve.json only if it has changed on the server."""
    return download_file_if_changed(
        "https://gcve.eu/dist/gcve.json.sigsha512", "gcve.json.sigsha512"
    )


def verify_gcve_integrity(
    json_path: Path = GCVE_PATH,
    sig_path: Path = SIG_PATH,
    pubkey_path: Path = PUBKEY_PATH,
) -> bool:
    """
    Verifies the integrity of a JSON file using a SHA-512 signature and a public key.

    Args:
        json_path (Path): Path to the JSON file.
        sig_path (Path): Path to the base64-encoded signature file.
        pubkey_path (Path): Path to the PEM-formatted public key.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        # Load the public key
        with open(pubkey_path, "rb") as key_file:
            public_key = load_pem_public_key(key_file.read())

        # Read and decode the base64 signature
        with open(sig_path, "rb") as sig_file:
            signature = base64.b64decode(sig_file.read())

        # Read the JSON file content
        with open(json_path, "rb") as json_file:
            data = json_file.read()

        # Verify the signature
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA512())  # type: ignore

        return True
    except Exception:
        print("Integrity check failed.")
        return False
