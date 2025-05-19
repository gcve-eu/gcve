import base64
import json
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from gcve.gna import GNAEntry
from gcve.utils import download_file

BASE_PATH: Path = Path(".gcve")
GCVE_PATH: Path = Path("registry/gcve.json")
SIG_PATH: Path = Path("registry/gcve.json.sigsha512")
PUBKEY_PATH: Path = Path("registry/public.pem")


def load_registry(base_path: Path = BASE_PATH) -> List[GNAEntry]:
    """Load the downloaded registry (gcve.json) into a Python object."""
    with open(base_path / GCVE_PATH, encoding="utf-8") as f:
        return json.load(f)


def update_registry(base_path: Path = BASE_PATH) -> bool:
    """Download registry (gcve.json) only if it has changed on the server."""
    return download_file("https://gcve.eu/dist/gcve.json", base_path / GCVE_PATH)


def update_registry_public_key(base_path: Path = BASE_PATH) -> bool:
    """Download key/public.pem only if it has changed on the server."""
    return download_file("https://gcve.eu/dist/key/public.pem", base_path / PUBKEY_PATH)


def update_registry_signature(base_path: Path = BASE_PATH) -> bool:
    """Download gcve.json.sigsha512 only if it has changed on the server."""
    return download_file(
        "https://gcve.eu/dist/gcve.json.sigsha512", base_path / SIG_PATH
    )


def verify_registry_integrity(base_path: Path = BASE_PATH) -> bool:
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
        with open(base_path / PUBKEY_PATH, "rb") as key_file:
            public_key = load_pem_public_key(key_file.read())

        # Read and decode the base64 signature
        with open(base_path / SIG_PATH, "rb") as sig_file:
            signature = base64.b64decode(sig_file.read())

        # Read the JSON file content
        with open(base_path / GCVE_PATH, "rb") as json_file:
            data = json_file.read()

        # Verify the signature
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA512())  # type: ignore

        return True
    except Exception:
        print("Integrity check failed.")
        return False
