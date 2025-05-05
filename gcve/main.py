import re
from datetime import datetime, timezone
from typing import Generator, List, Optional, Set, Tuple

from gcve.gna import GNAEntry, get_gna_id_by_short_name
from gcve.utils import (
    download_directory_signature_if_changed,
    download_gcve_json_if_changed,
    download_public_key_if_changed,
    load_gcve_json,
    verify_gcve_integrity,
)

# from vulnerabilitylookup.vulnerabilitylookup import VulnerabilityLookup

# vulnerabilitylookup: VulnerabilityLookup = VulnerabilityLookup()  # type: ignore[unused-ignore]
known_cves: Set[str] = set()


# https://gcve.eu/about/#gcve-identifier-format
GCVE_REGEX = re.compile(r"GCVE-(\d+)-(\d{4})-(\d{4,})")


def validate_gcve_id(gcve_id: str) -> Optional[Tuple[int, int, int]]:
    """
    Validate a GCVE ID and return its parsed components as a tuple:
    (GNA ID, Year, Uniq ID)

    Returns None if the format is invalid.
    """
    match = GCVE_REGEX.fullmatch(gcve_id)
    if not match:
        return None
    gna_id, year, number = map(int, match.groups())
    return gna_id, year, number


def normalize_cve_id(cve_id: str) -> str:
    """Ensure CVE ID is in CVE-YYYY-NNNN format."""
    match = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve_id)
    if not match:
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    year, number = match.groups()
    return f"CVE-{year}-{int(number):04d}"


def to_gcve_id(cve_id: str) -> str:
    """Convert a CVE ID to a GCVE-compatible ID.

    GCVE-0 is technically the CVE reference."""
    cve_id = normalize_cve_id(cve_id.upper())
    year = cve_id.split("-")[1]
    number = cve_id.split("-")[2]
    return f"GCVE-0-{year}-{number}"


def gcve0_to_cve(gcve_id: str) -> str:
    """
    Convert a GCVE-0 ID to a CVE ID.

    Args:
        gcve_id (str): The GCVE ID to convert.

    Returns:
        str: The corresponding CVE ID.

    Raises:
        ValueError: If the input is not a valid GCVE ID.
    """
    import re

    match = re.fullmatch(r"GCVE-0-(\d{4})-(\d{4,})", gcve_id, re.IGNORECASE)
    if not match:
        raise ValueError(f"Invalid GCVE ID format: {gcve_id}")

    year, unique_id = match.groups()
    return f"CVE-{year}-{unique_id}"


def gcve_generator(existing_gcves: Set[str], gna_id: int) -> Generator[str, None, None]:
    """Generate new GCVE-1-YYYY-NNNN IDs, avoiding conflicts with existing.

    GCVE-1 is a CIRCL Vulnerability-Lookup allocation."""
    year = datetime.now(timezone.utc).year
    count = 1
    while True:
        candidate = f"GCVE-{gna_id}-{year}-{count:04d}"
        if candidate not in existing_gcves:
            yield candidate
        count += 1


if __name__ == "__main__":
    # Point of entry in execution mode

    # --- Examples of usage ---

    # Retrieve the public key if it has changed
    download_public_key_if_changed()

    # Retrieve the signature of the directory if it has changed
    download_directory_signature_if_changed()

    # Retrieve the JSON Directory file available at GCVE.eu
    updated: bool = download_gcve_json_if_changed()

    # Verify the integrity of the directory
    if integrity := verify_gcve_integrity():
        # Load the GCVE directory
        gcve_data: List[GNAEntry] = load_gcve_json()
    else:
        exit(1)

    # Validating a GCVE id
    print("\nValidating a GCVE ID:")
    if res := validate_gcve_id("GCVE-1-2025-00001"):
        print(f"GNA ID: {res[0]}\nYear: {res[1]}\nUnique ID: {res[2]}")

    # Create GCVE from existing CVE
    print("\n\nCreate GCVE from existing CVE:")
    print(to_gcve_id("CVE-2023-1234"))  # GCVE-0-2023-1234

    # Generate new GCVE-1 entries
    print("\n\nGenerate GCVE-1 entries:")
    # we suppose that all known CVEs are in kvrocks:
    if CIRCL_GNA_ID := get_gna_id_by_short_name("CIRCL", gcve_data):
        # existing_gcves = {to_gcve_id(cve) for cve in vulnerabilitylookup.get_all_ids()}
        existing_gcves = {to_gcve_id(cve) for cve in known_cves}
        generator = gcve_generator(existing_gcves, CIRCL_GNA_ID)
        for _ in range(5):
            print(next(generator))

    # Upgrading GCVE-ID to GCVE-0
    print("\n\nUpgrading GCVE-1 to GCVE-0:")
    # If a GCVE-1 ID like GCVE-1-2025-0005 later matches a new official CVE like CVE-2025-0005, we just remap it using:
    if "CVE-2025-0005" in known_cves:
        upgraded = to_gcve_id("CVE-2025-0005")
        print(upgraded)
