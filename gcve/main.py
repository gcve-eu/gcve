import re
from datetime import datetime, timezone
from typing import Generator, List, Optional, Set, Tuple, TypedDict

# from vulnerabilitylookup.vulnerabilitylookup import VulnerabilityLookup

# vulnerabilitylookup: VulnerabilityLookup = VulnerabilityLookup()  # type: ignore[unused-ignore]
known_cves: Set[str] = set()


class GNAEntry(TypedDict, total=False):
    """Define a GNA entry:
    https://gcve.eu/about/#eligibility-and-process-to-obtain-a-gna-id"""

    id: int
    short_name: str
    full_name: str
    cpe_vendor_name: str
    gcve_url: str
    gcve_api: str
    gcve_dump: str
    gcve_allocation: str


# JSON Directory File Available at GCVE.eu
GCVE_eu: List[GNAEntry] = [
    {"id": 0, "short_name": "CVE", "full_name": "CVE Program"},
    {
        "id": 1,
        "short_name": "CIRCL",
        "cpe_vendor_name": "circl",
        "full_name": "Computer Incident Response Center Luxembourg",
        "gcve_url": "https://vulnerability.circl.lu",
        "gcve_api": "https://vulnerability.circl.lu/api/",
        "gcve_dump": "https://vulnerability.circl.lu/dumps/",
        "gcve_allocation": "https://vulnerability.circl.lu",
    },
]

# https://gcve.eu/about/#gcve-identifier-format
GCVE_REGEX = re.compile(r"GCVE-(\d+)-(\d{4})-(\d{4,})")


def get_gna_id_by_short_name(
    short_name: str, gna_list: List[GNAEntry]
) -> Optional[int]:
    """Return the GNA ID for a given short name, or None if not found."""
    for entry in gna_list:
        if entry.get("short_name") == short_name:
            return entry.get("id")
    return None


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
    # Validating a GCVE id
    print("Validating a GCVE ID:")
    if res := validate_gcve_id("GCVE-1-2025-00001"):
        print(f"GNA ID: {res[0]}\nYear: {res[1]}\nUnique ID: {res[2]}")

    # Create GCVE from existing CVE
    print("\n\nCreate GCVE from existing CVE:")
    print(to_gcve_id("CVE-2023-1234"))  # GCVE-0-2023-1234

    # Generate new GCVE-1 entries
    print("\n\nGenerate GCVE-1 entries:")
    # we suppose that all known CVEs are in kvrocks:
    if CIRCL_GNA_ID := get_gna_id_by_short_name("CIRCL", GCVE_eu):
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
