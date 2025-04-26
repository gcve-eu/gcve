from typing import List, Optional, TypedDict


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


def get_gna_id_by_short_name(
    short_name: str, gna_list: List[GNAEntry]
) -> Optional[int]:
    """Return the GNA ID for a given short name, or None if not found."""
    for entry in gna_list:
        if entry.get("short_name") == short_name:
            return entry.get("id")
    return None
