from typing import List, Optional, TypedDict

# For Python >= 3.11
# class GNAEntry(TypedDict, total=False):
#     """Define a GNA entry:
#     https://gcve.eu/about/#eligibility-and-process-to-obtain-a-gna-id"""

#     id: Required[int]
#     short_name: Required[str]
#     full_name: str
#     cpe_vendor_name: str
#     gcve_url: str
#     gcve_api: str
#     gcve_dump: str
#     gcve_allocation: str
#     gcve_sync_api: str


# For Python >= 3.10
class GNAEntry(TypedDict):
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
    gcve_sync_api: str


def find_gna_by_short_name(short_name: str, gna_list: List[GNAEntry]) -> List[GNAEntry]:
    """Return the GNAs corresponding to the given short name, or an empty list if nothing found."""
    return [
        entry
        for entry in gna_list
        if short_name.lower() in entry.get("short_name", "").lower()
    ]


def get_gna_by_short_name(short_name: str, gna_list: List[GNAEntry]) -> GNAEntry | None:
    """Return the GNA for a given short name, or None if not found."""
    for entry in gna_list:
        if entry.get("short_name") == short_name:
            return entry
    return None


def get_gna_id_by_short_name(
    short_name: str, gna_list: List[GNAEntry]
) -> Optional[int]:
    """Return the GNA ID for a given short name, or None if not found."""
    if entry := get_gna_by_short_name(short_name, gna_list):
        return entry.get("id")
    return None
