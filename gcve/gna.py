from typing import TypedDict


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
