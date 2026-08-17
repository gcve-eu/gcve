from typing import Any, Dict, List, Optional, TypedDict


class RootInfo(TypedDict):
    """Root or Top-Level Root organization of a CNA partner."""

    shortName: str
    organizationName: str


class CNAPartnerMetadata(TypedDict, total=False):
    """Metadata of a CNA partner as published on
    https://www.cve.org/PartnerInformation/ListofPartners"""

    cna_id: str
    short_name: str
    contact: List[Dict[str, Any]]
    disclosure_policy: List[Dict[str, str]]
    security_advisories: Dict[str, Any]
    resources: List[Any]
    is_root: bool
    root: RootInfo
    top_level_root: RootInfo
    roles: List[Dict[str, str]]
    organization_types: List[str]
    scope_html: str
    source_page: str
    partner_page: str


class CNAPartner(TypedDict):
    """Define a CNA partner entry of the CVE Program:
    https://gcve.eu/dist/cna_partners.json"""

    partner: str
    scope: str
    program_role: str
    organization_type: str
    country: str
    metadata: CNAPartnerMetadata


def find_cna_by_name(name: str, partners: List[CNAPartner]) -> List[CNAPartner]:
    """Return the CNA partners whose name or short name contains the given
    string (case insensitive), or an empty list if nothing found."""
    return [
        entry
        for entry in partners
        if name.lower() in entry.get("partner", "").lower()
        or name.lower() in entry.get("metadata", {}).get("short_name", "").lower()
    ]


def get_cna_by_short_name(
    short_name: str, partners: List[CNAPartner]
) -> Optional[CNAPartner]:
    """Return the CNA partner for a given short name, or None if not found."""
    for entry in partners:
        if entry.get("metadata", {}).get("short_name") == short_name:
            return entry
    return None


def get_cna_by_country(country: str, partners: List[CNAPartner]) -> List[CNAPartner]:
    """Return the CNA partners for a given country (case insensitive),
    or an empty list if nothing found."""
    return [
        entry
        for entry in partners
        if entry.get("country", "").lower() == country.lower()
    ]
