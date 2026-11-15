"""Summary of a vulnerability record, independent of its format.

Records published by the GNAs are mostly in the CVE Record Format, but other
formats (OSV, CSAF, etc.) are possible. A record is summarized in two steps:
its format is detected, then an extractor dedicated to this format fills a
:class:`VulnerabilitySummary`. Supporting a new format only requires a new
extractor, registered in ``EXTRACTORS``.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

Record = Dict[str, Any]

FORMAT_CVE = "cve"
FORMAT_OSV = "osv"  # also used for the GitHub Security Advisories (GHSA)
FORMAT_CSAF = "csaf"

CVSS_KEY_REGEX = re.compile(r"cvssV\d+_\d+")


@dataclass
class Severity:
    scheme: str  # e.g. "CVSS 4.0"
    score: Optional[float] = None
    rating: Optional[str] = None  # e.g. "HIGH"
    vector: Optional[str] = None


@dataclass
class Affected:
    vendor: Optional[str] = None
    product: Optional[str] = None
    versions: List[str] = field(default_factory=list)


@dataclass
class VulnerabilitySummary:
    """The main information of a vulnerability record."""

    format: str
    id: str
    aliases: List[str] = field(default_factory=list)
    title: Optional[str] = None
    description: Optional[str] = None
    state: Optional[str] = None
    published: Optional[str] = None
    updated: Optional[str] = None
    assigner: Optional[str] = None
    severities: List[Severity] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    affected: List[Affected] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    credits: List[str] = field(default_factory=list)


def _text(value: Any) -> Optional[str]:
    """Return a string without control characters, or None. Records are not
    trusted: escape sequences must not reach the terminal."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        char
        for char in value
        if char in "\n\t" or unicodedata.category(char) not in ("Cc", "Cf")
    ).strip()
    return cleaned or None


def _named(value: Any) -> Optional[str]:
    """Same as _text, without the "n/a" placeholder of the CVE records."""
    text = _text(value)
    return None if text and text.lower() == "n/a" else text


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _unique(values: List[Optional[str]], exclude: str = "") -> List[str]:
    """Remove the empty values and the duplicates (case-insensitive)."""
    seen = {exclude.upper()}
    result: List[str] = []
    for value in values:
        if value and value.upper() not in seen:
            seen.add(value.upper())
            result.append(value)
    return result


def detect_record_format(record: Any) -> Optional[str]:
    """Return the format of a record (cve, osv, csaf), or None if unknown."""
    if not isinstance(record, dict):
        return None
    if record.get("dataType") == "CVE_RECORD" or (
        "cveMetadata" in record and "containers" in record
    ):
        return FORMAT_CVE
    if "csaf_version" in _dict(record.get("document")):
        return FORMAT_CSAF
    if "id" in record and ("schema_version" in record or "modified" in record):
        return FORMAT_OSV
    return None


def _cve_version(version: Dict[str, Any]) -> Optional[str]:
    """Describe an entry of the versions of an affected product."""
    start = _named(version.get("version"))
    if start in ("0", "*", "unspecified"):
        start = None
    less_than = _text(version.get("lessThan"))
    less_than_or_equal = _text(version.get("lessThanOrEqual"))
    parts: List[str] = []
    if less_than or less_than_or_equal:
        if start:
            parts.append(f">= {start}")
        parts.append(f"< {less_than}" if less_than else f"<= {less_than_or_equal}")
    elif start:
        parts.append(start)
    text = ", ".join(parts)
    status = _text(version.get("status"))
    if status and status != "affected":
        text = f"{text} ({status})" if text else status
    return text or None


def summarize_cve(record: Record) -> VulnerabilitySummary:
    """Summarize a record in the CVE Record Format (GCVE-BCP-05)."""
    metadata = _dict(record.get("cveMetadata"))
    cna = _dict(_dict(record.get("containers")).get("cna"))

    ids = _unique(
        [_text(metadata.get("vulnId")), _text(metadata.get("cveId"))]
        + [_text(item.get("vulnId")) for item in _dicts(cna.get("x_gcve"))]
    )

    descriptions = _dicts(cna.get("descriptions"))
    english = [
        item for item in descriptions if str(item.get("lang", "")).startswith("en")
    ]
    description = next(
        (text for item in english + descriptions if (text := _text(item.get("value")))),
        None,
    )

    title = _text(cna.get("title"))

    severities: List[Severity] = []
    for metric in _dicts(cna.get("metrics")):
        for key, cvss in metric.items():
            # The key is not trusted either: only cvssV3_1, cvssV4_0, etc.
            if not CVSS_KEY_REGEX.fullmatch(key) or not isinstance(cvss, dict):
                continue
            score = cvss.get("baseScore")
            version = _text(cvss.get("version")) or key[5:].replace("_", ".")
            severity = Severity(
                scheme=f"CVSS {version}",
                score=(
                    float(score)
                    if isinstance(score, (int, float)) and not isinstance(score, bool)
                    else None
                ),
                rating=_text(cvss.get("baseSeverity")),
                vector=_text(cvss.get("vectorString")),
            )
            if severity.score is not None or severity.rating or severity.vector:
                severities.append(severity)

    weaknesses: List[Optional[str]] = []
    for problem_type in _dicts(cna.get("problemTypes")):
        for item in _dicts(problem_type.get("descriptions")):
            cwe_id = _text(item.get("cweId"))
            text = _named(item.get("description"))
            if cwe_id and text and not text.upper().startswith(cwe_id.upper()):
                text = f"{cwe_id}: {text}"
            weaknesses.append(text or cwe_id)

    affected = [
        Affected(
            vendor=_named(item.get("vendor")),
            product=_named(item.get("product")) or _named(item.get("packageName")),
            versions=_unique(
                [_cve_version(version) for version in _dicts(item.get("versions"))]
            ),
        )
        for item in _dicts(cna.get("affected"))
    ]
    affected = [
        item for item in affected if item.vendor or item.product or item.versions
    ]

    credits: List[Optional[str]] = []
    for item in _dicts(cna.get("credits")):
        name = _text(item.get("value"))
        credit_type = _text(item.get("type"))
        credits.append(f"{name} ({credit_type})" if name and credit_type else name)

    return VulnerabilitySummary(
        format=FORMAT_CVE,
        id=ids[0] if ids else "",
        aliases=ids[1:],
        title=title,
        # The title is sometimes a copy of the description.
        description=description if description != title else None,
        state=_text(metadata.get("state")),
        published=_text(metadata.get("datePublished")),
        updated=_text(metadata.get("dateUpdated")),
        assigner=_text(metadata.get("assignerShortName"))
        or _text(_dict(cna.get("providerMetadata")).get("shortName")),
        severities=severities,
        weaknesses=_unique(weaknesses),
        affected=affected,
        references=_unique(
            [_text(item.get("url")) for item in _dicts(cna.get("references"))]
        ),
        credits=_unique(credits),
    )


# One extractor per supported format.
EXTRACTORS: Dict[str, Callable[[Record], VulnerabilitySummary]] = {
    FORMAT_CVE: summarize_cve,
}


def summarize_record(record: Any) -> Optional[VulnerabilitySummary]:
    """Summarize a vulnerability record.
    Returns None if the format of the record is unknown or not supported yet."""
    extractor = EXTRACTORS.get(detect_record_format(record) or "")
    return extractor(record) if extractor else None
