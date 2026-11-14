"""Look up a vulnerability record by its GCVE identifier.

BCP-03 (https://gcve.eu/bcp/gcve-bcp-03/) defines no endpoint to fetch a single
record, so a lookup goes through the publication channels of the GNA which
allocated the identifier, then falls back on another GNA known to pull from it:

1. the static dump of the GNA (``gcve_dump``, cached locally);
2. the pull API of the GNA (``gcve_pull_api`` + ``/api/gcve/publication``);
3. the per-identifier endpoint of an aggregator GNA
   (``/api/vulnerability/<id>``, Vulnerability-Lookup API). By default GNA-1.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterator, List, NamedTuple, Optional

import requests

from gcve.gna import GNAEntry, get_gna, get_gna_by_short_name
from gcve.main import validate_gcve_id
from gcve.registry import BASE_PATH, load_registry
from gcve.utils import USER_AGENT, fetch_file

DUMPS_PATH: Path = Path("dumps")
DEFAULT_AGGREGATOR_GNA_ID = 1
REQUEST_TIMEOUT = 30
PULL_API_PER_PAGE = 100  # maximum allowed by BCP-03
PULL_API_MAX_PAGES = 500

Record = Dict[str, Any]

# The steps of a lookup are logged at the INFO level.
logger = logging.getLogger(__name__)


class LookupResult(NamedTuple):
    """A vulnerability record, with the place it was found."""

    record: Record
    source: str  # human-readable description of the source which answered
    url: str


def _gna_label(gna: GNAEntry) -> str:
    return f"GNA-{gna.get('id')} ({gna.get('short_name', '')})"


def _base_url(gna: GNAEntry, field: str) -> Optional[str]:
    """Return the URL stored in a field of a GNA entry, without trailing slash.
    Only HTTPS URLs are accepted."""
    value = gna.get(field)
    if not isinstance(value, str) or not value.lower().startswith("https://"):
        return None
    return value.rstrip("/")


def _pull_api_base(gna: GNAEntry) -> Optional[str]:
    """Base URL of the pull API of a GNA. A trailing /api is dropped since the
    endpoints defined in BCP-03 already start with /api."""
    base = _base_url(gna, "gcve_pull_api")
    if base and base.endswith("/api"):
        base = base[: -len("/api")]
    return base


def _record_ids(record: Record) -> Iterator[str]:
    """Yield the GCVE identifiers carried by a record."""
    metadata = record.get("cveMetadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("vulnId"), str):
        yield metadata["vulnId"]
    containers = record.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    x_gcve = cna.get("x_gcve") if isinstance(cna, dict) else None
    if isinstance(x_gcve, list):
        for item in x_gcve:
            if isinstance(item, dict) and isinstance(item.get("vulnId"), str):
                yield item["vulnId"]


def _matches(record: Any, gcve_id: str) -> bool:
    return isinstance(record, dict) and any(
        vuln_id.upper() == gcve_id for vuln_id in _record_ids(record)
    )


def dump_urls(gna: GNAEntry) -> List[str]:
    """Return the candidate URLs for the NDJSON dump of a GNA.

    ``gcve_dump`` is either the dump itself or the directory containing it. The
    dump may also be published next to the pull API (/dumps/gna-<id>.ndjson)."""
    file_name = f"gna-{gna.get('id')}.ndjson"
    urls: List[str] = []
    raw_dump = gna.get("gcve_dump", "")
    if dump := _base_url(gna, "gcve_dump"):
        if dump.endswith(".ndjson"):
            urls.append(dump)
        elif raw_dump.endswith("/"):
            urls.append(f"{dump}/{file_name}")
    if pull_api := _pull_api_base(gna):
        url = f"{pull_api}/dumps/{file_name}"
        if url not in urls:
            urls.append(url)
    return urls


def _search_dump(path: Path, gcve_id: str) -> Optional[Record]:
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if _matches(record, gcve_id):
                return record
    return None


def lookup_in_dump(
    gcve_id: str, gna: GNAEntry, base_path: Path = BASE_PATH
) -> Optional[LookupResult]:
    """Look for a record in the dump of the GNA. The dump is cached locally and
    only downloaded again when it has changed on the server."""
    destination = base_path / DUMPS_PATH / f"gna-{gna.get('id')}.ndjson"
    urls = dump_urls(gna)
    if not urls:
        logger.info("Dump: no usable dump URL for %s.", _gna_label(gna))
    for url in urls:
        try:
            updated = fetch_file(url, destination, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            logger.info("Dump: GET %s -> failed (%s)", url, e)
            continue
        logger.info(
            "Dump: GET %s -> %s",
            url,
            (
                f"downloaded to {destination.as_posix()}"
                if updated
                else f"not modified, using cached {destination.as_posix()}"
            ),
        )
        if record := _search_dump(destination, gcve_id):
            return LookupResult(record, f"dump of {_gna_label(gna)}", url)
        logger.info("Dump: %s is not in the dump.", gcve_id)
    return None


def lookup_in_pull_api(gcve_id: str, gna: GNAEntry) -> Optional[LookupResult]:
    """Look for a record by paging through the pull API of the GNA."""
    if not (base := _pull_api_base(gna)):
        logger.info("Pull API: no usable pull API URL for %s.", _gna_label(gna))
        return None
    url = f"{base}/api/gcve/publication"
    previous_page: Any = None
    for page in range(1, PULL_API_MAX_PAGES + 1):
        try:
            response = requests.get(
                url,
                params={"per_page": PULL_API_PER_PAGE, "page": page},
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            records = response.json()
        except (requests.RequestException, ValueError) as e:
            logger.info("Pull API: GET %s (page %d) -> failed (%s)", url, page, e)
            return None
        if not isinstance(records, list):
            logger.info("Pull API: GET %s (page %d) -> not a list", url, page)
            return None
        logger.info(
            "Pull API: GET %s (page %d) -> %d record(s)", url, page, len(records)
        )
        # Stop at the end, or if the server ignores the pagination.
        if not records or records == previous_page:
            logger.info("Pull API: %s is not in the publications.", gcve_id)
            return None
        for record in records:
            if _matches(record, gcve_id):
                return LookupResult(record, f"pull API of {_gna_label(gna)}", url)
        previous_page = records
    return None


def lookup_in_aggregator(gcve_id: str, aggregator: GNAEntry) -> Optional[LookupResult]:
    """Look for a record on a GNA which pulls from other GNAs, with the
    per-identifier endpoint of the Vulnerability-Lookup API."""
    if not (base := _pull_api_base(aggregator)):
        logger.info(
            "Aggregator: no usable pull API URL for %s.", _gna_label(aggregator)
        )
        return None
    url = f"{base}/api/vulnerability/{gcve_id}"
    try:
        response = requests.get(
            url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        record = response.json()
    except (requests.RequestException, ValueError) as e:
        logger.info("Aggregator: GET %s -> failed (%s)", url, e)
        return None
    # An unknown identifier is answered with an empty object.
    if not isinstance(record, dict) or not record:
        logger.info("Aggregator: GET %s -> no record", url)
        return None
    logger.info("Aggregator: GET %s -> found", url)
    return LookupResult(record, f"{_gna_label(aggregator)}, as aggregator", url)


def resolve_gna(gna: str | int, registry: List[GNAEntry]) -> GNAEntry:
    """Return a GNA from its identifier or its short name.
    Raises LookupError if it is not in the registry."""
    entry = (
        get_gna(int(gna), registry)
        if str(gna).isdigit()
        else get_gna_by_short_name(str(gna), registry)
    )
    if entry is None:
        raise LookupError(f"GNA {gna} not found in the registry.")
    return entry


def lookup_gcve(
    gcve_id: str, base_path: Path = BASE_PATH, via: Optional[str | int] = None
) -> Optional[LookupResult]:
    """Look up a vulnerability record by its GCVE identifier.

    The GNA which allocated the identifier is queried first (dump, then pull
    API), then GNA-1 as aggregator. GCVE-0 identifiers (CVE) are only looked up
    on the aggregator. With ``via`` (identifier or short name of a GNA), only
    this GNA is queried, as aggregator.

    Returns None if the record is not found. Raises ValueError if the identifier
    is invalid and LookupError if a GNA is not in the local registry."""
    gcve_id = gcve_id.strip().upper()
    if not (parsed := validate_gcve_id(gcve_id)):
        raise ValueError(f"Invalid GCVE ID format: {gcve_id}")
    gna_id, year, number = parsed
    logger.info(
        "Identifier: %s (GNA %d, year %d, number %d)", gcve_id, gna_id, year, number
    )
    registry = load_registry(base_path)

    if via is not None:
        aggregator = resolve_gna(via, registry)
        logger.info(
            "Registry: only querying %s, as aggregator.", _gna_label(aggregator)
        )
        return lookup_in_aggregator(gcve_id, aggregator)

    if gna_id == 0:
        logger.info("Registry: GNA 0 is the CVE Program, querying the aggregator.")
    else:
        gna = resolve_gna(gna_id, registry)
        logger.info(
            "Registry: %s, gcve_dump=%s, gcve_pull_api=%s",
            _gna_label(gna),
            gna.get("gcve_dump"),
            gna.get("gcve_pull_api"),
        )
        if result := lookup_in_dump(gcve_id, gna, base_path) or lookup_in_pull_api(
            gcve_id, gna
        ):
            return result

    if default_aggregator := get_gna(DEFAULT_AGGREGATOR_GNA_ID, registry):
        return lookup_in_aggregator(gcve_id, default_aggregator)
    return None
