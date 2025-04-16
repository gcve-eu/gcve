# GCVE: Global CVE Allocation System

The [Global CVE (GCVE) allocation system](https://gcve.eu) is a new, decentralized approach to vulnerability identification and numbering, designed to improve flexibility, scalability, and autonomy for participating entities.

While remaining compatible with the traditional CVE system, GCVE introduces GCVE Numbering Authorities (GNAs). GNAs are independent entities that can allocate identifiers without relying on a centralised block distribution system or rigid policy enforcement.

This format is already used in [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup).  
See an example [here](https://vulnerability.circl.lu/product/651684fd-f2b4-45ac-96d0-e3e484af6113).


## Example of usage

Generating new GCVE-1 entries (CIRCL namespace) while preventing collisions with official CVE entries (GCVE-0):

```python
from gcve import gcve_generator, get_gna_id_by_short_name, to_gcve_id
from gcve.gna import GNAEntry
from gcve.utils import download_gcve_json_if_changed, load_gcve_json

# Retrieve the JSON Directory file available at GCVE.eu if it has changed
updated: bool = download_gcve_json_if_changed()
# Initializes the GNA entries
gcve_data: List[GNAEntry] = load_gcve_json()

# If "CIRCL" found in the registry
if CIRCL_GNA_ID := get_gna_id_by_short_name("CIRCL", gcve_data):
    # Existing GCVE-O
    existing_gcves = {to_gcve_id(cve) for cve in vulnerabilitylookup.get_all_ids()}

    generator = gcve_generator(existing_gcves, CIRCL_GNA_ID)
    for _ in range(5):
        print(next(generator))
```


### Upgrading GCVE-1 to GCVE-0

If a GCVE-1 ID like GCVE-1-2025-0005 later matches a new official CVE like CVE-2025-0005, we just remap it using:

```python
from gcve import to_gcve_id
if "CVE-2025-0005" in known_cves:
    upgraded = to_gcve_id("CVE-2025-0005")
```

## Contact

https://www.circl.lu


## License

[GCVE](https://github.com/gcve-eu/gcve) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)
