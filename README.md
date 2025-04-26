# GCVE: Global CVE Allocation System

The [Global CVE (GCVE) allocation system](https://gcve.eu) is a new, decentralized approach to vulnerability identification and numbering, designed to improve flexibility, scalability, and autonomy for participating entities.

While remaining compatible with the traditional CVE system, GCVE introduces GCVE Numbering Authorities (GNAs). GNAs are independent entities that can allocate identifiers without relying on a centralised block distribution system or rigid policy enforcement.

This format is already used in [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup).  
See an example [here](https://vulnerability.circl.lu/product/651684fd-f2b4-45ac-96d0-e3e484af6113).


## Examples of usage

### As a command line tool

First install the gcve client:

```bash
python -m pip install --user pipx
python -m pipx ensurepath

pipx install gcve
  installed package gcve 0.4.3, installed using Python 3.13.0
  These apps are now globally available
    - gcve
done! ✨ 🌟 ✨
```

### Pulling the registry locally

```bash
$ gcve registry --pull
Pulling from registry...
Downloaded updated https://gcve.eu/dist/key/public.pem to data/public.pem
Downloaded updated https://gcve.eu/dist/gcve.json.sigsha512 to data/gcve.json.sigsha512
Downloaded updated https://gcve.eu/dist/gcve.json to data/gcve.json
Integrity check passed successfully.
```

### Searching the registry

```bash
$ gcve registry --find DFN-CERT
{
  "id": 680,
  "short_name": "DFN-CERT",
  "full_name": "DFN-CERT Services GmbH",
  "gcve_url": "https://adv-archiv.dfn-cert.de/"
}
```

Listing available commands:

```bash
$ gcve --help
usage: gcve [-h] {registry} ...

A Python client for the Global CVE Allocation System.

positional arguments:
  {registry}
    registry  Registry operations

options:
  -h, --help  show this help message and exit
```


### As a library

#### Verifying the integrity of your local GNA directory copy

```python
download_public_key_if_changed()
download_directory_signature_if_changed()
download_gcve_json_if_changed()

# Verify the integrity of the directory
if integrity := verify_gcve_integrity():
    # Load the GCVE directory
    gcve_data: List[GNAEntry] = load_gcve_json()
```

#### Generating new GCVE-1 entries (CIRCL namespace)

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



## Contact

https://www.circl.lu


## License

[GCVE](https://github.com/gcve-eu/gcve) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)


Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (c) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme
