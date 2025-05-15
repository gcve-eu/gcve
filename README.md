# A Python client for the Global CVE Allocation System

The [Global CVE (GCVE) allocation system](https://gcve.eu) is a new, decentralized
approach to vulnerability identification and numbering, designed to improve flexibility,
scalability, and autonomy for participating entities.

This client can be integrated into software such as
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup)
to provide core GCVE functionalities by adhering to the
[Best Current Practices](https://gcve.eu/bcp/).  
It can also be used as a standalone command-line tool.


## Examples of usage

### As a command line tool

First install the gcve client:

```bash
$ python -m pip install --user pipx
$ python -m pipx ensurepath

$ pipx install gcve
  installed package gcve 0.9.0, installed using Python 3.13.0
  These apps are now globally available
    - gcve
done! ✨ 🌟 ✨
```

#### Pulling the registry locally

```bash
$ gcve registry --pull
Pulling from registry...
Downloaded updated https://gcve.eu/dist/key/public.pem to .gcve/registry/public.pem
Downloaded updated https://gcve.eu/dist/gcve.json.sigsha512 to .gcve/registry/gcve.json.sigsha512
Downloaded updated https://gcve.eu/dist/gcve.json to .gcve/registry/gcve.json
Integrity check passed successfully.

```

#### Retrieving a GNA

Note: This operation is case sensitive.

```bash
$ gcve registry --get CIRCL
{
  "id": 1,
  "short_name": "CIRCL",
  "cpe_vendor_name": "circl",
  "full_name": "Computer Incident Response Center Luxembourg",
  "gcve_url": "https://vulnerability.circl.lu/",
  "gcve_api": "https://vulnerability.circl.lu/api/",
  "gcve_dump": "https://vulnerability.circl.lu/dumps/",
  "gcve_allocation": "https://vulnerability.circl.lu/",
  "gcve_sync_api": "https://vulnerability.circl.lu/"
}

$ gcve registry --get CIRCL | jq .id
1
```

#### Searching the Registry

Note: Search operations are case insensitive.

```bash
$ gcve registry --find cert
[
  {
    "id": 106,
    "full_name": "National Cyber Security Centre SK-CERT",
    "short_name": "SK-CERT",
    "gcve_url": "https://www.sk-cert.sk/"
  },
  {
    "id": 680,
    "short_name": "DFN-CERT",
    "full_name": "DFN-CERT Services GmbH",
    "gcve_url": "https://adv-archiv.dfn-cert.de/"
  }
]
```


### As a library

#### Verifying the integrity of your local GNA directory copy

```python
Python 3.13.0 (main, Oct 10 2024, 07:28:38) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from typing import List
... from gcve.gna import GNAEntry
... from gcve.utils import (
...     download_public_key_if_changed,
...     download_directory_signature_if_changed,
...     download_gcve_json_if_changed,
...     verify_gcve_integrity,
...     load_gcve_json,
... )
... 
>>> download_public_key_if_changed()
No changes — using cached .gcve/registry/public.pem.
False
>>> download_directory_signature_if_changed()
No changes — using cached .gcve/registry/gcve.json.sigsha512.
False
>>> download_gcve_json_if_changed()
No changes — using cached .gcve/registry/gcve.json.
False
>>> if verify_gcve_integrity():
...     gcve_data: List[GNAEntry] = load_gcve_json()
...     
>>> 
```

#### Generating new GCVE entries

Example with GCVE-1 entries (CIRCL namespace):

```python
from typing import List
from gcve.gna import GNAEntry
from gcve import gcve_generator, get_gna_id_by_short_name, to_gcve_id
from gcve.gna import GNAEntry
from gcve.utils import download_gcve_json_if_changed, load_gcve_json

# Retrieve the JSON Directory file available at GCVE.eu if it has changed
download_gcve_json_if_changed()
# Initializes the GNA entries
gcve_data = load_gcve_json()

# If "CIRCL" found in the registry
if CIRCL_GNA_ID := get_gna_id_by_short_name("CIRCL", gcve_data):
    # Existing GCVE-O
    existing_gcves = {to_gcve_id(cve) for cve in vulnerabilitylookup.get_all_ids()}

    generator = gcve_generator(existing_gcves, CIRCL_GNA_ID)
    for _ in range(5):
        print(next(generator))
```


## License

[GCVE](https://github.com/gcve-eu/gcve) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html).


- Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
- Copyright (c) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme


## Contact

~~~
Att: GCVE.EU
CIRCL - Computer Incident Response Center Luxembourg
c/o "Luxembourg House of Cybersecurity" g.i.e.
122, rue Adolphe Fischer
L-1521 Luxembourg
Grand-Duchy of Luxembourg
~~~
