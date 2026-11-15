# A Python client for the Global CVE Allocation System

The [Global CVE (GCVE) allocation system](https://gcve.eu) is a new, decentralized
approach to vulnerability identification and numbering, designed to improve flexibility,
scalability, and autonomy for participating entities.

This client can be integrated into software such as
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup)
to provide core GCVE functionalities by adhering to the
[Best Current Practices](https://gcve.eu/bcp/).
It can also be used as a standalone command-line tool.

- [Installation](#installation)
- [Command line](#command-line)
  - [Registry of the GNAs](#registry-of-the-gnas)
  - [Looking up a vulnerability](#looking-up-a-vulnerability)
  - [References](#references)
  - [CNA partners](#cna-partners)
- [Library](#library)
- [License](#license)
- [Contact](#contact)


## Installation

```bash
$ python -m pip install --user pipx
$ python -m pipx ensurepath

$ pipx install gcve
```

The `--pretty` option of the `lookup` command requires
[rich](https://github.com/Textualize/rich), available with the `pretty` extra:

```bash
$ pipx install 'gcve[pretty]'
```


## Command line

| Command           | Purpose                                                      |
|-------------------|--------------------------------------------------------------|
| `gcve registry`   | Pull, list and search the registry of the GNAs.              |
| `gcve lookup`     | Look up a vulnerability by its GCVE or CVE identifier.       |
| `gcve references` | Pull and list the references (e.g. KEV catalogs).            |
| `gcve cna`        | Pull, list and search the CNA partners of the CVE Program.   |

The files are stored in the `.gcve` directory of the current directory. Use
`--path` to choose another location. The commands write the data on the
standard output, as JSON, so it can be piped to a tool like `jq`.


### Registry of the GNAs

#### Pulling the registry

The registry is downloaded with its signature, then its integrity is verified.
Pull it before using the other operations.

```bash
$ gcve registry --pull
Pulling from registry…
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
  "gcve_pull_api": "https://vulnerability.circl.lu/"
}

$ gcve registry --get CIRCL | jq .id
1
```

#### Searching the registry

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

#### Listing the registry

```bash
$ gcve registry --list | jq length
47

$ gcve registry --list | jq -r '.[] | select(.gcve_pull_api) | "\(.id) \(.short_name)"'
1 CIRCL
115 Adrian Dacka
125 Postiz
128 bcsec
1337 AHA!
```


### Looking up a vulnerability

Look up a vulnerability record by its GCVE or CVE identifier. The local
registry is used to find where the record is published, so it must have been
pulled before (`gcve registry --pull`).

```bash
$ gcve lookup GCVE-115-2026-00010
Source: dump of GNA-115 (Adrian Dacka) - https://gna115.pages.dev/dumps/gna-115.ndjson
{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.1",
  ...
}
```

The record is written on the standard output. The source which answered, and
the other messages, are written on the standard error output:

```bash
$ gcve lookup GCVE-115-2026-00010 | jq .containers.cna.title
Source: dump of GNA-115 (Adrian Dacka) - https://gna115.pages.dev/dumps/gna-115.ndjson
"Reflected Cross-Site Scripting (XSS) in e107 CMS"

$ gcve lookup GCVE-128-2026-0001 2> /dev/null | jq -r '.containers.cna.affected[] | "\(.vendor) \(.product)"'
N-able Mail Assure
```

The exit status is 1 when the record is not found.

| Option            | Purpose                                                              |
|-------------------|----------------------------------------------------------------------|
| `--follow`        | Display the record of the related identifier instead.                |
| `--pretty`        | Display a summary of the record instead of the JSON.                 |
| `--via GNA`       | Only query this GNA (identifier or short name), as aggregator.       |
| `-v`, `--verbose` | Display the resolution of the identifier and the requests made.      |
| `--path PATH`     | Path of the local registry (default: `.gcve`).                       |

#### Where the records come from

The sources are tried in this order:

1. the dump of the GNA which allocated the identifier (`gcve_dump`), cached in
   `.gcve/dumps/` and only downloaded again when it has changed;
2. the pull API of this GNA (`gcve_pull_api`);
3. GNA-1 (CIRCL), which pulls from other GNAs.

Use `-v` to see the resolution of the identifier and the requests made:

```bash
$ gcve lookup -v GCVE-1-2026-20325 > /dev/null
Identifier: GCVE-1-2026-20325 (GNA 1, year 2026, number 20325)
Registry: GNA-1 (CIRCL), gcve_dump=https://vulnerability.circl.lu/dumps/, gcve_pull_api=https://vulnerability.circl.lu/
Dump: GET https://vulnerability.circl.lu/dumps/gna-1.ndjson -> not modified, using cached .gcve/dumps/gna-1.ndjson
Dump: GCVE-1-2026-20325 is not in the dump.
Pull API: GET https://vulnerability.circl.lu/api/gcve/publication (page 1) -> 100 record(s)
Source: pull API of GNA-1 (CIRCL) - https://vulnerability.circl.lu/api/gcve/publication
```

Use `--via` to only query a GNA acting as aggregator, instead of the GNA which
allocated the identifier:

```bash
$ gcve lookup GCVE-115-2026-00010 --via CIRCL | jq .cveMetadata.vulnId
Source: GNA-1 (CIRCL), as aggregator - https://vulnerability.circl.lu/api/vulnerability/GCVE-115-2026-00010
"GCVE-115-2026-00010"
```

#### CVE identifiers

GNA 0 is the CVE Program: `CVE-2025-53700` is `GCVE-0-2025-53700`. Both forms
are accepted, and looked up on GNA-1.

```bash
$ gcve lookup CVE-2025-53700 > /dev/null
Source: GNA-1 (CIRCL), as aggregator - https://vulnerability.circl.lu/api/vulnerability/GCVE-0-2025-53700
```

#### Related identifiers

A vulnerability published by a GNA may also have a CVE. When the record found
refers to another identifier, it is displayed as related:

```bash
$ gcve lookup CVE-2026-128637 > /dev/null
Source: GNA-1 (CIRCL), as aggregator - https://vulnerability.circl.lu/api/vulnerability/GCVE-0-2026-128637
Related: GCVE-1-2026-20325

$ gcve lookup GCVE-1-2026-20325 > /dev/null
Source: pull API of GNA-1 (CIRCL) - https://vulnerability.circl.lu/api/gcve/publication
Related: CVE-2026-128637
```

Use `--follow` to display the record of the related identifier instead, for
example the record published by the GNA for a CVE:

```bash
$ gcve lookup --follow CVE-2026-128637 | jq .cveMetadata.vulnId
Source: GNA-1 (CIRCL), as aggregator - https://vulnerability.circl.lu/api/vulnerability/GCVE-0-2026-128637
Related: GCVE-1-2026-20325
Following: GCVE-1-2026-20325
Source: pull API of GNA-1 (CIRCL) - https://vulnerability.circl.lu/api/gcve/publication
Related: CVE-2026-128637
"gcve-1-2026-20325"
```

Only one identifier is followed. The link depends on the records: a CVE record
does not always refer to the GCVE identifier of the GNA.

#### Summary of a record

Use `--pretty` to display a summary of the record instead of the JSON
(requires the `pretty` extra, see [Installation](#installation)):

```bash
$ gcve lookup --pretty GCVE-1-2025-0001
Source: dump of GNA-1 (CIRCL) - https://vulnerability.circl.lu/dumps/gna-1.ndjson
╭─ GCVE-1-2025-0001 ────────────────────────────────────────────────────────────╮
│                                                                               │
│  Title       The absence of a password confirmation step when deactivating    │
│              an account allows a CSRF request to potentially initiate the     │
│              deactivation for an authenticated user.                          │
│  State       PUBLISHED                                                        │
│  Published   2025-05-27                                                       │
│  Updated     2025-05-30                                                       │
│  Severity    5.3 MEDIUM (CVSS 4.0)                                            │
│  Weakness    CWE-352 Cross-Site Request Forgery (CSRF)                        │
│  Affected    CIRCL Vulnerability-Lookup  <= 2.10.0                            │
│  Credits     Devansh Chauhan (finder)                                         │
│  ...                                                                          │
╰───────────────────────────────────────────────────────────────────────────────╯
```

Records in the CVE Record Format are summarized. A record in another format
is displayed as highlighted JSON.


### References

#### Pulling the references file

```bash
$ gcve references --pull
Pulling references…
Downloaded updated https://gcve.eu/dist/references.json to .gcve/references/references.json
References downloaded successfully.
```

#### Listing references

```bash
$ gcve references --list
{
  "kev": [
    {
      "uuid": "405284c2-e461-4670-8979-7fd2c9755a60",
      "short_name": "CISA KEV"
    },
    {
      "uuid": "1a89b78e-f703-45f3-bb86-59eb712668bd",
      "short_name": "CIRCL",
      "gcve_gna_id": 1
    },
    {
      "uuid": "cce329bf-df49-4c6e-a027-80be2e6483bd",
      "short_name": "EUVD KEV",
      "gcve_gna_id": 2
    }
  ]
}
```


### CNA partners

The list of CNA partners of the CVE Program, as published on
[cve.org](https://www.cve.org/PartnerInformation/ListofPartners) and mirrored
on [gcve.eu](https://gcve.eu/dist/cna_partners.json).

#### Pulling the CNA partners file

```bash
$ gcve cna --pull
Pulling CNA partners…
Downloaded updated https://gcve.eu/dist/cna_partners.json to .gcve/partners/cna_partners.json
CNA partners downloaded successfully.
```

#### Searching the CNA partners

Note: Search operations are case insensitive and match on the partner name
and short name. ``--get`` performs a case sensitive exact match on the short name.

```bash
$ gcve cna --get CIRCL | jq .country
"Luxembourg"

$ gcve cna --find microsoft | jq '.[].partner'
"Microsoft Corporation"
```


## Library

### Verifying the integrity of your local GNA directory copy

```python
>>> from typing import List
>>> from gcve.gna import GNAEntry
>>> from gcve.registry import (
...     update_registry_public_key,
...     update_registry_signature,
...     update_registry,
...     verify_registry_integrity,
...     load_registry,
... )
>>> update_registry_public_key()
No changes — using cached .gcve/registry/public.pem.
False
>>> update_registry_signature()
No changes — using cached .gcve/registry/gcve.json.sigsha512.
False
>>> update_registry()
No changes — using cached .gcve/registry/gcve.json.
False
>>> if verify_registry_integrity():
...     gcve_data: List[GNAEntry] = load_registry()
...
```

### Working with identifiers

```python
>>> from gcve import validate_gcve_id, to_gcve_id, gcve0_to_cve
>>> validate_gcve_id("GCVE-1-2025-00001")  # GNA ID, year, unique ID
(1, 2025, 1)
>>> to_gcve_id("CVE-2023-40224")
'GCVE-0-2023-40224'
>>> gcve0_to_cve("GCVE-0-2023-40224")
'CVE-2023-40224'
```

### Looking up a vulnerability

The registry must be available locally (see above). `lookup_gcve()` accepts a
GCVE or a CVE identifier and returns `None` when the record is not found.

```python
>>> from gcve import lookup_gcve, related_ids
>>> result = lookup_gcve("CVE-2026-128637")
>>> result.source
'GNA-1 (CIRCL), as aggregator'
>>> result.url
'https://vulnerability.circl.lu/api/vulnerability/GCVE-0-2026-128637'
>>> result.record["cveMetadata"]["cveId"]
'CVE-2026-128637'
>>> related_ids(result.record, "CVE-2026-128637")
['GCVE-1-2026-20325']
```

Use `via` to only query a GNA acting as aggregator:
`lookup_gcve("GCVE-115-2026-00010", via="CIRCL")`. The steps of a lookup are
logged at the `INFO` level with the `gcve.lookup` logger.

### Summarizing a vulnerability record

A summary is independent of the format of the record. `summarize_record()`
returns `None` when the format is not supported: only the CVE Record Format
is summarized for now.

```python
>>> from gcve import lookup_gcve, summarize_record
>>> result = lookup_gcve("GCVE-1-2025-0001")
>>> summary = summarize_record(result.record)
>>> summary.id
'GCVE-1-2025-0001'
>>> [(severity.scheme, severity.score, severity.rating) for severity in summary.severities]
[('CVSS 4.0', 5.3, 'MEDIUM')]
>>> summary.weaknesses
['CWE-352 Cross-Site Request Forgery (CSRF)']
>>> [(affected.vendor, affected.product, affected.versions) for affected in summary.affected]
[('CIRCL', 'Vulnerability-Lookup', ['<= 2.10.0'])]
```

### Generating new GCVE entries

Example with GCVE-1 entries (CIRCL namespace):

```python
from gcve import gcve_generator, get_gna_id_by_short_name, to_gcve_id
from gcve.registry import update_registry, load_registry

# Retrieve the JSON Directory file available at GCVE.eu if it has changed
update_registry()
# Initializes the GNA entries
gcve_data = load_registry()

# If "CIRCL" found in the registry
if CIRCL_GNA_ID := get_gna_id_by_short_name("CIRCL", gcve_data):
    # Existing GCVE-O
    existing_gcves = {to_gcve_id(cve) for cve in vulnerabilitylookup.get_all_ids()}

    generator = gcve_generator(existing_gcves, CIRCL_GNA_ID)
    for _ in range(5):
        print(next(generator))
```

### Loading references

```python
>>> from gcve.registry import update_references, load_references
>>>
>>> update_references()
Downloaded updated https://gcve.eu/dist/references.json to .gcve/references/references.json
True
>>> references = load_references()
>>> references['kev'][0]
{'uuid': '405284c2-e461-4670-8979-7fd2c9755a60', 'short_name': 'CISA KEV'}
```

### Loading the CNA partners

```python
>>> from gcve.registry import update_cna_partners, load_cna_partners
>>> from gcve.cna import get_cna_by_short_name
>>>
>>> update_cna_partners()
Downloaded updated https://gcve.eu/dist/cna_partners.json to .gcve/partners/cna_partners.json
True
>>> partners = load_cna_partners()
>>> get_cna_by_short_name("CIRCL", partners)["metadata"]["cna_id"]
'CNA-2026-0027'
```


## License

[GCVE](https://github.com/gcve-eu/gcve) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html).


- Copyright (c) 2025-2026 Computer Incident Response Center Luxembourg (CIRCL)
- Copyright (c) 2025-2026 Cédric Bonhomme - https://github.com/cedricbonhomme


## Contact

~~~
Att: GCVE.EU
CIRCL - Computer Incident Response Center Luxembourg
c/o "Luxembourg House of Cybersecurity" g.i.e.
122, rue Adolphe Fischer
L-1521 Luxembourg
Grand-Duchy of Luxembourg
~~~
