# Changelog


## Release 0.14.0 (2026-11-14)

- Added new `lookup` subcommand to retrieve a vulnerability record by its
  GCVE identifier (e.g. `gcve lookup GCVE-115-2026-00010`). The local
  registry is used to find where the record is published: the dump of the
  GNA (`gcve_dump`), then its pull API (`gcve_pull_api`), then GNA-1 which
  pulls from other GNAs. The source which answered is displayed. The
  `--via` option queries another GNA acting as aggregator.
- Added the `-v`/`--verbose` option to the `lookup` subcommand to display
  the resolution of the identifier and the requests made. The steps are
  logged with the `gcve.lookup` logger when used as a library.
- The `lookup` subcommand also accepts a CVE identifier, looked up as its
  GCVE-0 form (e.g. `gcve lookup CVE-2025-53700`). The other identifiers
  carried by the record found are displayed as related: the CVE of a
  vulnerability published by a GNA, or the GCVE identifier of the GNA for
  a CVE. They are available with `related_ids()` from the library API.
- Added the `--follow` option to the `lookup` subcommand to display the
  record of the related identifier instead, e.g. the record published by
  the GNA for a CVE.
- Added the `--pretty` option to the `lookup` subcommand to display a
  summary of the record (title, dates, severity, weaknesses, affected
  products, references, credits) instead of the JSON. It requires rich,
  available with the new `pretty` extra (`pip install 'gcve[pretty]'`).
- Added the new `gcve.summary` module, with `summarize_record()`,
  `detect_record_format()` and `VulnerabilitySummary` available from the
  library API. A summary is independent of the format of the record. Only
  the CVE Record Format is summarized for now.
- Added the new `gcve.lookup` module, with `lookup_gcve()` and
  `LookupResult` available from the library API.
- Dumps are cached in `.gcve/dumps/` and only downloaded when they changed.
- Fixed the caching of the `ETag` and `Last-Modified` headers, which were
  ignored when the server sent them in lowercase.
- A file removed from the local cache is now downloaded again, even if its
  cached headers are still present.
- Updated README.md with examples for the lookup functionality.


## Release 0.13.0 (2026-08-17)

- Added new `cna` subcommand to pull, list, and search the CNA partners of
  the CVE Program (https://gcve.eu/dist/cna_partners.json).
- Added `load_cna_partners()` and `update_cna_partners()` functions to the
  library API, along with the new `gcve.cna` module providing the
  `CNAPartner` type and lookup helpers.
- Updated README.md with examples for the CNA partners functionality.


## Release 0.12.2 (2026-08-17)

- Updated dependencies. Notably, cryptography has been upgraded
  from 48.0.1 to 50.0.0.


## Release 0.12.1 (2026-07-15)

- Updated dependencies. Notably, cryptography has been upgraded
  from 44.0.3 to 48.0.1.


## Release 0.12.0 (2026-01-31)

- Added new `references` subcommand to pull and list references from gcve.eu.
- Added `load_references()` and `update_references()` functions to the library API.
- Added CLAUDE.md documentation file for Claude Code guidance.
- Updated README.md with examples for references functionality.


## Release 0.11.3 (2025-07-17)

- Updated the GNAEntry type with the new gcve_pull_api attribute.


## Release 0.11.2 (2025-06-11)

- Fixed an issue when loading the ``__version__`` variable.


## Release 0.11.1 (2025-06-11)

- Replace default requests user-agent with official GCVE user-agent.
- Updated dependencies.


## Release 0.11.0 (2025-05-30)

- Added a new function to get a GNA by identifier.


## Release 0.10.2 (2025-05-19)

- Added missing py.typed file.


- ## Release 0.10.1 (2025-05-19)

- Added py.typed file in the package.


## Release 0.10.0 (2025-05-19)

- Refactored core part of the library.


## Release 0.9.0 (2025-05-15)

- Improved handling of the local GNA registry location.
  Functions that fetch updates from the GNA directory now
  accept a configurable base path, which can also be set via the command line.


## Release 0.8.3 (2025-05-05)

- gcve0_to_cve() is now case-insensitive.


## Release 0.8.2 (2025-04-30)

- The main gcve script is now under the root gcve module.


## Release 0.8.1 (2025-04-30)

- Fix definition of GNAEntry for Python 3.10.


## Release 0.8.0 (2025-04-30)

- Added a --list command to display the current registry entries.
- Updated GNAEntry for full compatibility with Python 3.10.
- Introduced gcve0_to_cve() function to convert GCVE-0 identifiers to CVE IDs.


## Release 0.7.0 (2025-04-28)

- Improved the definition of a GNAEntry.
- Improved typing and added a Mypy workflow.
- Improved documentation.


## Release 0.6.0 (2025-04-28)

- Updated GNAEntry type with new gcve_sync_api attribute.
- Added find_gna_by_short_name function.
- Various improvements to the cli.


## Release 0.5.0 (2025-04-27)

- Added a function and a command to search the registry.


## Release 0.4.4 (2025-04-27)

- Improved the structure of the project.
- Added new ``version`` argument to the command line.


## Release 0.4.0 (2025-04-25)

- Added a function to pull the SHA 512 signature from gcve.eu.
- Added a function to pull the GCVE public key from gcve.eu.
- Added a function to check the integrity of the local copy of the registry.
- Added a command line tool in order to pull the registry.


## Release 0.3.0 (2025-04-16)

- Retrieve the JSON Directory file available at GCVE.eu if it has changed.
- Added a function to find a GNA ID with its shortname.
- Added definition of a GNAEntry.


## Release 0.2.0 (2025-04-16)

Updated documentation.


## Release 0.1.0 (2025-04-16)

Initial release which is used in
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup).
