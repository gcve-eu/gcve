# Changelog


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
