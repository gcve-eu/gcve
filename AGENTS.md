# AGENTS.md

Instructions for AI coding agents working on GCVE, whatever the tool.

<!-- Standard block: identical in every project. -->
## Rules for agents

The full policy on AI-assisted contributions is in [CONTRIBUTING.md](CONTRIBUTING.md).
For an agent, it means:

- Keep your changes minimal and within the scope of the task. Do not mix unrelated
  changes (reformatting, renaming, rewritten comments) into a fix.
- Verify what you change before you report it as done, and say what you could not
  verify.
- Leave the decision to commit, to push, and to open a pull request to the human
  you work with, after they have reviewed your changes.
- End each commit containing generated code with a `Co-Authored-By` trailer naming
  the model.
- Do not skip the pre-commit hooks, and do not add a dependency, without asking.
<!-- End of the standard block. -->

## Project overview

GCVE is a Python client for the Global CVE Allocation System (https://gcve.eu), a
decentralized approach to vulnerability identification and numbering. It is both a
command-line tool and a library, used by software such as Vulnerability-Lookup. It
works with GCVE identifiers, the registry of the GNAs (GCVE Numbering Authorities)
and the vulnerability records they publish.

## Commands

```bash
# Install the project, with the development tools and the optional extras.
# Without --all-extras, rich is missing and mypy fails on gcve/pretty.py.
poetry install --with dev --all-extras

# Type checking, as in the CI (configuration in mypy.ini, strict)
poetry run mypy .

# All the checks: pyupgrade, isort, black, flake8, pip-audit, etc.
poetry run pre-commit run --all-files

# Run the client from the source tree
poetry run gcve registry --pull
poetry run gcve lookup GCVE-1-2025-0001

# Build the package
poetry build
```

## Verifying a change

- There is no test suite. Verify a change by running the client: the commands need
  the network, and the registry pulled locally (`poetry run gcve registry --pull`).
- Use `poetry run gcve`. A bare `gcve` may be a released version installed with pipx,
  not the source tree.
- The examples of the README show real outputs: run a command before documenting its
  output.

## Conventions

- Python 3.11+, with type hints. mypy runs in strict mode.
- Formatting with black (default line length) and isort (black profile). flake8
  accepts lines up to 120 characters. Let the pre-commit hooks format the code.
- Commit messages: `new: [scope] …` for a feature, `chg: [scope] …` for a change,
  `fix: [scope] …` for a fix, with a body explaining why.
- Commits are signed with GPG: the human must be present to enter the passphrase.
- A user-visible change is described in CHANGELOG.md, under the entry of the release
  in preparation, and documented in README.md.
- The runtime dependencies are kept to a minimum (requests, cryptography). Anything
  else is an optional extra, like rich for `gcve lookup --pretty`.

## Architecture

One module per concern, in `gcve/`. Read the module for the details.

| Module        | Purpose                                                                |
|---------------|------------------------------------------------------------------------|
| `main.py`     | GCVE identifiers: validation, conversion from and to CVE, generation.  |
| `gna.py`      | Type of a GNA entry of the registry, and search functions.             |
| `cna.py`      | Type of a CNA partner of the CVE Program, and search functions.        |
| `registry.py` | Download, signature verification and loading of the files of gcve.eu.  |
| `utils.py`    | HTTP download with a local cache (ETag, Last-Modified).                |
| `lookup.py`   | Lookup of a vulnerability record by its GCVE or CVE identifier.        |
| `summary.py`  | Summary of a record, independent of its format.                        |
| `pretty.py`   | Display of a summary in a terminal, with rich.                         |
| `cli.py`      | Command-line interface: `registry`, `lookup`, `references`, `cna`.     |

The public API of the library is what `gcve/__init__.py` exports.

## Things to know

- **Identifiers.** The format is `GCVE-{GNA ID}-{YEAR}-{NUMBER}`. GNA 0 is the CVE
  Program: `CVE-2023-1234` is `GCVE-0-2023-1234`. GNA 1 is CIRCL.
- **The registry is signed.** It is verified (RSA, SHA-512) when it is pulled, and
  before a lookup: the URLs used for a lookup come from the registry. Only HTTPS URLs
  are followed.
- **How a record is found.** BCP-03 (https://gcve.eu/bcp/gcve-bcp-03/) defines no
  endpoint to fetch one record. A lookup tries the dump of the GNA (`gcve_dump`),
  then its pull API (`gcve_pull_api` + `/api/gcve/publication`), then GNA-1, which
  pulls from other GNAs. The `gcve_api` field is specific to each GNA: do not use it.
- **The registry is not uniform.** Most fields of a GNA entry are optional, and
  `gcve_dump` may be a file, a directory or a web page.
- **Records are not trusted.** They come from third parties. Before a value of a
  record is written to a terminal, control characters are removed and identifiers
  are checked against a strict pattern (see `summary.py` and `lookup.py`).
- **Formats.** Records are mostly in the CVE Record Format, but other formats (OSV,
  CSAF) are possible. A new format is a new extractor in `summary.py`; the display
  only relies on the summary.
- **Local files.** Everything is cached in `.gcve/` (registry, dumps, references,
  CNA partners), which is not versioned.
