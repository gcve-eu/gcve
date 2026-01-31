# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GCVE is a Python client for the Global CVE Allocation System (https://gcve.eu), a decentralized approach to vulnerability identification and numbering. The client provides both a CLI tool and a Python library for working with GCVE identifiers and the GNA (GCVE Numbering Authority) registry.

## Development Commands

### Environment Setup
```bash
# Install with Poetry (recommended for development)
poetry install

# Install with pipx (for CLI usage)
pipx install gcve
```

### Code Quality
```bash
# Run type checking
mypy gcve/

# Run linting
flake8 gcve/

# Run pre-commit hooks manually
pre-commit run --all-files
```

### Building and Distribution
```bash
# Build package
poetry build

# Install locally for testing
pip install -e .
```

## Code Architecture

### Core Modules

**gcve/main.py** - Core GCVE ID generation and validation logic
- `validate_gcve_id()`: Validates GCVE ID format using regex `GCVE-(\d+)-(\d{4})-(\d{4,})`
- `to_gcve_id()`: Converts CVE IDs to GCVE-0 format (GCVE-0 represents CVE reference)
- `gcve0_to_cve()`: Converts GCVE-0 IDs back to CVE format
- `gcve_generator()`: Generator function that creates new GCVE IDs for a GNA, avoiding collisions

**gcve/gna.py** - GNA (GCVE Numbering Authority) entry type definitions and lookup functions
- `GNAEntry`: TypedDict defining the structure of a GNA registry entry (id, short_name, full_name, cpe_vendor_name, gcve_url, gcve_api, gcve_dump, gcve_allocation, gcve_pull_api)
- Provides search and lookup functions for finding GNA entries by ID or short name

**gcve/registry.py** - Registry management with cryptographic verification
- Downloads and caches the GNA registry from gcve.eu
- Implements integrity verification using RSA signatures with SHA-512
- Registry files stored in `.gcve/registry/` by default
- Uses HTTP caching (ETag, Last-Modified) to avoid unnecessary downloads

**gcve/utils.py** - HTTP utility functions
- Smart download with conditional requests using ETag/Last-Modified headers
- Custom User-Agent header for GCVE client identification

**gcve/cli.py** - Command-line interface
- `registry` subcommand with operations: `--pull`, `--get`, `--find`, `--list`
- All operations work with local registry cache in `.gcve/` directory

### Key Concepts

**GCVE ID Format**: `GCVE-{GNA_ID}-{YEAR}-{NUMBER}`
- GNA_ID 0 is reserved for CVE (e.g., GCVE-0-2023-1234 represents CVE-2023-1234)
- GNA_ID 1 is CIRCL's namespace
- Higher GNA IDs are assigned to other numbering authorities

**Registry Security**: The GNA registry is cryptographically signed. The workflow is:
1. Download public key, signature file, and registry JSON
2. Verify signature using RSA with SHA-512 hashing
3. Only load registry if integrity check passes

**Caching Strategy**: HTTP conditional requests with ETag/Last-Modified prevent redundant downloads while ensuring data freshness.

### Public API Surface

The package exports these functions from `gcve/__init__.py`:
- `GNAEntry`, `get_gna_id_by_short_name`
- `validate_gcve_id`, `to_gcve_id`, `gcve0_to_cve`, `gcve_generator`

## Code Style

- Python 3.10+ required (uses union type syntax `|`)
- Type hints enforced with mypy (strict configuration)
- Black formatter with 120 character line length for flake8
- isort for import sorting with black profile
- Pre-commit hooks run: pyupgrade, isort, black, flake8, trailing-whitespace, end-of-file-fixer, pip-audit
