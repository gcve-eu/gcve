#!/usr/bin/env python

import argparse
import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any, List

from gcve import __version__
from gcve.cna import CNAPartner, find_cna_by_name, get_cna_by_short_name
from gcve.gna import GNAEntry, find_gna_by_short_name, get_gna_by_short_name
from gcve.lookup import lookup_gcve
from gcve.registry import (
    GCVE_PATH,
    load_cna_partners,
    load_references,
    load_registry,
    update_cna_partners,
    update_references,
    update_registry,
    update_registry_public_key,
    update_registry_signature,
    verify_registry_integrity,
)
from gcve.summary import detect_record_format, summarize_record


def handle_registry(args: Any) -> None:
    if args.pull:
        print("Pulling from registry…")
        update_registry_public_key(Path(args.path))
        update_registry_signature(Path(args.path))
        update_registry(Path(args.path))
        if verify_registry_integrity(Path(args.path)):
            print("Integrity check passed successfully.")
        return

    if args.get or args.find or args.list_registry:
        gcve_data: List[GNAEntry] = load_registry(Path(args.path))
        if args.get:
            result = get_gna_by_short_name(args.get, gcve_data)
            if result:
                print(json.dumps(result, indent=2))
        elif args.list_registry:
            print(json.dumps(gcve_data, indent=2))
        elif args.find:
            results: List[GNAEntry] = find_gna_by_short_name(args.find, gcve_data)
            print(json.dumps(results, indent=2))
        return

    print("Registry command called without --pull")


def handle_references(args: Any) -> None:
    if args.pull:
        print("Pulling references…")
        update_references(Path(args.path))
        print("References downloaded successfully.")
        return

    if args.list_references:
        references_data = load_references(Path(args.path))
        print(json.dumps(references_data, indent=2))
        return

    print("References command called without valid arguments")


def handle_cna(args: Any) -> None:
    if args.pull:
        print("Pulling CNA partners…")
        update_cna_partners(Path(args.path))
        print("CNA partners downloaded successfully.")
        return

    if args.get or args.find or args.list_cna:
        cna_data: List[CNAPartner] = load_cna_partners(Path(args.path))
        if args.get:
            result = get_cna_by_short_name(args.get, cna_data)
            if result:
                print(json.dumps(result, indent=2))
        elif args.list_cna:
            print(json.dumps(cna_data, indent=2))
        elif args.find:
            results: List[CNAPartner] = find_cna_by_name(args.find, cna_data)
            print(json.dumps(results, indent=2))
        return

    print("CNA command called without valid arguments")


def handle_lookup(args: Any) -> None:
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    if args.pretty and importlib.util.find_spec("rich") is None:
        sys.exit("The --pretty option requires rich: pip install 'gcve[pretty]'")
    base_path = Path(args.path)
    if not (base_path / GCVE_PATH).exists():
        sys.exit("No local registry found. Run 'gcve registry --pull' first.")
    # The URLs used for the lookup come from the registry.
    if not verify_registry_integrity(base_path):
        sys.exit(1)

    try:
        result = lookup_gcve(args.gcve_id, base_path, via=args.via)
    except (ValueError, LookupError) as e:
        sys.exit(str(e))

    if result is None:
        sys.exit(f"{args.gcve_id} not found.")
    print(f"Source: {result.source} - {result.url}", file=sys.stderr)
    if args.pretty:
        print_pretty(result.record)
    else:
        print(json.dumps(result.record, indent=2))


def print_pretty(record: Any) -> None:
    """Display the summary of a record, or the record as highlighted JSON when
    its format can not be summarized."""
    from gcve.pretty import print_json, print_summary  # requires rich

    if summary := summarize_record(record):
        print_summary(summary)
        return
    record_format = detect_record_format(record) or "unknown"
    print(
        f"No summary available for this format ({record_format}), displaying the record.",
        file=sys.stderr,
    )
    print_json(record)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="gcve", description="A Python client for the Global CVE Allocation System."
    )
    subparsers = parser.add_subparsers(dest="command")

    parser.add_argument(
        "--version", action="store_true", help="Display the version of the client."
    )

    # Subcommand: registry
    registry_parser = subparsers.add_parser("registry", help="Registry operations")
    registry_parser.add_argument(
        "--pull", action="store_true", help="Pull from registry"
    )
    registry_parser.add_argument(
        "--list", dest="list_registry", help="List the registry", action="store_true"
    )
    registry_parser.add_argument("--get", dest="get", help="Get by shortname")
    registry_parser.add_argument(
        "--find", dest="find", help="Find in the registry by shortname"
    )
    registry_parser.add_argument(
        "--path", dest="path", help="Path of the local registry.", default=".gcve"
    )
    registry_parser.set_defaults(func=handle_registry)

    # Subcommand: references
    references_parser = subparsers.add_parser(
        "references", help="References operations"
    )
    references_parser.add_argument(
        "--pull", action="store_true", help="Pull references from server"
    )
    references_parser.add_argument(
        "--list",
        dest="list_references",
        help="List the references",
        action="store_true",
    )
    references_parser.add_argument(
        "--path", dest="path", help="Path of the local references.", default=".gcve"
    )
    references_parser.set_defaults(func=handle_references)

    # Subcommand: cna
    cna_parser = subparsers.add_parser(
        "cna", help="CNA partners of the CVE Program operations"
    )
    cna_parser.add_argument(
        "--pull", action="store_true", help="Pull CNA partners from server"
    )
    cna_parser.add_argument(
        "--list", dest="list_cna", help="List the CNA partners", action="store_true"
    )
    cna_parser.add_argument("--get", dest="get", help="Get a CNA partner by shortname")
    cna_parser.add_argument(
        "--find", dest="find", help="Find CNA partners by name or shortname"
    )
    cna_parser.add_argument(
        "--path", dest="path", help="Path of the local CNA partners.", default=".gcve"
    )
    cna_parser.set_defaults(func=handle_cna)

    # Subcommand: lookup
    lookup_parser = subparsers.add_parser(
        "lookup", help="Look up a vulnerability by its GCVE identifier"
    )
    lookup_parser.add_argument(
        "gcve_id", metavar="GCVE-ID", help="GCVE identifier, e.g. GCVE-1-2025-0001"
    )
    lookup_parser.add_argument(
        "--via",
        dest="via",
        metavar="GNA",
        help="Only query this GNA (identifier or short name), as aggregator, "
        "instead of the GNA which allocated the identifier.",
    )
    lookup_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Display a summary of the record instead of the JSON. "
        "Requires rich: pip install 'gcve[pretty]'.",
    )
    lookup_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display the resolution of the identifier and the requests made.",
    )
    lookup_parser.add_argument(
        "--path", dest="path", help="Path of the local registry.", default=".gcve"
    )
    lookup_parser.set_defaults(func=handle_lookup)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    elif args.version:
        print(__version__)
    else:
        parser.print_help()
