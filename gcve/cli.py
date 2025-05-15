#!/usr/bin/env python

import argparse
import json
from pathlib import Path
from typing import Any, List

from gcve import __version__
from gcve.gna import GNAEntry, find_gna_by_short_name, get_gna_by_short_name
from gcve.utils import (
    download_directory_signature_if_changed,
    download_gcve_json_if_changed,
    download_public_key_if_changed,
    load_gcve_json,
    verify_gcve_integrity,
)


def handle_registry(args: Any) -> None:
    if args.pull:
        print("Pulling from registry...")
        download_public_key_if_changed(Path(args.path))
        download_directory_signature_if_changed(Path(args.path))
        download_gcve_json_if_changed(Path(args.path))
        if verify_gcve_integrity(Path(args.path)):
            print("Integrity check passed successfully.")
        return

    if args.get or args.find or args.list_registry:
        gcve_data: List[GNAEntry] = load_gcve_json(Path(args.path))
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

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    elif args.version:
        print(__version__)
    else:
        parser.print_help()
