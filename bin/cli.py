#!/usr/bin/env python

import argparse
from typing import Any

from gcve import __version__
from gcve.utils import (
    download_directory_signature_if_changed,
    download_gcve_json_if_changed,
    download_public_key_if_changed,
    verify_gcve_integrity,
)


def handle_registry(args: Any) -> None:
    if args.pull:
        print("Pulling from registry...")
        download_public_key_if_changed()
        download_directory_signature_if_changed()
        download_gcve_json_if_changed()
        if verify_gcve_integrity():
            print("Integrity check passed successfully.")
    else:
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
    registry_parser.set_defaults(func=handle_registry)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    elif args.version:
        print(__version__)
    else:
        parser.print_help()
