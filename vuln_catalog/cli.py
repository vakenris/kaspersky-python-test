import argparse
from pathlib import Path
import sqlite3
import sys

from .database import read_product, replace_catalog
from .domain import version_key
from .feeds import load_versions, load_vulnerabilities


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vuln_catalog",
        description="Query known vulnerabilities from a local feed snapshot.",
    )
    parser.add_argument("--db", type=Path, default=Path("catalog.sqlite3"), help="SQLite file")
    commands = parser.add_subparsers(dest="command", required=True)

    importer = commands.add_parser("import", help="load both JSON feeds into SQLite")
    importer.add_argument("--versions", type=Path, default=Path("data/versions.json"))
    importer.add_argument(
        "--vulnerabilities", type=Path, default=Path("data/vulnerabilities.json")
    )

    recommend = commands.add_parser("recommend", help="find the newest matching catalog version")
    check = commands.add_parser("check", help="show known vulnerabilities for a version")
    for command in (recommend, check):
        command.add_argument("product", help="exact product name, ignoring ASCII letter case")
        command.add_argument("--vendor", help="manufacturer, if the product name is ambiguous")
    check.add_argument("version", help="version number, for example 24.06")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "import":
            versions = load_versions(args.versions)
            vulnerabilities = load_vulnerabilities(args.vulnerabilities)
            product_count = replace_catalog(args.db, versions, vulnerabilities)
            print(
                f"Imported {product_count} products, {len(versions)} versions, "
                f"and {len(vulnerabilities)} vulnerability records into {args.db}."
            )
            return 0

        product = read_product(args.db, args.product, args.vendor)
        label = f"{product.name} ({product.vendor})"
        if args.command == "recommend":
            version = product.recommendation()
            if version is None:
                print(f"{label}: no catalog version without known vulnerabilities.")
            else:
                print(f"{label}: {version} (no known vulnerabilities in the supplied feed).")
            return 0

        version = version_key(args.version)
        print(f"{label}, version {args.version}")
        if version not in {version_key(value) for value in product.versions}:
            print("Version absent from the catalog. Checking the recorded ranges.")
        findings = product.findings(version)
        if not findings:
            print("No known vulnerabilities in the supplied feed.")
        for item in findings:
            start = item.effective_start
            lower_bound = start if start != "0" else "unspecified"
            print(
                f"{item.article_id} | {item.published_on} | {item.description} | "
                f"first affected: {lower_bound} | first fixed: {item.first_fixed}"
            )
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
