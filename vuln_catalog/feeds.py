from datetime import date
import json
from pathlib import Path
from typing import Iterator

from .domain import Vulnerability, version_key


VersionRow = tuple[str, str, str]
VulnerabilityRow = tuple[str, str, Vulnerability]


def _records(path: Path, fields: tuple[str, ...]) -> Iterator[tuple[str, list[str]]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"{path}: {exc}") from exc

    if not isinstance(payload, list):
        raise ValueError(f"{path}: expected a JSON array")

    for index, record in enumerate(payload, start=1):
        location = f"{path}, record {index}"
        if not isinstance(record, dict):
            raise ValueError(f"{location}: expected a JSON object")

        values = []
        for field in fields:
            value = record.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{location}: {field} must be a non-empty string")
            values.append(value.strip())
        yield location, values


def load_versions(path: Path) -> list[VersionRow]:
    rows = []
    for location, (vendor, product, version) in _records(
        path, ("vendor", "product", "version")
    ):
        try:
            version_key(version)
        except ValueError as exc:
            raise ValueError(f"{location}: {exc}") from exc
        rows.append((vendor, product, version))
    return rows


def load_vulnerabilities(path: Path) -> list[VulnerabilityRow]:
    fields = (
        "vendor", "product", "KLA_id", "description", "publish_date",
        "start_vuln_version", "fixed_version",
    )
    rows = []
    for location, values in _records(path, fields):
        vendor, product, article, description, published, start, fixed = values
        item = Vulnerability(article, description, published, start, fixed)
        try:
            if date.fromisoformat(published).isoformat() != published:
                raise ValueError("publish_date must use YYYY-MM-DD")
            if version_key(item.effective_start) >= version_key(fixed):
                raise ValueError("start_vuln_version must precede fixed_version")
        except ValueError as exc:
            raise ValueError(f"{location}: {exc}") from exc
        rows.append((vendor, product, item))
    return rows
