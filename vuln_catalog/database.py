from contextlib import closing
from pathlib import Path
import sqlite3

from .domain import ProductCatalog, Vulnerability
from .feeds import VersionRow, VulnerabilityRow


_APPLICATION_ID = 0x56434154  # VCAT
_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        vendor TEXT NOT NULL,
        name TEXT NOT NULL,
        UNIQUE (vendor, name)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS products_name_idx ON products (name COLLATE NOCASE)
    """,
    """
    CREATE TABLE IF NOT EXISTS versions (
        product_id INTEGER NOT NULL REFERENCES products (id) ON DELETE CASCADE,
        version TEXT NOT NULL,
        PRIMARY KEY (product_id, version)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        product_id INTEGER NOT NULL REFERENCES products (id) ON DELETE CASCADE,
        article_id TEXT NOT NULL,
        description TEXT NOT NULL,
        published_on TEXT NOT NULL,
        first_affected TEXT NOT NULL,
        first_fixed TEXT NOT NULL,
        PRIMARY KEY (product_id, article_id, first_affected, first_fixed)
    )
    """,
)


def _connect(path: Path, mode: str) -> sqlite3.Connection:
    uri = f"{path.resolve().as_uri()}?mode={mode}"
    return sqlite3.connect(uri, uri=True, isolation_level=None)


def _application_id(connection: sqlite3.Connection) -> int:
    return connection.execute("PRAGMA application_id").fetchone()[0]


def replace_catalog(
    path: Path, versions: list[VersionRow], vulnerabilities: list[VulnerabilityRow]
) -> int:
    products = sorted(
        {(vendor, name) for vendor, name, _ in versions}
        | {(vendor, name) for vendor, name, _ in vulnerabilities}
    )
    with closing(_connect(path, "rwc")) as connection, connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        application_id = _application_id(connection)
        if application_id != _APPLICATION_ID:
            existing_schema = connection.execute(
                "SELECT 1 FROM sqlite_schema LIMIT 1"
            ).fetchone()
            if application_id != 0 or existing_schema:
                raise ValueError(f"{path} belongs to a different application")

        for statement in _SCHEMA:
            connection.execute(statement)
        connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
        connection.execute("DELETE FROM products")
        connection.executemany("INSERT INTO products (vendor, name) VALUES (?, ?)", products)
        ids = {
            (vendor, name): product_id
            for product_id, vendor, name in connection.execute("SELECT id, vendor, name FROM products")
        }
        connection.executemany(
            "INSERT INTO versions (product_id, version) VALUES (?, ?)",
            ((ids[vendor, name], version) for vendor, name, version in versions),
        )
        connection.executemany(
            """
            INSERT INTO vulnerabilities
                (product_id, article_id, description, published_on, first_affected, first_fixed)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    ids[vendor, name],
                    item.article_id,
                    item.description,
                    item.published_on,
                    item.first_affected,
                    item.first_fixed,
                )
                for vendor, name, item in vulnerabilities
            ),
        )
    return len(products)


def read_product(path: Path, name: str, vendor: str | None = None) -> ProductCatalog:
    if not path.exists():
        raise ValueError(f"database {path} does not exist; run the import command first")

    with closing(_connect(path, "ro")) as connection, connection:
        connection.execute("BEGIN")
        if _application_id(connection) != _APPLICATION_ID:
            raise ValueError(f"{path} is not an initialized vulnerability catalog")

        query = "SELECT id, vendor, name FROM products WHERE name = ? COLLATE NOCASE"
        params = (name,) if vendor is None else (name, vendor)
        if vendor is not None:
            query += " AND vendor = ? COLLATE NOCASE"
        matches = connection.execute(query + " ORDER BY vendor, name", params).fetchall()
        if not matches:
            qualifier = "" if vendor is None else f" from {vendor!r}"
            raise ValueError(f"unknown product {name!r}{qualifier}")
        if len(matches) > 1:
            vendors = ", ".join(row[1] for row in matches)
            raise ValueError(f"ambiguous product {name!r}; use --vendor ({vendors})")

        product_id, vendor_name, product_name = matches[0]
        versions = tuple(
            row[0]
            for row in connection.execute(
                "SELECT version FROM versions WHERE product_id = ? ORDER BY version",
                (product_id,),
            )
        )
        vulnerabilities = tuple(
            Vulnerability(*row)
            for row in connection.execute(
                """
                SELECT article_id, description, published_on, first_affected, first_fixed
                FROM vulnerabilities
                WHERE product_id = ?
                ORDER BY published_on DESC, article_id, first_affected, first_fixed
                """,
                (product_id,),
            )
        )
    return ProductCatalog(vendor_name, product_name, versions, vulnerabilities)
