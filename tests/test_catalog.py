from contextlib import closing, redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from vuln_catalog.cli import main
from vuln_catalog.domain import ProductCatalog, Vulnerability, version_key


ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_dotted_numbers_are_compared_numerically(self):
        self.assertGreater(version_key("15.10"), version_key("15.9"))
        self.assertEqual(version_key("24.07"), version_key("24.7.0"))
        self.assertLess(version_key("8.0.4510.0"), version_key("8.0.4510.1"))

    def test_invalid_version_is_rejected(self):
        for value in ("1.2-beta", "1..2", "", "-1.0"):
            with self.subTest(version=value), self.assertRaises(ValueError):
                version_key(value)

    def test_range_starts_inclusively_and_ends_exclusively(self):
        item = Vulnerability("KLA1", "Test", "2024-01-01", "2.9", "2.10")
        self.assertFalse(item.affects(version_key("2.8")))
        self.assertTrue(item.affects(version_key("2.9")))
        self.assertFalse(item.affects(version_key("2.10")))

    def test_recommendation_uses_catalog_and_skips_affected_versions(self):
        item = Vulnerability("KLA1", "Test", "2024-01-01", "2.9", "3.0")
        product = ProductCatalog("Vendor", "Product", ("2.8", "2.10", "2.7"), (item,))
        self.assertEqual(product.recommendation(), "2.8")


class RealFeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.database = Path(directory.name) / "catalog with spaces.sqlite3"
        result = cls.run_cli("import")
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.import_output = result.stdout

    @classmethod
    def run_cli(cls, *args):
        return subprocess.run(
            [sys.executable, "-B", "-m", "vuln_catalog", "--db", str(cls.database), *args],
            cwd=ROOT,
            capture_output=True,
            encoding="utf-8",
            timeout=10,
        )

    def test_import_counts_and_integrity(self):
        self.assertIn("24 products, 834 versions, and 135 vulnerability records", self.import_output)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM versions").fetchone(), (834,))
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone(), (135,)
            )
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_7_zip_cli_examples(self):
        cases = (
            (("check", "7-zip", "24.06"), "KLA77436"),
            (("check", "7-Zip", "24.07"), "No known vulnerabilities"),
            (("recommend", "7-Zip"), "24.09"),
            (("recommend", "Oracle VirtualBox"), "no catalog version"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)

    def test_matching_a_release_line_uses_its_own_fix(self):
        affected = self.run_cli("check", "Git for Windows", "2.43.3")
        fixed = self.run_cli("check", "Git for Windows", "2.43.4")
        self.assertEqual((affected.returncode, fixed.returncode), (0, 0))
        self.assertEqual(affected.stdout.count("KLA67449"), 1)
        self.assertIn("first fixed: 2.43.4", affected.stdout)
        self.assertNotIn("KLA67449", fixed.stdout)

    def test_postgresql_release_lines(self):
        affected = self.run_cli("check", "PostgreSQL", "15.8.1")
        fixed = self.run_cli("check", "PostgreSQL", "15.9.1")
        self.assertEqual((affected.returncode, fixed.returncode), (0, 0))
        self.assertIn("KLA77143", affected.stdout)
        self.assertNotIn("KLA77143", fixed.stdout)

    def test_thunderbird_empty_range_is_interpreted_using_the_advisory(self):
        affected = self.run_cli("check", "Mozilla Thunderbird", "115.12.2")
        fixed = self.run_cli("check", "Mozilla Thunderbird", "128.0")
        self.assertEqual((affected.returncode, fixed.returncode), (0, 0))
        self.assertIn("KLA70478", affected.stdout)
        self.assertNotIn("KLA70478", fixed.stdout)
        with closing(sqlite3.connect(self.database)) as connection:
            original = connection.execute(
                "SELECT first_affected, first_fixed FROM vulnerabilities WHERE article_id = ?",
                ("KLA70478",),
            ).fetchone()
        self.assertEqual(original, ("128", "128.0"))

    def test_unknown_product_and_uncatalogued_version_are_distinct(self):
        missing_product = self.run_cli("check", "Unknown product", "1.0")
        missing_version = self.run_cli("check", "7-Zip", "24.04")
        self.assertEqual(missing_product.returncode, 1)
        self.assertIn("unknown product", missing_product.stderr)
        self.assertEqual(missing_version.returncode, 0)
        self.assertIn("Version absent from the catalog", missing_version.stdout)
        self.assertIn("KLA77436", missing_version.stdout)


class ImportTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name)
        self.db = path / "catalog.sqlite3"
        self.versions = path / "versions.json"
        self.vulnerabilities = path / "vulnerabilities.json"
        self.vulnerabilities.write_text("[]", encoding="utf-8")

    def invoke(self, *args):
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--db", str(self.db), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def import_versions(self, *records):
        self.versions.write_text(json.dumps(records), encoding="utf-8")
        return self.invoke(
            "import", "--versions", str(self.versions),
            "--vulnerabilities", str(self.vulnerabilities),
        )

    def test_failed_reload_preserves_previous_snapshot(self):
        original = {"vendor": "Example", "product": "Demo", "version": "1.0"}
        duplicate = {**original, "version": "2.0"}
        self.assertEqual(self.import_versions(original)[0], 0)
        self.assertEqual(self.import_versions(duplicate, duplicate)[0], 1)
        code, output, error = self.invoke("recommend", "Demo")
        self.assertEqual(code, 0, error)
        self.assertIn("1.0", output)

        self.assertEqual(self.import_versions(duplicate)[0], 0)
        self.assertEqual(self.import_versions(duplicate)[0], 0)
        code, output, error = self.invoke("recommend", "Demo")
        self.assertEqual(code, 0, error)
        self.assertIn("2.0", output)

    def test_invalid_record_identifies_file_and_position(self):
        code, _, error = self.import_versions(
            {"vendor": "Example", "product": "Demo", "version": "latest"}
        )
        self.assertEqual(code, 1)
        self.assertIn("versions.json, record 1", error)
        self.assertFalse(self.db.exists())

    def test_ambiguous_name_can_be_disambiguated_by_vendor(self):
        records = (
            {"vendor": "First", "product": "Demo", "version": "1.0"},
            {"vendor": "Second", "product": "Demo", "version": "2.0"},
        )
        self.assertEqual(self.import_versions(*records)[0], 0)
        code, _, error = self.invoke("recommend", "Demo")
        self.assertEqual(code, 1)
        self.assertIn("--vendor", error)
        code, output, error = self.invoke("recommend", "Demo", "--vendor", "Second")
        self.assertEqual(code, 0, error)
        self.assertIn("2.0", output)
