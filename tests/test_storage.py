import sqlite3
import tempfile
import unittest
from pathlib import Path

from blocklist_builder.storage import atomic_write_domains, initialize_database


class StorageTest(unittest.TestCase):
    def test_database_schema_has_no_dns_tables(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            initialize_database(connection)
            tables = {
                name
                for (name,) in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }

        self.assertFalse(any(name.startswith("dns") for name in tables))
        self.assertNotIn("removed", tables)

    def test_output_has_no_trailing_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "domains.txt"

            atomic_write_domains(
                output_path,
                iter([("a.example",), ("b.example",)]),
            )

            self.assertEqual(
                output_path.read_bytes(),
                b"a.example\nb.example",
            )
