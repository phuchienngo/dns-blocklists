import tempfile
import unittest
from pathlib import Path

from blocklist_builder.storage import atomic_write_domains


class StorageTest(unittest.TestCase):
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
