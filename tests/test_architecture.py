import unittest
from pathlib import Path


class ArchitectureTest(unittest.TestCase):
    def test_builder_is_split_by_responsibility(self) -> None:
        import scripts.build_blocklists as facade
        from blocklist_builder import builder, parsing, storage

        self.assertIs(facade.build, builder.build)
        self.assertIs(facade.parse_content, parsing.parse_content)
        self.assertTrue(callable(builder.build))
        self.assertTrue(callable(parsing.parse_content))
        self.assertTrue(callable(storage.initialize_database))
        package = Path(__file__).resolve().parents[1] / "blocklist_builder"
        self.assertFalse((package / "dns.py").exists())
        self.assertFalse((package / "dns_records.py").exists())
        self.assertFalse((package / "dns_discovery.py").exists())


if __name__ == "__main__":
    unittest.main()
