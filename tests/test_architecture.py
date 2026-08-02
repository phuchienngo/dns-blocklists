import unittest


class ArchitectureTest(unittest.TestCase):
    def test_builder_is_split_by_responsibility(self) -> None:
        import scripts.build_blocklists as facade
        from blocklist_builder import builder, dns, parsing, storage

        self.assertIs(facade.build, builder.build)
        self.assertIs(facade.parse_content, parsing.parse_content)
        self.assertTrue(callable(builder.build))
        self.assertTrue(callable(dns.validate_dns_database))
        self.assertTrue(callable(parsing.parse_content))
        self.assertTrue(callable(storage.initialize_database))


if __name__ == "__main__":
    unittest.main()
