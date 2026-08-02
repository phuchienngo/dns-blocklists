import sqlite3
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import blocklist_builder.parsing as parsing
from blocklist_builder.builder import build


class BuildTest(unittest.TestCase):
    def test_filters_exact_public_suffixes_before_parent_collapse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "domains.txt").write_text(
                "duckdns.org\ntracker.duckdns.org\nexample.com\n",
                encoding="utf-8",
            )

            count = build(
                config={
                    "public_suffix_list": "memory://psl",
                    "sources": {"domains": ["domains.txt"]},
                },
                base_directory=root,
                output_directory=root / "output",
                skip_dns=True,
                fetch_text=lambda _: (
                    "// ===BEGIN ICANN DOMAINS===\ncom\norg\n"
                    "// ===BEGIN PRIVATE DOMAINS===\nduckdns.org\n"
                ),
            )

            self.assertEqual(count, 2)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "example.com\ntracker.duckdns.org",
            )

    def test_allowlist_excludes_domains_and_their_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom").mkdir()
            (root / "domains.txt").write_text(
                "allowed.example.com\nsub.allowed.example.com\nads.example.com\n",
                encoding="utf-8",
            )
            (root / "custom/allowlist.txt").write_text(
                "allowed.example.com\n",
                encoding="utf-8",
            )

            count = build(
                config={"sources": {"domains": ["domains.txt"]}},
                base_directory=root,
                output_directory=root / "output",
                skip_dns=True,
            )

            self.assertEqual(count, 1)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "ads.example.com",
            )
            self.assertEqual(
                sorted(path.name for path in (root / "output").iterdir()),
                ["blocklist.txt"],
            )

    def test_automatically_includes_custom_blocklist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom").mkdir()
            (root / "domains.txt").write_text(
                "source.example.com\n",
                encoding="utf-8",
            )
            (root / "custom/blocklist.txt").write_text(
                "custom.example.com\n",
                encoding="utf-8",
            )

            count = build(
                config={"sources": {"domains": ["domains.txt"]}},
                base_directory=root,
                output_directory=root / "output",
                skip_dns=True,
            )

            self.assertEqual(count, 2)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "custom.example.com\nsource.example.com",
            )

    def test_collapses_descendants_before_dns_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "domains.txt").write_text(
                "dead-parent.example\nlive.dead-parent.example\n",
                encoding="utf-8",
            )
            validated: list[str] = []

            def validate(
                connection: sqlite3.Connection,
                _dns_config: dict,
            ) -> None:
                validated.extend(
                    domain
                    for (domain,) in connection.execute(
                        "SELECT domain FROM domains ORDER BY domain"
                    )
                )
                connection.execute(
                    """
                    CREATE TABLE dns_resolved (
                        domain TEXT PRIMARY KEY
                    ) WITHOUT ROWID
                    """
                )

            count = build(
                config={"sources": {"domains": ["domains.txt"]}},
                base_directory=root,
                output_directory=root / "output",
                dns_validator=validate,
            )

            self.assertEqual(validated, ["dead-parent.example"])
            self.assertEqual(count, 0)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "",
            )

    def test_accepts_sources_grouped_by_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {
                "sources": {"adblock": ["memory://ads"]}
            }

            try:
                count = build(
                    config=config,
                    base_directory=root,
                    output_directory=root / "output",
                    skip_dns=True,
                    fetch_text=lambda _: "||ads.example.com^\n",
                )
            except Exception as error:
                self.fail(f"grouped sources were rejected: {error}")

            self.assertEqual(count, 1)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "ads.example.com",
            )

    def test_collapses_descendants_across_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "first.txt").write_text(
                "\n".join(
                    [
                        "example.com",
                        "a.example.com",
                        "dead-parent.com",
                        "live.dead-parent.com",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "second.txt").write_text(
                "b.a.example.com",
                encoding="utf-8",
            )
            config = {
                "sources": {"domains": ["first.txt", "second.txt"]}
            }

            def validate(
                connection: sqlite3.Connection,
                _dns_config: dict,
            ) -> None:
                connection.execute(
                    """
                    CREATE TABLE dns_resolved (
                        domain TEXT PRIMARY KEY
                    ) WITHOUT ROWID
                    """
                )
                connection.executemany(
                    "INSERT INTO dns_resolved VALUES (?)",
                    [
                        ("example.com",),
                        ("a.example.com",),
                        ("b.a.example.com",),
                        ("live.dead-parent.com",),
                    ],
                )

            counts = build(
                config=config,
                base_directory=root,
                output_directory=root / "output",
                dns_validator=validate,
            )

            self.assertEqual(counts, 1)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "example.com",
            )

    def test_does_not_emit_timer_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom.txt").write_text(
                "ads.example.com\n",
                encoding="utf-8",
            )
            config = {"sources": {"domains": ["custom.txt"]}}
            output = StringIO()

            def slow_validator(
                connection: sqlite3.Connection,
                _dns_config: dict,
            ) -> None:
                time.sleep(0.04)
                connection.execute(
                    """
                    CREATE TABLE dns_resolved (
                        domain TEXT PRIMARY KEY
                    ) WITHOUT ROWID
                    """
                )

            with redirect_stdout(output):
                build(
                    config=config,
                    base_directory=root,
                    output_directory=root / "output",
                    dns_validator=slow_validator,
                )

            self.assertNotIn("still running", output.getvalue())

    def test_reports_build_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {"sources": {"domains": ["memory://ads"]}}
            output = StringIO()

            with redirect_stdout(output):
                build(
                    config=config,
                    base_directory=root,
                    output_directory=root / "output",
                    skip_dns=True,
                    fetch_text=lambda _: "ads.example.com\n",
                )

            log = output.getvalue()
            self.assertIn(
                "Starting build: 6 phases "
                "(download 0-10%, parse 10-30%, "
                "MassDNS 30-70%, subdomain rescue 70-85%, "
                "extended DNS 85-95%, dnsx 95-100%)",
                log,
            )
            self.assertIn(
                "[phase 1/6 | 0.0%] [download 1/1] "
                "Downloading memory://ads",
                log,
            )
            self.assertIn(
                "[phase 1/6 | 10.0%] [download 1/1] "
                "Downloaded memory://ads",
                log,
            )
            self.assertIn(
                "[phase 2/6 | 10.0%] [parse 1/1] "
                "Parsing memory://ads",
                log,
            )
            self.assertIn(
                "[phase 2/6 | 30.0%] [parse 1/1] "
                "Parsed memory://ads: 1 domain",
                log,
            )
            self.assertIn(
                "[phase 3/6 | 70.0%] MassDNS validation skipped: "
                "retaining 1 unique domain",
                log,
            )
            self.assertIn(
                "[phase 4/6 | 85.0%] Subdomain rescue skipped",
                log,
            )
            self.assertIn(
                "[phase 5/6 | 95.0%] Extended DNS skipped",
                log,
            )
            self.assertIn(
                "[phase 6/6 | 100.0%] dnsx fallback skipped",
                log,
            )
            self.assertIn(
                "[phase 6/6 | 100.0%] Writing blocklist.txt: 1 domain",
                log,
            )
            self.assertIn(
                "[phase 6/6 | 100.0%] Build complete in ",
                log,
            )

    def test_builds_one_output_from_url_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom.txt").write_text(
                "local.example.com\n*.shared.example.com\n",
                encoding="utf-8",
            )
            config = {
                "sources": {"domains": ["memory://ads", "custom.txt"]}
            }

            with patch.object(
                parsing,
                "parse_content",
                side_effect=AssertionError("build loaded a whole source"),
            ):
                try:
                    counts = build(
                        config=config,
                        base_directory=root,
                        output_directory=root / "output",
                        skip_dns=True,
                        fetch_text=lambda _: (
                            "ads.example.com\nallowed.example.com\n"
                            "ads.example.com\n"
                        ),
                    )
                except Exception as error:
                    self.fail(f"URL-list config was rejected: {error}")

            self.assertEqual(counts, 4)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "ads.example.com\nallowed.example.com\n"
                "local.example.com\nshared.example.com",
            )
    def test_dns_failure_keeps_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            existing = output / "blocklist.txt"
            existing.write_text("existing.example.com\n", encoding="utf-8")
            config = {"sources": {"domains": ["custom.txt"]}}
            (root / "custom.txt").write_text(
                "new.example.com\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "DNS failed"):
                build(
                    config=config,
                    base_directory=root,
                    output_directory=output,
                    dns_validator=lambda *_: (_ for _ in ()).throw(
                        RuntimeError("DNS failed")
                    ),
                )

            self.assertEqual(
                existing.read_text(encoding="utf-8"),
                "existing.example.com\n",
            )

    def test_all_unresolved_domains_can_produce_empty_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom.txt").write_text(
                "live.example.com\ndead.example.com\n",
                encoding="utf-8",
            )
            config = {"sources": {"domains": ["custom.txt"]}}

            def resolve(connection, _dns_config) -> None:
                connection.execute(
                    """
                    CREATE TABLE dns_resolved (
                        domain TEXT PRIMARY KEY
                    ) WITHOUT ROWID;
                    """
                )

            counts = build(
                config=config,
                base_directory=root,
                output_directory=root / "output",
                dns_validator=resolve,
            )

            self.assertEqual(counts, 0)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "",
            )


if __name__ == "__main__":
    unittest.main()
