import inspect
import tempfile
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
            )

            self.assertEqual(count, 2)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "custom.example.com\nsource.example.com",
            )

    def test_collapses_descendants_without_dns_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "domains.txt").write_text(
                "dead-parent.example\nlive.dead-parent.example\n",
                encoding="utf-8",
            )
            count = build(
                config={"sources": {"domains": ["domains.txt"]}},
                base_directory=root,
                output_directory=root / "output",
            )

            self.assertEqual(count, 1)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "dead-parent.example",
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

            counts = build(
                config=config,
                base_directory=root,
                output_directory=root / "output",
            )

            self.assertEqual(counts, 2)
            self.assertEqual(
                (root / "output/blocklist.txt").read_text(encoding="utf-8"),
                "dead-parent.com\nexample.com",
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

            with redirect_stdout(output):
                build(
                    config=config,
                    base_directory=root,
                    output_directory=root / "output",
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
                    fetch_text=lambda _: "ads.example.com\n",
                )

            log = output.getvalue()
            self.assertIn(
                "Starting build: 3 phases "
                "(download 0-20%, parse/filter 20-90%, "
                "write 90-100%)",
                log,
            )
            self.assertIn(
                "[phase 1/3 | 0.0%] [download 1/1] "
                "Downloading memory://ads",
                log,
            )
            self.assertIn(
                "[phase 1/3 | 20.0%] [download 1/1] "
                "Downloaded memory://ads",
                log,
            )
            self.assertIn(
                "[phase 2/3 | 20.0%] [parse 1/1] "
                "Parsing memory://ads",
                log,
            )
            self.assertIn(
                "[phase 2/3 | 90.0%] [parse 1/1] "
                "Parsed memory://ads: 1 domain",
                log,
            )
            self.assertIn(
                "[phase 3/3 | 90.0%] Writing blocklist.txt: 1 domain",
                log,
            )
            self.assertIn(
                "[phase 3/3 | 100.0%] Build complete in ",
                log,
            )
            self.assertNotIn("DNS", log)
            self.assertNotIn("dns", log)

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
    def test_source_failure_keeps_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            existing = output / "blocklist.txt"
            existing.write_text("existing.example.com\n", encoding="utf-8")
            config = {"sources": {"domains": ["memory://broken"]}}

            with self.assertRaisesRegex(RuntimeError, "source unavailable"):
                build(
                    config=config,
                    base_directory=root,
                    output_directory=output,
                    fetch_text=lambda *_: (_ for _ in ()).throw(
                        RuntimeError("source unavailable")
                    ),
                )

            self.assertEqual(
                existing.read_text(encoding="utf-8"),
                "existing.example.com\n",
            )

    def test_build_api_has_no_dns_controls(self) -> None:
        parameters = inspect.signature(build).parameters

        self.assertNotIn("skip_dns", parameters)
        self.assertNotIn("dns_validator", parameters)


if __name__ == "__main__":
    unittest.main()
