import unittest
import tempfile
import textwrap
import sqlite3
from pathlib import Path
from unittest.mock import patch

import scripts.build_blocklists as builder
from scripts.build_blocklists import (
    build,
    parse_content,
)


class ParseContentTest(unittest.TestCase):
    def test_stream_parser_accepts_one_shot_line_iterable(self) -> None:
        class OneShotLines:
            def __init__(self) -> None:
                self.iterated = False

            def __iter__(self):
                if self.iterated:
                    raise AssertionError("source was iterated more than once")
                self.iterated = True
                yield "||ads.example.com^\n"
                yield "@@||allowed.example.com^\n"

        entries: list[tuple[str, str]] = []
        builder.parse_lines(
            OneShotLines(),
            "adblock",
            emit=lambda domain, scope: entries.append((domain, scope)),
        )

        self.assertEqual(entries, [("ads.example.com", "suffix")])

    def test_domains_preserve_exact_and_suffix_scope(self) -> None:
        content = """
        # comment
        Example.COM
        *.example.com
        exact.example.com.
        not_a_domain
        """

        self.assertEqual(
            parse_content(content, "domains"),
            {
                "example.com": "suffix",
                "exact.example.com": "host",
            },
        )

    def test_source_scope_can_force_suffix(self) -> None:
        self.assertEqual(
            parse_content("social.example.com\n", "domains", scope="suffix"),
            {"social.example.com": "suffix"},
        )

    def test_hosts_extract_exact_domains(self) -> None:
        content = """
        0.0.0.0 ads.example.com tracker.example.com # comment
        127.0.0.1 localhost
        ::1 localhost
        """

        self.assertEqual(
            parse_content(content, "hosts"),
            {
                "ads.example.com": "host",
                "tracker.example.com": "host",
            },
        )

    def test_adblock_ignores_exception_rules(self) -> None:
        content = """
        [Adblock Plus 2.0]
        ! comment
        ||ads.example.com^
        @@||allowed.example.com^
        ||metrics.example.com^$third-party
        ||disabled.example.com^$third-party
        ||disabled.example.com^$third-party,badfilter
        example.com##.advertisement
        /regular-expression/
        """

        self.assertEqual(
            parse_content(content, "adblock"),
            {
                "ads.example.com": "suffix",
                "metrics.example.com": "suffix",
            },
        )

    def test_rpz_wildcard_makes_domain_a_suffix(self) -> None:
        content = """
        $TTL 30
        @ IN SOA rpz.example. hostmaster.example. (
            1 3600 900 604800 30
        )
        @ IN NS localhost.
        blocked.example.com 60 IN CNAME .
        *.blocked.example.com 120 CNAME .
        exact.example.com IN CNAME .
        passthrough.example.com CNAME rpz-passthru.
        """

        self.assertEqual(
            parse_content(textwrap.dedent(content), "rpz"),
            {
                "blocked.example.com": "suffix",
                "exact.example.com": "host",
            },
        )


class DnsClassificationTest(unittest.TestCase):
    def test_dnsx_streams_a_and_aaaa_through_one_resolver_file(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            builder._initialize_database(connection)
            connection.execute(
                """
                INSERT INTO domains(category, domain, scope)
                VALUES ('adblock', 'live.example', 0)
                """
            )
            commands: list[list[str]] = []
            resolver_files: list[str] = []
            input_domains: list[str] = []

            def complete_dnsx(command, **kwargs) -> None:
                commands.append(command)
                resolver_path = Path(command[command.index("-r") + 1])
                resolver_files.append(
                    resolver_path.read_text(encoding="utf-8")
                )
                input_domains.extend(
                    line.strip() for line in kwargs["stdin"] if line.strip()
                )
                kwargs["stdout"].write(
                    '{"host":"live.example","a":["192.0.2.1"]}\n'
                )

            with (
                patch.object(builder.shutil, "which", return_value="/dnsx"),
                patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=complete_dnsx,
                ),
            ):
                builder._validate_dns_database(
                    connection,
                    {"resolvers": ["1.1.1.1", "8.8.8.8"]},
                )

            self.assertEqual(len(commands), 1)
            self.assertEqual(commands[0][0], "/dnsx")
            self.assertTrue(
                {
                    "-a",
                    "-aaaa",
                    "-stream",
                    "-json",
                    "-omit-raw",
                    "-disable-update-check",
                }.issubset(commands[0])
            )
            self.assertEqual(
                resolver_files,
                ["1.1.1.1\n8.8.8.8\n"],
            )
            self.assertEqual(input_domains, ["live.example"])

    def test_dnsx_jsonl_keeps_only_domains_with_addresses(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            builder._initialize_database(connection)
            connection.executemany(
                """
                INSERT INTO domains(category, domain, scope)
                VALUES ('adblock', ?, ?)
                """,
                [
                    ("dead.example", 0),
                    ("wild.example", 1),
                    ("live.example", 0),
                    ("v6.example", 0),
                    ("missing.example", 0),
                ],
            )
            builder._store_dnsx_results(
                connection,
                [
                    '{"host":"dead.example","status_code":"NOERROR"}\n',
                    '{"host":"wild.example","a":[],"aaaa":[]}\n',
                    '{"host":"live.example","a":["192.0.2.1"]}\n',
                    '{"host":"v6.example","aaaa":["2001:db8::1"]}\n',
                ],
            )
            connection.execute(
                "CREATE TABLE removed(domain TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            builder._remove_unresolved_domains(connection)

            self.assertEqual(
                list(
                    connection.execute("SELECT domain FROM removed ORDER BY domain")
                ),
                [
                    ("dead.example",),
                    ("missing.example",),
                    ("wild.example",),
                ],
            )

class BuildTest(unittest.TestCase):
    def test_builds_separate_outputs_without_filtering_domains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom.txt").write_text(
                "local.example.com\n*.shared.example.com\n",
                encoding="utf-8",
            )
            config = {
                "sources": [
                    {
                        "name": "remote",
                        "category": "adblock",
                        "format": "domains",
                        "url": "memory://ads",
                    },
                    {
                        "name": "local",
                        "category": "social",
                        "format": "domains",
                        "scope": "suffix",
                        "path": "custom.txt",
                    },
                ],
            }

            with patch.object(
                builder,
                "parse_content",
                side_effect=AssertionError("build loaded a whole source"),
            ):
                counts = build(
                    config=config,
                    base_directory=root,
                    output_directory=root / "output",
                    skip_dns=True,
                    fetch_text=lambda _: (
                        "ads.example.com\nallowed.example.com\nads.example.com\n"
                    ),
                )

            self.assertEqual(counts, {"adblock": 2, "social": 2})
            self.assertEqual(
                (root / "output/adblock.txt").read_text(encoding="utf-8"),
                "ads.example.com\nallowed.example.com\n",
            )
            self.assertEqual(
                (root / "output/social.txt").read_text(encoding="utf-8"),
                "local.example.com\nshared.example.com\n",
            )
    def test_dns_failure_keeps_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            existing = output / "adblock.txt"
            existing.write_text("existing.example.com\n", encoding="utf-8")
            config = {
                "sources": [
                    {
                        "name": "local",
                        "category": "adblock",
                        "format": "domains",
                        "path": "custom.txt",
                    }
                ],
            }
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
            config = {
                "sources": [
                    {
                        "name": "local",
                        "category": "adblock",
                        "format": "domains",
                        "path": "custom.txt",
                    }
                ],
            }

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

            self.assertEqual(counts, {"adblock": 0})
            self.assertEqual(
                (root / "output/adblock.txt").read_text(encoding="utf-8"),
                "",
            )


if __name__ == "__main__":
    unittest.main()
