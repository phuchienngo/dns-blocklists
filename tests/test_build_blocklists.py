import unittest
import tempfile
import textwrap
import sqlite3
import time
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import scripts.build_blocklists as builder
from scripts.build_blocklists import (
    build,
    parse_content,
)


class ParseContentTest(unittest.TestCase):
    def test_progress_quantity_pluralizes_category(self) -> None:
        self.assertEqual(builder._quantity(2, "category"), "2 categories")

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
    def test_massdns_reports_cumulative_batch_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "domains.txt").write_text(
                "\n".join(
                    [
                        "a.example",
                        "b.example",
                        "c.example",
                        "d.example",
                        "e.example",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            config = {
                "dns": {"resolvers": ["1.1.1.1"]},
                "sources": [
                    {
                        "name": "local",
                        "category": "adblock",
                        "format": "domains",
                        "path": "domains.txt",
                    }
                ],
            }
            calls: list[tuple[str, list[str]]] = []

            def complete_massdns(command, **_kwargs) -> None:
                query_type = command[command.index("-t") + 1]
                domains = Path(command[-1]).read_text(
                    encoding="utf-8"
                ).splitlines()
                calls.append((query_type, domains))
                output_path = Path(command[command.index("-w") + 1])
                with output_path.open("w", encoding="utf-8") as output:
                    for domain in domains:
                        has_address = (
                            query_type == "A"
                            and domain in {"a.example", "c.example"}
                        ) or (
                            query_type == "AAAA"
                            and domain == "d.example"
                        )
                        payload = {
                            "name": f"{domain}.",
                            "type": query_type,
                            "status": (
                                "NOERROR"
                                if has_address
                                or (
                                    domain == "d.example"
                                    and query_type == "A"
                                )
                                else "NXDOMAIN"
                            ),
                        }
                        if has_address:
                            payload["data"] = {
                                "answers": [
                                    {
                                        "type": query_type,
                                        "data": (
                                            "93.184.216.34"
                                            if query_type == "A"
                                            else "2606:4700:4700::1111"
                                        ),
                                    }
                                ]
                            }
                        output.write(json.dumps(payload) + "\n")

            output = StringIO()
            with (
                patch.object(builder, "DNS_BATCH_SIZE", 2, create=True),
                patch.object(
                    builder.shutil,
                    "which",
                    return_value="/massdns",
                ),
                patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=complete_massdns,
                ),
                redirect_stdout(output),
            ):
                counts = build(
                    config=config,
                    base_directory=root,
                    output_directory=root / "output",
                )

            self.assertEqual(
                calls,
                [
                    ("A", ["a.example", "b.example"]),
                    ("A", ["c.example", "d.example"]),
                    ("AAAA", ["d.example"]),
                    ("A", ["e.example"]),
                ],
            )
            self.assertEqual(counts, {"adblock": 3})
            log = output.getvalue()
            self.assertIn(
                "[step 2/3 | 67%] DNS batch 1/3 complete: "
                "processed 2/5 (40.0%), kept 1, removed 1",
                log,
            )
            self.assertIn(
                "[step 2/3 | 67%] DNS batch 3/3 complete: "
                "processed 5/5 (100.0%), kept 3, removed 2",
                log,
            )

    def test_massdns_runs_a_and_aaaa_with_one_resolver_file(self) -> None:
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
            input_batches: list[list[str]] = []

            def complete_massdns(command, **_kwargs) -> None:
                commands.append(command)
                resolver_path = Path(command[command.index("-r") + 1])
                resolver_files.append(
                    resolver_path.read_text(encoding="utf-8")
                )
                input_batches.append(
                    Path(command[-1]).read_text(
                        encoding="utf-8"
                    ).splitlines()
                )
                output_path = Path(command[command.index("-w") + 1])
                query_type = command[command.index("-t") + 1]
                answers = []
                if query_type == "AAAA":
                    answers = [
                        {
                            "type": "AAAA",
                            "data": "2606:4700:4700::1111",
                        }
                    ]
                output_path.write_text(
                    json.dumps(
                        {
                            "name": "live.example.",
                            "type": query_type,
                            "status": "NOERROR",
                            "data": {"answers": answers},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            with (
                patch.object(
                    builder.shutil,
                    "which",
                    return_value="/massdns",
                ),
                patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=complete_massdns,
                ),
            ):
                builder._validate_dns_database(
                    connection,
                    {"resolvers": ["1.1.1.1", "8.8.8.8"]},
                )

            self.assertEqual(len(commands), 2)
            self.assertTrue(all(command[0] == "/massdns" for command in commands))
            self.assertEqual(
                [command[command.index("-t") + 1] for command in commands],
                ["A", "AAAA"],
            )
            self.assertTrue(
                all(
                    {"-o", "Je", "-q", "--verify-ip"}.issubset(command)
                    for command in commands
                )
            )
            self.assertEqual(
                resolver_files,
                [
                    "1.1.1.1\n8.8.8.8\n",
                    "1.1.1.1\n8.8.8.8\n",
                ],
            )
            self.assertEqual(
                input_batches,
                [["live.example"], ["live.example"]],
            )

    def test_massdns_jsonl_keeps_only_domains_with_addresses(self) -> None:
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
                    ("private.example", 0),
                    ("multicast.example", 0),
                    ("missing.example", 0),
                ],
            )
            builder._store_massdns_results(
                connection,
                [
                    '{"name":"dead.example.","type":"A",'
                    '"status":"NXDOMAIN"}\n',
                    '{"name":"wild.example.","type":"A",'
                    '"status":"NOERROR","data":{"answers":[]}}\n',
                    '{"name":"live.example.","type":"A",'
                    '"status":"NOERROR","data":{"answers":['
                    '{"type":"A","data":"93.184.216.34"}]}}\n',
                    '{"name":"v6.example.","type":"AAAA",'
                    '"status":"NOERROR","data":{"answers":['
                    '{"type":"AAAA","data":"2606:4700:4700::1111"}]}}\n',
                    '{"name":"private.example.","type":"A",'
                    '"status":"NOERROR","data":{"answers":['
                    '{"type":"A","data":"127.0.0.1"}]}}\n',
                    '{"name":"multicast.example.","type":"A",'
                    '"status":"NOERROR","data":{"answers":['
                    '{"type":"A","data":"224.0.0.1"}]}}\n',
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
                    ("multicast.example",),
                    ("private.example",),
                    ("wild.example",),
                ],
            )

    def test_massdns_retries_unresolved_and_keeps_unknown(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            builder._initialize_database(connection)
            connection.executemany(
                """
                INSERT INTO domains(category, domain, scope)
                VALUES ('adblock', ?, 0)
                """,
                [
                    ("dead.example",),
                    ("recovered.example",),
                    ("resolved.example",),
                    ("unknown.example",),
                ],
            )
            calls: list[tuple[str, str, list[str]]] = []

            def complete_massdns(command, **_kwargs) -> None:
                query_type = command[command.index("-t") + 1]
                resolver_text = Path(
                    command[command.index("-r") + 1]
                ).read_text(encoding="utf-8")
                domains = Path(command[-1]).read_text(
                    encoding="utf-8"
                ).splitlines()
                calls.append((resolver_text, query_type, domains))
                output_path = Path(command[command.index("-w") + 1])
                retry = command[command.index("-s") + 1] == "200"
                rows = []
                for domain in domains:
                    status = "SERVFAIL"
                    answers = []
                    if not retry and domain == "resolved.example":
                        status = "NOERROR"
                        answers = [
                            {
                                "type": query_type,
                                "data": (
                                    "93.184.216.34"
                                    if query_type == "A"
                                    else "2606:4700:4700::1111"
                                ),
                            }
                        ]
                    elif retry and domain == "recovered.example":
                        status = "NOERROR"
                        answers = [
                            {
                                "type": query_type,
                                "data": (
                                    "93.184.216.34"
                                    if query_type == "A"
                                    else "2606:4700:4700::1111"
                                ),
                            }
                        ]
                    elif domain == "dead.example":
                        status = "NXDOMAIN"
                    payload = {
                        "name": f"{domain}.",
                        "type": query_type,
                        "status": status,
                    }
                    if answers:
                        payload["data"] = {"answers": answers}
                    rows.append(json.dumps(payload))
                output_path.write_text(
                    "\n".join(rows) + "\n",
                    encoding="utf-8",
                )

            with (
                patch.object(
                    builder.shutil,
                    "which",
                    return_value="/massdns",
                ),
                patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=complete_massdns,
                ),
            ):
                builder._validate_dns_database(
                    connection,
                    {"resolvers": ["1.1.1.1", "8.8.8.8"]},
                )
                connection.execute(
                    "CREATE TABLE removed(domain TEXT PRIMARY KEY) WITHOUT ROWID"
                )
                builder._remove_unresolved_domains(connection)

            self.assertEqual(
                list(connection.execute("SELECT domain FROM removed")),
                [("dead.example",)],
            )
            self.assertEqual(len(calls), 4)
            self.assertEqual(
                [call[0] for call in calls],
                [
                    "1.1.1.1\n8.8.8.8\n",
                    "1.1.1.1\n8.8.8.8\n",
                    "1.1.1.1\n8.8.8.8\n",
                    "1.1.1.1\n8.8.8.8\n",
                ],
            )
            self.assertEqual(
                [(call[1], call[2]) for call in calls],
                [
                    (
                        "A",
                        [
                            "dead.example",
                            "recovered.example",
                            "resolved.example",
                            "unknown.example",
                        ],
                    ),
                    (
                        "AAAA",
                        ["recovered.example", "unknown.example"],
                    ),
                    (
                        "A",
                        ["recovered.example", "unknown.example"],
                    ),
                    ("AAAA", ["unknown.example"]),
                ],
            )

class BuildTest(unittest.TestCase):
    def test_collapses_descendants_only_under_retained_same_category_parent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "adblock.txt").write_text(
                "\n".join(
                    [
                        "example.com",
                        "a.example.com",
                        "b.a.example.com",
                        "dead-parent.com",
                        "live.dead-parent.com",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "privacy.txt").write_text(
                "a.example.com",
                encoding="utf-8",
            )
            config = {
                "sources": [
                    {
                        "name": "adblock",
                        "category": "adblock",
                        "format": "domains",
                        "path": "adblock.txt",
                    },
                    {
                        "name": "privacy",
                        "category": "privacy",
                        "format": "domains",
                        "path": "privacy.txt",
                    },
                ],
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

            self.assertEqual(counts, {"adblock": 2, "privacy": 1})
            self.assertEqual(
                (root / "output/adblock.txt").read_text(encoding="utf-8"),
                "example.com\nlive.dead-parent.com",
            )
            self.assertEqual(
                (root / "output/privacy.txt").read_text(encoding="utf-8"),
                "a.example.com",
            )

    def test_output_has_no_trailing_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "domains.txt"

            builder._atomic_write_domains(
                output_path,
                iter([("a.example",), ("b.example",)]),
            )

            self.assertEqual(
                output_path.read_bytes(),
                b"a.example\nb.example",
            )

    def test_reports_heartbeat_during_dns_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom.txt").write_text(
                "ads.example.com\n",
                encoding="utf-8",
            )
            config = {
                "sources": [
                    {
                        "name": "local-ads",
                        "category": "adblock",
                        "format": "domains",
                        "path": "custom.txt",
                    }
                ],
            }
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

            with (
                patch.object(
                    builder,
                    "PROGRESS_HEARTBEAT_SECONDS",
                    0.01,
                    create=True,
                ),
                redirect_stdout(output),
            ):
                build(
                    config=config,
                    base_directory=root,
                    output_directory=root / "output",
                    dns_validator=slow_validator,
                )

            self.assertIn(
                "[step 2/3 | 67%] DNS validation still running (",
                output.getvalue(),
            )

    def test_reports_build_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "custom.txt").write_text(
                "ads.example.com\n",
                encoding="utf-8",
            )
            config = {
                "sources": [
                    {
                        "name": "local-ads",
                        "category": "adblock",
                        "format": "domains",
                        "path": "custom.txt",
                    }
                ],
            }
            output = StringIO()

            with redirect_stdout(output):
                build(
                    config=config,
                    base_directory=root,
                    output_directory=root / "output",
                    skip_dns=True,
                )

            log = output.getvalue()
            self.assertIn(
                "Starting build: 3 total steps "
                "(1 source, DNS validation, 1 category output)",
                log,
            )
            self.assertIn(
                "[step 1/3 | 33%] [source 1/1] "
                "Processing local-ads (adblock, domains)",
                log,
            )
            self.assertIn(
                "[step 1/3 | 33%] [source 1/1] "
                "Parsed local-ads: 1 domain",
                log,
            )
            self.assertIn(
                "[step 2/3 | 67%] DNS validation skipped: "
                "retaining 1 unique domain",
                log,
            )
            self.assertIn(
                "[step 3/3 | 100%] [output 1/1] "
                "Writing adblock.txt: 1 domain",
                log,
            )
            self.assertIn(
                "[step 3/3 | 100%] Build complete in ",
                log,
            )

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
                "ads.example.com\nallowed.example.com",
            )
            self.assertEqual(
                (root / "output/social.txt").read_text(encoding="utf-8"),
                "local.example.com\nshared.example.com",
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
