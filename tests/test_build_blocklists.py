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
    def test_progress_quantity_pluralizes_domain(self) -> None:
        self.assertEqual(builder._quantity(2, "domain"), "2 domains")

    def test_stream_parser_accepts_one_shot_line_iterable(self) -> None:
        class OneShotLines:
            def __init__(self) -> None:
                self.iterated = False

            def __iter__(self):
                if self.iterated:
                    raise AssertionError("source was iterated more than once")
                self.iterated = True
                yield "ads.example.com\n"
                yield "allowed.example.com\n"

        entries: list[str] = []
        builder.parse_lines(
            OneShotLines(),
            emit=entries.append,
        )

        self.assertEqual(entries, ["ads.example.com", "allowed.example.com"])

    def test_domains_are_normalized(self) -> None:
        content = """
        # comment
        Example.COM
        *.example.com
        exact.example.com.
        not_a_domain
        """

        self.assertEqual(
            parse_content(content),
            {"example.com", "exact.example.com"},
        )

    def test_adblock_extracts_domain_rules(self) -> None:
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

        try:
            domains = parse_content(content, "adblock")
        except Exception as error:
            self.fail(f"adblock format was rejected: {error}")
        self.assertEqual(
            domains,
            {"ads.example.com", "metrics.example.com"},
        )

    def test_rpz_extracts_cname_root_records(self) -> None:
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

        try:
            domains = parse_content(textwrap.dedent(content), "rpz")
        except Exception as error:
            self.fail(f"RPZ format was rejected: {error}")
        self.assertEqual(
            domains,
            {"blocked.example.com", "exact.example.com"},
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
                "sources": {"domains": ["domains.txt"]},
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
            self.assertEqual(counts, 3)
            log = output.getvalue()
            self.assertIn(
                "[phase 3/4 | 54.0%] DNS batch 1/3 complete: "
                "processed 2/5 (40.0%), resolved 1, removed 1, "
                "pending dnsx 0",
                log,
            )
            self.assertIn(
                "[phase 3/4 | 90.0%] DNS batch 3/3 complete: "
                "processed 5/5 (100.0%), resolved 3, removed 2, "
                "pending dnsx 0",
                log,
            )

    def test_massdns_runs_a_and_aaaa_with_one_resolver_file(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            builder._initialize_database(connection)
            connection.execute(
                """
                INSERT INTO domains(domain)
                VALUES ('live.example')
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
                INSERT INTO domains(domain)
                VALUES (?)
                """,
                [
                    ("dead.example",),
                    ("wild.example",),
                    ("live.example",),
                    ("v6.example",),
                    ("private.example",),
                    ("multicast.example",),
                    ("missing.example",),
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

    def test_dnsx_rechecks_massdns_unknown_and_keeps_unresolved(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            builder._initialize_database(connection)
            connection.executemany(
                """
                INSERT INTO domains(domain)
                VALUES (?)
                """,
                [
                    ("dead.example",),
                    ("recovered.example",),
                    ("resolved.example",),
                    ("still-unknown.example",),
                    ("unknown.example",),
                ],
            )
            calls: list[tuple[str, str, list[str]]] = []
            dnsx_commands: list[list[str]] = []
            dnsx_batches: list[list[str]] = []
            dnsx_stdout: list[object] = []
            progress = StringIO()

            def complete_dns(command, **_kwargs) -> None:
                if command[0] == "/dnsx":
                    dnsx_commands.append(command)
                    dnsx_stdout.append(_kwargs.get("stdout"))
                    domains = Path(
                        command[command.index("-l") + 1]
                    ).read_text(encoding="utf-8").splitlines()
                    dnsx_batches.append(domains)
                    output = ""
                    if domains == ["unknown.example"]:
                        output = (
                            json.dumps(
                                {
                                    "host": "unknown.example",
                                    "a": ["93.184.216.34"],
                                    "status_code": "NOERROR",
                                }
                            )
                            + "\n"
                        )
                    Path(command[command.index("-o") + 1]).write_text(
                        output,
                        encoding="utf-8",
                    )
                    return

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
                    side_effect=lambda executable: {
                        "massdns": "/massdns",
                        "dnsx": "/dnsx",
                    }[executable],
                ),
                patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=complete_dns,
                ),
                patch.object(builder, "DNSX_BATCH_SIZE", 1),
                redirect_stdout(progress),
            ):
                builder._validate_dns_database(
                    connection,
                    {"resolvers": ["1.1.1.1", "8.8.8.8"]},
                    dnsx_progress_formatter=lambda fraction: (
                        f"[phase 4/4 | {90 + 10 * fraction:.1f}%]"
                    ),
                )
                connection.execute(
                    "CREATE TABLE removed(domain TEXT PRIMARY KEY) WITHOUT ROWID"
                )
                builder._remove_unresolved_domains(connection)

            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT domain FROM removed ORDER BY domain"
                    )
                ),
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
                dnsx_batches,
                [["still-unknown.example"], ["unknown.example"]],
            )
            self.assertEqual(len(dnsx_commands), 2)
            self.assertEqual(
                dnsx_stdout,
                [builder.subprocess.DEVNULL, builder.subprocess.DEVNULL],
            )
            dnsx_command = dnsx_commands[0]
            self.assertTrue(
                {
                    "-a",
                    "-aaaa",
                    "-json",
                    "-omit-raw",
                    "-silent",
                    "-duc",
                }.issubset(dnsx_command)
            )
            self.assertIn(
                "[phase 4/4 | 90.0%] dnsx fallback started: "
                "rechecking 2 domains",
                progress.getvalue(),
            )
            self.assertIn(
                "[phase 4/4 | 95.0%] dnsx batch 1/2 complete: "
                "processed 1/2 (50.0%), recovered 0, removed 0, unknown 1",
                progress.getvalue(),
            )
            self.assertIn(
                "[phase 4/4 | 100.0%] dnsx batch 2/2 complete: "
                "processed 2/2 (100.0%), recovered 1, removed 0, unknown 1",
                progress.getvalue(),
            )
            self.assertIn(
                "[phase 4/4 | 100.0%] dnsx fallback complete: "
                "recovered 1, removed 0, unknown 1 kept",
                progress.getvalue(),
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
                            "still-unknown.example",
                            "unknown.example",
                        ],
                    ),
                    (
                        "AAAA",
                        [
                            "recovered.example",
                            "still-unknown.example",
                            "unknown.example",
                        ],
                    ),
                    (
                        "A",
                        [
                            "recovered.example",
                            "still-unknown.example",
                            "unknown.example",
                        ],
                    ),
                    (
                        "AAAA",
                        ["still-unknown.example", "unknown.example"],
                    ),
                ],
            )

    def test_dnsx_classifies_addresses_negatives_and_unknown(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            builder._initialize_database(connection)
            connection.executemany(
                "INSERT INTO domains VALUES (?)",
                [
                    ("dead.example",),
                    ("nodata.example",),
                    ("private.example",),
                    ("transient.example",),
                    ("v4.example",),
                    ("v6.example",),
                ],
            )
            connection.execute(
                "INSERT INTO dns_unknown SELECT domain FROM domains"
            )
            counts = builder._store_dnsx_results(
                connection,
                [
                    '{"host":"v4.example","a":["93.184.216.34"]}\n',
                    '{"host":"v6.example","aaaa":['
                    '"2606:4700:4700::1111"]}\n',
                    '{"host":"private.example","a":["127.0.0.1"]}\n',
                    '{"host":"dead.example","status_code":"NXDOMAIN"}\n',
                    '{"host":"nodata.example","status_code":"NOERROR",'
                    '"a":[],"aaaa":[]}\n',
                    '{"host":"transient.example",'
                    '"status_code":"SERVFAIL"}\n',
                ],
            )
            connection.execute(
                "CREATE TABLE removed(domain TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            builder._remove_unresolved_domains(connection)

            self.assertEqual(counts, (2, 2))
            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT domain FROM dns_resolved ORDER BY domain"
                    )
                ),
                [("v4.example",), ("v6.example",)],
            )
            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT domain FROM removed ORDER BY domain"
                    )
                ),
                [("dead.example",), ("nodata.example",)],
            )

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
                "Starting build: 4 phases "
                "(download 0-10%, parse 10-30%, "
                "MassDNS 30-90%, dnsx 90-100%)",
                log,
            )
            self.assertIn(
                "[phase 1/4 | 0.0%] [download 1/1] "
                "Downloading memory://ads",
                log,
            )
            self.assertIn(
                "[phase 1/4 | 10.0%] [download 1/1] "
                "Downloaded memory://ads",
                log,
            )
            self.assertIn(
                "[phase 2/4 | 10.0%] [parse 1/1] "
                "Parsing memory://ads",
                log,
            )
            self.assertIn(
                "[phase 2/4 | 30.0%] [parse 1/1] "
                "Parsed memory://ads: 1 domain",
                log,
            )
            self.assertIn(
                "[phase 3/4 | 90.0%] MassDNS validation skipped: "
                "retaining 1 unique domain",
                log,
            )
            self.assertIn(
                "[phase 4/4 | 100.0%] dnsx fallback skipped",
                log,
            )
            self.assertIn(
                "[phase 4/4 | 100.0%] Writing blocklist.txt: 1 domain",
                log,
            )
            self.assertIn(
                "[phase 4/4 | 100.0%] Build complete in ",
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
                builder,
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
