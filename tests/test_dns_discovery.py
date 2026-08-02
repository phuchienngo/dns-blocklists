import json
import sqlite3
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import blocklist_builder.dns_discovery as builder
import blocklist_builder.storage as storage


class SubdomainRescueTest(unittest.TestCase):
    def test_preserves_successful_batches_when_a_later_batch_fails(
        self,
    ) -> None:
        with sqlite3.connect(":memory:") as connection:
            storage._initialize_database(connection)
            connection.executemany(
                "INSERT INTO domains VALUES (?)",
                [
                    ("ads.a.test",),
                    ("ads.b.test",),
                    ("ads.c.test",),
                ],
            )
            connection.execute(
                "INSERT INTO dns_nxdomain_candidates SELECT domain FROM domains"
            )
            subfinder_batches: list[list[str]] = []

            def complete_tools(command, **kwargs) -> None:
                if command[0] == "/subfinder":
                    roots = (
                        Path(command[command.index("-dL") + 1])
                        .read_text(encoding="utf-8")
                        .splitlines()
                    )
                    subfinder_batches.append(roots)
                    if roots == ["c.test"]:
                        kwargs["stderr"].write("provider unavailable\n")
                        kwargs["stderr"].flush()
                        raise builder.subprocess.CalledProcessError(7, command)
                    Path(command[command.index("-o") + 1]).write_text(
                        "live.ads.a.test\n",
                        encoding="utf-8",
                    )
                    return

                query_type = command[command.index("-t") + 1]
                output_path = Path(command[command.index("-w") + 1])
                answers = (
                    [{"type": "A", "data": "93.184.216.34"}]
                    if query_type == "A"
                    else []
                )
                output_path.write_text(
                    json.dumps(
                        {
                            "name": "live.ads.a.test",
                            "type": query_type,
                            "status": "NOERROR",
                            "data": {"answers": answers},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            progress = StringIO()
            with (
                patch.object(builder, "SUBFINDER_BATCH_SIZE", 2),
                patch.object(
                    builder.shutil,
                    "which",
                    side_effect=lambda executable: f"/{executable}",
                ),
                patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=complete_tools,
                ),
                redirect_stdout(progress),
            ):
                builder._rescue_nxdomain_domains(
                    connection,
                    {"resolvers": ["1.1.1.1"]},
                    builder.PublicSuffixList(["test"]),
                )

            self.assertEqual(
                subfinder_batches,
                [["a.test", "b.test"], ["c.test"]],
            )
            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT domain FROM dns_resolved "
                        "WHERE domain IN (SELECT domain FROM domains)"
                    )
                ),
                [("ads.a.test",)],
            )
            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT domain FROM dns_rescue_unknown ORDER BY domain"
                    )
                ),
                [("ads.b.test",), ("ads.c.test",)],
            )
            log = progress.getvalue()
            self.assertIn(
                "Subfinder batch 1/2 complete: processed 2/3 roots, "
                "found 1 subdomain",
                log,
            )
            self.assertIn(
                "Subfinder batch 2/2 failed (exit 7): provider unavailable; "
                "processed 3/3 roots",
                log,
            )

    def test_keeps_nxdomain_parent_when_any_discovered_child_resolves(
        self,
    ) -> None:
        with sqlite3.connect(":memory:") as connection:
            storage._initialize_database(connection)
            connection.executemany(
                "INSERT INTO domains VALUES (?)",
                [
                    ("ads.oppomobile.com",),
                    ("ads.example.com",),
                    ("ads.uncovered.net",),
                ],
            )
            connection.execute(
                "INSERT INTO dns_nxdomain_candidates SELECT domain FROM domains"
            )
            commands: list[list[str]] = []
            subfinder_roots: list[str] = []

            def complete_tools(command, **_kwargs) -> None:
                commands.append(command)
                if command[0] == "/subfinder":
                    subfinder_roots.extend(
                        Path(command[command.index("-dL") + 1])
                        .read_text(encoding="utf-8")
                        .splitlines()
                    )
                    Path(command[command.index("-o") + 1]).write_text(
                        "adx.ads.oppomobile.com\n"
                        "www.example.com\n"
                        "foreign.other.com\n",
                        encoding="utf-8",
                    )
                    return

                query_type = command[command.index("-t") + 1]
                domains = Path(command[-1]).read_text(
                    encoding="utf-8"
                ).splitlines()
                if (
                    command[0] == "/massdns"
                    and domains == ["adx.ads.oppomobile.com"]
                    and query_type == "A"
                ):
                    raise builder.subprocess.CalledProcessError(1, command)
                output_path = Path(command[command.index("-w") + 1])
                rows = []
                for domain in domains:
                    answers = []
                    if (
                        domain == "adx.ads.oppomobile.com"
                        and query_type == "AAAA"
                    ):
                        answers.append(
                            {
                                "type": "AAAA",
                                "data": "2606:4700:4700::1111",
                            }
                        )
                    rows.append(
                        json.dumps(
                            {
                                "name": domain,
                                "type": query_type,
                                "status": "NOERROR",
                                "data": {"answers": answers},
                            }
                        )
                    )
                output_path.write_text(
                    "\n".join(rows) + "\n", encoding="utf-8"
                )

            progress = StringIO()
            with (
                patch.object(
                    builder.shutil,
                    "which",
                    side_effect=lambda executable: f"/{executable}",
                ),
                patch.object(
                    builder.subprocess,
                    "run",
                    side_effect=complete_tools,
                ),
                redirect_stdout(progress),
            ):
                builder._rescue_nxdomain_domains(
                    connection,
                    {"resolvers": ["1.1.1.1", "8.8.8.8"]},
                    builder.PublicSuffixList(["com", "net"]),
                    progress_formatter=lambda fraction: (
                        f"[phase 4/6 | {70 + 15 * fraction:.1f}%]"
                    ),
                )
                connection.execute(
                    "CREATE TABLE removed(domain TEXT PRIMARY KEY) WITHOUT ROWID"
                )
                storage._remove_unresolved_domains(connection)

            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT domain FROM dns_resolved "
                        "WHERE domain IN (SELECT domain FROM domains)"
                    )
                ),
                [("ads.oppomobile.com",)],
            )
            self.assertEqual(
                list(connection.execute("SELECT domain FROM removed")),
                [("ads.example.com",)],
            )
            self.assertEqual(
                list(connection.execute("SELECT domain FROM dns_rescue_unknown")),
                [("ads.uncovered.net",)],
            )
            subfinder_command = commands[0]
            self.assertEqual(
                subfinder_roots,
                ["example.com", "oppomobile.com", "uncovered.net"],
            )
            self.assertTrue(
                {"-silent", "-duc"}.issubset(subfinder_command)
            )
            self.assertNotIn("-recursive", subfinder_command)
            self.assertIn(
                "Subfinder discovery complete: 2 subdomains found, "
                "2/3 roots covered",
                progress.getvalue(),
            )
            self.assertIn(
                "Subdomain rescue complete: 1 NXDOMAIN parent rescued, "
                "1 removed, 1 unknown kept",
                progress.getvalue(),
            )
