import asyncio
import sqlite3
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

import dns.exception
import dns.resolver
import dns.rrset

import blocklist_builder.dns_records as builder
import blocklist_builder.storage as storage


class ExtendedDnsClassificationTest(unittest.IsolatedAsyncioTestCase):
    class Resolver:
        def __init__(self, answers):
            self.answers = answers
            self.queries: list[tuple[str, str]] = []

        async def resolve(self, name, rdtype, **_kwargs):
            key = (str(name).rstrip("."), str(rdtype))
            self.queries.append(key)
            answer = self.answers.get(key, [])
            if isinstance(answer, Exception):
                raise answer
            return answer

    @staticmethod
    def rrset(owner: str, record_type: str, *records: str):
        return dns.rrset.from_text(
            f"{owner}.",
            300,
            "IN",
            record_type,
            *records,
        )

    async def test_follows_cname_to_global_address(self) -> None:
        resolver = self.Resolver(
            {
                ("tracker.example", "CNAME"): self.rrset(
                    "tracker.example", "CNAME", "edge.example."
                ),
                ("edge.example", "A"): self.rrset(
                    "edge.example", "A", "93.184.216.34"
                ),
            }
        )

        result = await builder._check_extended_domain(
            "tracker.example", resolver
        )

        self.assertEqual(result, ("resolved", "cname"))

    async def test_follows_https_alias_mode(self) -> None:
        resolver = self.Resolver(
            {
                ("tracker.example", "HTTPS"): self.rrset(
                    "tracker.example", "HTTPS", "0 service.example."
                ),
                ("service.example", "AAAA"): self.rrset(
                    "service.example",
                    "AAAA",
                    "2606:4700:4700::1111",
                ),
            }
        )

        result = await builder._check_extended_domain(
            "tracker.example", resolver
        )

        self.assertEqual(result, ("resolved", "https"))

    async def test_accepts_only_global_https_ip_hints(self) -> None:
        global_resolver = self.Resolver(
            {
                ("tracker.example", "HTTPS"): self.rrset(
                    "tracker.example",
                    "HTTPS",
                    '1 . ipv4hint="93.184.216.34"',
                ),
            }
        )
        private_resolver = self.Resolver(
            {
                ("tracker.example", "HTTPS"): self.rrset(
                    "tracker.example",
                    "HTTPS",
                    '1 . ipv4hint="127.0.0.1"',
                ),
            }
        )

        self.assertEqual(
            await builder._check_extended_domain(
                "tracker.example", global_resolver
            ),
            ("resolved", "https-hint"),
        )
        self.assertEqual(
            await builder._check_extended_domain(
                "tracker.example", private_resolver
            ),
            ("negative", None),
        )

    async def test_keeps_unknown_mandatory_https_parameters_unknown(self) -> None:
        resolver = self.Resolver(
            {
                ("tracker.example", "HTTPS"): self.rrset(
                    "tracker.example",
                    "HTTPS",
                    '1 . mandatory=key65400 key65400="value"',
                ),
            }
        )

        self.assertEqual(
            await builder._check_extended_domain("tracker.example", resolver),
            ("unknown", None),
        )

    async def test_keeps_alias_loops_and_transient_errors_unknown(self) -> None:
        loop_resolver = self.Resolver(
            {
                ("a.example", "CNAME"): self.rrset(
                    "a.example", "CNAME", "b.example."
                ),
                ("b.example", "CNAME"): self.rrset(
                    "b.example", "CNAME", "a.example."
                ),
            }
        )
        transient_resolver = self.Resolver(
            {
                ("tracker.example", "CNAME"): dns.resolver.NoNameservers(),
                ("tracker.example", "HTTPS"): dns.resolver.NoNameservers(),
            }
        )
        malformed_resolver = self.Resolver(
            {
                ("tracker.example", "CNAME"): dns.exception.FormError(),
                ("tracker.example", "HTTPS"): dns.exception.FormError(),
            }
        )

        self.assertEqual(
            await builder._check_extended_domain("a.example", loop_resolver),
            ("unknown", None),
        )
        self.assertEqual(
            await builder._check_extended_domain(
                "tracker.example", transient_resolver
            ),
            ("unknown", None),
        )
        self.assertEqual(
            await builder._check_extended_domain(
                "tracker.example", malformed_resolver
            ),
            ("unknown", None),
        )

    def test_extended_validation_streams_results_into_dns_tables(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            storage._initialize_database(connection)
            connection.executemany(
                "INSERT INTO dns_extended_candidates VALUES (?)",
                [
                    ("cname.example",),
                    ("dead.example",),
                    ("hint.example",),
                    ("https.example",),
                    ("transient.example",),
                ],
            )
            connection.execute(
                "INSERT INTO domains SELECT domain FROM dns_extended_candidates"
            )
            outcomes = {
                "cname.example": ("resolved", "cname"),
                "dead.example": ("negative", None),
                "hint.example": ("resolved", "https-hint"),
                "https.example": ("resolved", "https"),
                "transient.example": ("unknown", None),
            }

            async def check(domain, _resolver, **_kwargs):
                await asyncio.sleep(0)
                return outcomes[domain]

            progress = StringIO()
            with (
                patch.object(builder, "DNS_EXTENDED_BATCH_SIZE", 2),
                patch.object(builder, "_check_extended_domain", check),
                redirect_stdout(progress),
            ):
                builder._validate_extended_dns_database(
                    connection,
                    {"resolvers": ["1.1.1.1", "8.8.8.8"]},
                    progress_formatter=lambda fraction: (
                        f"[phase 5/6 | {85 + 10 * fraction:.1f}%]"
                    ),
                )
                connection.execute(
                    "CREATE TABLE removed(domain TEXT PRIMARY KEY) WITHOUT ROWID"
                )
                storage._remove_unresolved_domains(connection)

            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT domain FROM dns_resolved ORDER BY domain"
                    )
                ),
                [
                    ("cname.example",),
                    ("hint.example",),
                    ("https.example",),
                ],
            )
            self.assertEqual(
                list(
                    connection.execute(
                        "SELECT domain FROM dns_extended_unknown"
                    )
                ),
                [("transient.example",)],
            )
            self.assertEqual(
                list(connection.execute("SELECT domain FROM removed")),
                [("dead.example",)],
            )
            log = progress.getvalue()
            self.assertIn(
                "[phase 5/6 | 85.0%] Extended DNS started: "
                "checking 5 domains",
                log,
            )
            self.assertIn(
                "[phase 5/6 | 89.0%] Extended DNS batch 1/3 complete: "
                "processed 2/5 (40.0%)",
                log,
            )
            self.assertIn(
                "[phase 5/6 | 95.0%] Extended DNS complete: "
                "CNAME 1, HTTPS 1, HTTPS hints 1, removed 1, "
                "unknown 1 kept",
                log,
            )

