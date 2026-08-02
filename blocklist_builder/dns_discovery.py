from __future__ import annotations

import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from publicsuffix2 import PublicSuffixList

from blocklist_builder.dns_records import (
    store_massdns_results as _store_massdns_results,
)
from blocklist_builder.parsing import normalize_domain
from blocklist_builder.storage import atomic_write_domains as _atomic_write_domains

DNS_BATCH_SIZE = 10_000
DNS_PRIMARY_HASHMAP_SIZE = 800
SUBFINDER_MAX_TIME_MINUTES = 10


def _quantity(count: int, noun: str) -> str:
    if count == 1:
        return f"{count:,} {noun}"
    plural = f"{noun[:-1]}ies" if noun.endswith("y") else f"{noun}s"
    return f"{count:,} {plural}"


def _rescue_nxdomain_domains(
    connection: sqlite3.Connection,
    dns_config: dict[str, Any],
    public_suffixes: PublicSuffixList,
    *,
    progress_formatter: Callable[[float], str] | None = None,
) -> None:
    total = connection.execute(
        "SELECT COUNT(*) FROM dns_nxdomain_candidates"
    ).fetchone()[0]
    start_label = progress_formatter(0.0) if progress_formatter else ""
    if not total:
        print(
            f"{start_label + ' ' if start_label else ''}"
            "Subdomain rescue skipped: no NXDOMAIN parents",
            flush=True,
        )
        return

    connection.execute(
        """
        CREATE TEMP TABLE IF NOT EXISTS dns_retry_observations (
            domain TEXT NOT NULL,
            resolver TEXT NOT NULL,
            query_type TEXT NOT NULL,
            outcome TEXT NOT NULL,
            PRIMARY KEY (domain, resolver, query_type)
        ) WITHOUT ROWID
        """
    )
    candidate_roots: list[tuple[str, str]] = []
    for (domain,) in connection.execute(
        "SELECT domain FROM dns_nxdomain_candidates ORDER BY domain"
    ):
        root = public_suffixes.get_sld(domain, strict=True)
        if root:
            candidate_roots.append((domain, root))
        else:
            connection.execute(
                "INSERT OR IGNORE INTO dns_rescue_unknown VALUES (?)",
                (domain,),
            )
        if len(candidate_roots) >= 5000:
            connection.executemany(
                "INSERT OR IGNORE INTO dns_rescue_candidate_roots VALUES (?, ?)",
                candidate_roots,
            )
            candidate_roots.clear()
    if candidate_roots:
        connection.executemany(
            "INSERT OR IGNORE INTO dns_rescue_candidate_roots VALUES (?, ?)",
            candidate_roots,
        )

    root_count = connection.execute(
        "SELECT COUNT(DISTINCT root) FROM dns_rescue_candidate_roots"
    ).fetchone()[0]
    subfinder_executable = shutil.which("subfinder")
    if not subfinder_executable or not root_count:
        connection.execute(
            """
            INSERT OR IGNORE INTO dns_rescue_unknown
            SELECT domain FROM dns_nxdomain_candidates
            """
        )
        end_label = progress_formatter(1.0) if progress_formatter else ""
        reason = "subfinder executable not found" if root_count else "no roots"
        print(
            f"{end_label + ' ' if end_label else ''}"
            f"Subdomain rescue skipped: {reason}; "
            f"{_quantity(total, 'NXDOMAIN parent')} kept unknown",
            flush=True,
        )
        return

    command_timeout = int(dns_config.get("command_timeout_seconds", 3600))
    resolve_count = int(dns_config.get("resolve_count", 3))
    hashmap_size = int(
        dns_config.get("hashmap_size", DNS_PRIMARY_HASHMAP_SIZE)
    )
    massdns_executable = shutil.which(
        str(dns_config.get("executable", "massdns"))
    )
    if not massdns_executable:
        raise RuntimeError("massdns executable not found for subdomain rescue")

    print(
        f"{start_label + ' ' if start_label else ''}"
        f"Subfinder discovery started: checking "
        f"{_quantity(root_count, 'registrable root')} for "
        f"{_quantity(total, 'NXDOMAIN parent')}",
        flush=True,
    )
    with tempfile.TemporaryDirectory(
        prefix="dns-blocklists-subdomains-"
    ) as directory:
        temporary = Path(directory)
        roots_path = temporary / "roots.txt"
        subdomains_path = temporary / "subdomains.txt"
        subfinder_error_path = temporary / "subfinder.err"
        resolver_path = temporary / "resolvers.txt"
        input_path = temporary / "children.txt"
        output_path = temporary / "massdns.jsonl"
        massdns_error_path = temporary / "massdns.err"
        _atomic_write_domains(
            roots_path,
            connection.execute(
                """
                SELECT DISTINCT root
                FROM dns_rescue_candidate_roots
                ORDER BY root
                """
            ),
        )
        resolver_path.write_text(
            "".join(
                f"{resolver}\n" for resolver in dns_config["resolvers"]
            ),
            encoding="utf-8",
        )
        command = [
            subfinder_executable,
            "-dL",
            str(roots_path),
            "-silent",
            "-duc",
            "-max-time",
            str(SUBFINDER_MAX_TIME_MINUTES),
            "-o",
            str(subdomains_path),
        ]
        try:
            with subfinder_error_path.open("w", encoding="utf-8") as errors:
                subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=errors,
                    check=True,
                    timeout=command_timeout,
                )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            connection.execute(
                """
                INSERT OR IGNORE INTO dns_rescue_unknown
                SELECT domain FROM dns_nxdomain_candidates
                """
            )
            end_label = (
                progress_formatter(1.0) if progress_formatter else ""
            )
            print(
                f"{end_label + ' ' if end_label else ''}"
                "Subfinder discovery failed; all NXDOMAIN parents kept unknown",
                flush=True,
            )
            return

        discovered_rows: list[tuple[str, str]] = []
        if subdomains_path.is_file():
            with subdomains_path.open(encoding="utf-8") as subdomains:
                for raw_line in subdomains:
                    domain = normalize_domain(raw_line)
                    if not domain:
                        continue
                    root = public_suffixes.get_sld(domain, strict=True)
                    if not root:
                        continue
                    discovered_rows.append((domain, root))
                    if len(discovered_rows) >= 5000:
                        connection.executemany(
                            """
                            INSERT OR IGNORE INTO dns_discovered_hosts
                            VALUES (?, ?)
                            """,
                            discovered_rows,
                        )
                        discovered_rows.clear()
        if discovered_rows:
            connection.executemany(
                "INSERT OR IGNORE INTO dns_discovered_hosts VALUES (?, ?)",
                discovered_rows,
            )
        connection.execute(
            """
            DELETE FROM dns_discovered_hosts
            WHERE NOT EXISTS (
                SELECT 1
                FROM dns_rescue_candidate_roots AS candidate
                WHERE candidate.root = dns_discovered_hosts.root
            )
            """
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO dns_discovered_roots(root)
            SELECT DISTINCT root FROM dns_discovered_hosts
            """
        )
        discovered_count = connection.execute(
            "SELECT COUNT(*) FROM dns_discovered_hosts"
        ).fetchone()[0]
        covered_count = connection.execute(
            "SELECT COUNT(*) FROM dns_discovered_roots"
        ).fetchone()[0]
        discovery_label = (
            progress_formatter(0.3) if progress_formatter else ""
        )
        print(
            f"{discovery_label + ' ' if discovery_label else ''}"
            f"Subfinder discovery complete: "
            f"{_quantity(discovered_count, 'subdomain')} found, "
            f"{covered_count:,}/{root_count:,} roots covered",
            flush=True,
        )

        connection.execute(
            """
            INSERT OR IGNORE INTO dns_rescue_unknown(domain)
            SELECT candidate.domain
            FROM dns_rescue_candidate_roots AS candidate
            WHERE NOT EXISTS (
                SELECT 1
                FROM dns_discovered_roots AS discovered
                WHERE discovered.root = candidate.root
            )
            """
        )
        connection.execute(
            """
            WITH RECURSIVE ancestors(child, parent) AS (
                SELECT
                    domain,
                    SUBSTR(domain, INSTR(domain, '.') + 1)
                FROM dns_discovered_hosts
                WHERE INSTR(domain, '.') > 0

                UNION ALL

                SELECT
                    child,
                    SUBSTR(parent, INSTR(parent, '.') + 1)
                FROM ancestors
                WHERE INSTR(parent, '.') > 0
            )
            INSERT OR IGNORE INTO dns_discovered_children(child, parent)
            SELECT ancestor.child, candidate.domain
            FROM ancestors AS ancestor
            JOIN dns_nxdomain_candidates AS candidate
              ON candidate.domain = ancestor.parent
            """
        )

        child_count = connection.execute(
            "SELECT COUNT(DISTINCT child) FROM dns_discovered_children"
        ).fetchone()[0]
        child_cursor = connection.execute(
            "SELECT DISTINCT child FROM dns_discovered_children ORDER BY child"
        )
        processed = 0
        total_batches = (
            child_count + DNS_BATCH_SIZE - 1
        ) // DNS_BATCH_SIZE
        batch_index = 0
        while rows := child_cursor.fetchmany(DNS_BATCH_SIZE):
            batch_index += 1
            _atomic_write_domains(input_path, rows)
            connection.execute("DELETE FROM dns_retry_observations")
            for query_type in ("A", "AAAA"):
                command = [
                    massdns_executable,
                    "-r",
                    str(resolver_path),
                    "-t",
                    query_type,
                    "-o",
                    "Je",
                    "-q",
                    "-c",
                    str(resolve_count),
                    "-s",
                    str(hashmap_size),
                    "--verify-ip",
                    "-w",
                    str(output_path),
                    str(input_path),
                ]
                try:
                    with massdns_error_path.open(
                        "w", encoding="utf-8"
                    ) as errors:
                        subprocess.run(
                            command,
                            stderr=errors,
                            check=True,
                            timeout=command_timeout,
                        )
                except (
                    subprocess.CalledProcessError,
                    subprocess.TimeoutExpired,
                ):
                    connection.executemany(
                        """
                        INSERT OR IGNORE INTO dns_rescue_unknown(domain)
                        SELECT parent
                        FROM dns_discovered_children
                        WHERE child = ?
                        """,
                        rows,
                    )
                    continue
                with output_path.open(encoding="utf-8") as output:
                    _store_massdns_results(
                        connection,
                        output,
                        resolver="subdomain-rescue",
                        query_type=query_type,
                    )

            connection.executemany(
                "INSERT OR IGNORE INTO dns_rescue_batch VALUES (?)",
                rows,
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO dns_rescue_unknown(domain)
                SELECT DISTINCT mapping.parent
                FROM dns_discovered_children AS mapping
                JOIN dns_rescue_batch AS batch
                  ON batch.child = mapping.child
                WHERE NOT EXISTS (
                    SELECT 1 FROM dns_resolved AS resolved
                    WHERE resolved.domain = mapping.child
                )
                  AND NOT (
                      EXISTS (
                          SELECT 1 FROM dns_retry_observations AS observation
                          WHERE observation.domain = mapping.child
                            AND observation.outcome = 'nxdomain'
                      )
                      OR (
                          EXISTS (
                              SELECT 1
                              FROM dns_retry_observations AS observation
                              WHERE observation.domain = mapping.child
                                AND observation.query_type = 'A'
                                AND observation.outcome = 'nodata'
                          )
                          AND EXISTS (
                              SELECT 1
                              FROM dns_retry_observations AS observation
                              WHERE observation.domain = mapping.child
                                AND observation.query_type = 'AAAA'
                                AND observation.outcome = 'nodata'
                          )
                      )
                  )
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO dns_resolved(domain)
                SELECT DISTINCT mapping.parent
                FROM dns_discovered_children AS mapping
                JOIN dns_rescue_batch AS batch
                  ON batch.child = mapping.child
                WHERE EXISTS (
                    SELECT 1 FROM dns_resolved AS resolved
                    WHERE resolved.domain = mapping.child
                )
                """
            )
            connection.execute("DELETE FROM dns_rescue_batch")
            processed += len(rows)
            fraction = 0.3 + 0.7 * processed / child_count
            label = progress_formatter(fraction) if progress_formatter else ""
            print(
                f"{label + ' ' if label else ''}"
                f"Subdomain validation batch {batch_index}/{total_batches} "
                f"complete: processed {processed:,}/{child_count:,} children",
                flush=True,
            )

    connection.execute(
        """
        DELETE FROM dns_rescue_unknown
        WHERE EXISTS (
            SELECT 1 FROM dns_resolved AS resolved
            WHERE resolved.domain = dns_rescue_unknown.domain
        )
        """
    )
    rescued = connection.execute(
        """
        SELECT COUNT(*)
        FROM dns_nxdomain_candidates AS candidate
        WHERE EXISTS (
            SELECT 1 FROM dns_resolved AS resolved
            WHERE resolved.domain = candidate.domain
        )
        """
    ).fetchone()[0]
    unknown = connection.execute(
        "SELECT COUNT(*) FROM dns_rescue_unknown"
    ).fetchone()[0]
    removed = total - rescued - unknown
    end_label = progress_formatter(1.0) if progress_formatter else ""
    print(
        f"{end_label + ' ' if end_label else ''}"
        f"Subdomain rescue complete: "
        f"{_quantity(rescued, 'NXDOMAIN parent')} rescued, "
        f"{removed:,} removed, {unknown:,} unknown kept",
        flush=True,
    )


rescue_nxdomain_domains = _rescue_nxdomain_domains

