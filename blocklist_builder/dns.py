from __future__ import annotations

import shutil
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from publicsuffix2 import PublicSuffixList

from blocklist_builder.dns_discovery import (
    rescue_nxdomain_domains as _rescue_nxdomain_domains,
)
from blocklist_builder.dns_records import (
    check_extended_domain as _check_extended_domain,
    store_dnsx_results as _store_dnsx_results,
    store_massdns_results as _store_massdns_results,
    validate_extended_dns_database as _validate_extended_dns_database,
)

DNS_BATCH_SIZE = 10_000
DNSX_BATCH_SIZE = 2_000
DNS_PRIMARY_HASHMAP_SIZE = 800
DNS_RETRY_HASHMAP_SIZE = 200


def _quantity(count: int, noun: str) -> str:
    if count == 1:
        return f"{count:,} {noun}"
    plural = f"{noun[:-1]}ies" if noun.endswith("y") else f"{noun}s"
    return f"{count:,} {plural}"


def _validate_dns_database(
    connection: sqlite3.Connection,
    dns_config: dict[str, Any],
    *,
    public_suffixes: PublicSuffixList | None = None,
    progress_formatter: Callable[[float], str] | None = None,
    rescue_progress_formatter: Callable[[float], str] | None = None,
    extended_progress_formatter: Callable[[float], str] | None = None,
    dnsx_progress_formatter: Callable[[float], str] | None = None,
) -> None:
    resolvers = dns_config.get("resolvers")
    if not isinstance(resolvers, list) or not resolvers:
        raise ValueError("dns.resolvers must contain at least one resolver")
    command_timeout = int(dns_config.get("command_timeout_seconds", 3600))
    hashmap_size = int(
        dns_config.get("hashmap_size", DNS_PRIMARY_HASHMAP_SIZE)
    )
    resolve_count = int(dns_config.get("resolve_count", 3))
    executable = str(dns_config.get("executable", "massdns"))
    resolved_executable = shutil.which(executable)
    if not resolved_executable:
        raise RuntimeError(f"massdns executable not found: {executable}")
    dnsx_executable = shutil.which("dnsx")
    if not dnsx_executable:
        raise RuntimeError("dnsx executable not found: dnsx")

    total_domains = connection.execute(
        "SELECT COUNT(*) FROM (SELECT domain FROM domains GROUP BY domain)"
    ).fetchone()[0]
    total_batches = (
        total_domains + DNS_BATCH_SIZE - 1
    ) // DNS_BATCH_SIZE
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_resolved (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID
        """
    )
    connection.executescript(
        """
        CREATE TEMP TABLE dns_batch (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID;
        CREATE TEMP TABLE dns_phase (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID;
        CREATE TEMP TABLE dns_retry_observations (
            domain TEXT NOT NULL,
            resolver TEXT NOT NULL,
            query_type TEXT NOT NULL,
            outcome TEXT NOT NULL,
            PRIMARY KEY (domain, resolver, query_type)
        ) WITHOUT ROWID;
        CREATE TEMP VIEW dns_phase_negative AS
        SELECT phase.domain
        FROM dns_phase AS phase
        WHERE NOT EXISTS (
            SELECT 1
            FROM dns_resolved AS resolved
            WHERE resolved.domain = phase.domain
        )
          AND (
              EXISTS (
                  SELECT 1
                  FROM dns_retry_observations AS observation
                  WHERE observation.domain = phase.domain
                    AND observation.outcome = 'nxdomain'
              )
              OR (
                  EXISTS (
                      SELECT 1
                      FROM dns_retry_observations AS observation
                      WHERE observation.domain = phase.domain
                        AND observation.query_type = 'A'
                        AND observation.outcome = 'nodata'
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM dns_retry_observations AS observation
                      WHERE observation.domain = phase.domain
                        AND observation.query_type = 'AAAA'
                        AND observation.outcome = 'nodata'
                  )
              )
          );
        CREATE TEMP VIEW dns_phase_nodata AS
        SELECT phase.domain
        FROM dns_phase AS phase
        WHERE NOT EXISTS (
            SELECT 1
            FROM dns_resolved AS resolved
            WHERE resolved.domain = phase.domain
        )
          AND EXISTS (
              SELECT 1
              FROM dns_retry_observations AS observation
              WHERE observation.domain = phase.domain
                AND observation.query_type = 'A'
                AND observation.outcome = 'nodata'
          )
          AND EXISTS (
              SELECT 1
              FROM dns_retry_observations AS observation
              WHERE observation.domain = phase.domain
                AND observation.query_type = 'AAAA'
                AND observation.outcome = 'nodata'
          );
        CREATE TEMP VIEW dns_phase_nxdomain AS
        SELECT phase.domain
        FROM dns_phase AS phase
        WHERE NOT EXISTS (
            SELECT 1
            FROM dns_resolved AS resolved
            WHERE resolved.domain = phase.domain
        )
          AND EXISTS (
              SELECT 1
              FROM dns_retry_observations AS observation
              WHERE observation.domain = phase.domain
                AND observation.outcome = 'nxdomain'
          );
        """
    )

    with tempfile.TemporaryDirectory(prefix="dns-blocklists-") as directory:
        temporary = Path(directory)
        input_path = temporary / "domains.txt"
        resolver_path = temporary / "resolvers.txt"
        output_path = temporary / "massdns.jsonl"
        error_path = temporary / "massdns.err"
        resolver_path.write_text(
            "".join(f"{resolver}\n" for resolver in resolvers),
            encoding="utf-8",
        )
        domain_cursor = connection.execute(
            """
            SELECT domain
            FROM domains
            GROUP BY domain
            ORDER BY domain
            """
        )
        processed_count = 0
        resolved_count = 0
        unknown_count = 0
        removed_count = 0
        rescue_count = 0
        extended_count = 0
        started_at = time.monotonic()
        batch_index = 0
        while batch := domain_cursor.fetchmany(DNS_BATCH_SIZE):
            batch_index += 1
            connection.execute("DELETE FROM dns_batch")
            connection.executemany(
                "INSERT INTO dns_batch VALUES (?)",
                batch,
            )

            def run_massdns(
                *,
                query_type: str,
                active_hashmap_size: int,
            ) -> None:
                command = [
                    resolved_executable,
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
                    str(active_hashmap_size),
                    "--verify-ip",
                    "-w",
                    str(output_path),
                    str(input_path),
                ]
                with error_path.open("w", encoding="utf-8") as errors:
                    try:
                        subprocess.run(
                            command,
                            stderr=errors,
                            check=True,
                            timeout=command_timeout,
                        )
                    except (
                        subprocess.CalledProcessError,
                        subprocess.TimeoutExpired,
                    ) as error:
                        raise RuntimeError(
                            f"massdns {query_type} failed on batch "
                            f"{batch_index}/{total_batches}"
                        ) from error

                with output_path.open(encoding="utf-8") as output:
                    _store_massdns_results(
                        connection,
                        output,
                        resolver="pool",
                        query_type=query_type,
                    )

            def write_input(rows: Iterable[tuple[str]]) -> None:
                with input_path.open("w", encoding="utf-8") as input_file:
                    for (domain,) in rows:
                        input_file.write(f"{domain}\n")

            def run_phase(
                rows: list[tuple[str]],
                active_hashmap_size: int,
            ) -> tuple[int, list[tuple[str]]]:
                connection.execute("DELETE FROM dns_phase")
                connection.execute("DELETE FROM dns_retry_observations")
                connection.executemany(
                    "INSERT INTO dns_phase VALUES (?)",
                    rows,
                )
                write_input(rows)
                run_massdns(
                    query_type="A",
                    active_hashmap_size=active_hashmap_size,
                )

                aaaa_rows = list(
                    connection.execute(
                        """
                        SELECT phase.domain
                        FROM dns_phase AS phase
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM dns_resolved AS resolved
                            WHERE resolved.domain = phase.domain
                        )
                          AND NOT EXISTS (
                              SELECT 1
                              FROM dns_retry_observations AS observation
                              WHERE observation.domain = phase.domain
                                AND observation.query_type = 'A'
                                AND observation.outcome = 'nxdomain'
                          )
                        ORDER BY phase.domain
                        """
                    )
                )
                if aaaa_rows:
                    write_input(aaaa_rows)
                    run_massdns(
                        query_type="AAAA",
                        active_hashmap_size=active_hashmap_size,
                    )

                connection.execute(
                    """
                    INSERT OR IGNORE INTO dns_extended_candidates(domain)
                    SELECT domain FROM dns_phase_nodata
                    """
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO dns_nxdomain_candidates(domain)
                    SELECT domain FROM dns_phase_nxdomain
                    """
                )

                negative_count = connection.execute(
                    "SELECT COUNT(*) FROM dns_phase_negative"
                ).fetchone()[0]
                unresolved_rows = list(
                    connection.execute(
                        """
                        SELECT phase.domain
                        FROM dns_phase AS phase
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM dns_resolved AS resolved
                            WHERE resolved.domain = phase.domain
                        )
                          AND NOT EXISTS (
                              SELECT 1
                              FROM dns_phase_negative AS negative
                              WHERE negative.domain = phase.domain
                          )
                        ORDER BY phase.domain
                        """
                    )
                )
                return negative_count, unresolved_rows

            primary_removed, retry_domains = run_phase(
                batch,
                hashmap_size,
            )
            retry_removed = 0
            final_unknown: list[tuple[str]] = []
            if retry_domains:
                retry_removed, final_unknown = run_phase(
                    retry_domains,
                    DNS_RETRY_HASHMAP_SIZE,
                )
            if final_unknown:
                connection.executemany(
                    "INSERT OR IGNORE INTO dns_unknown VALUES (?)",
                    final_unknown,
                )

            batch_resolved = connection.execute(
                """
                SELECT COUNT(*)
                FROM dns_batch AS batch
                WHERE EXISTS (
                    SELECT 1
                    FROM dns_resolved AS resolved
                    WHERE resolved.domain = batch.domain
                )
                """
            ).fetchone()[0]
            batch_extended = connection.execute(
                """
                SELECT COUNT(*)
                FROM dns_batch AS batch
                WHERE EXISTS (
                    SELECT 1
                    FROM dns_extended_candidates AS candidate
                    WHERE candidate.domain = batch.domain
                )
                """
            ).fetchone()[0]
            batch_rescue = connection.execute(
                """
                SELECT COUNT(*)
                FROM dns_batch AS batch
                WHERE EXISTS (
                    SELECT 1
                    FROM dns_nxdomain_candidates AS candidate
                    WHERE candidate.domain = batch.domain
                )
                """
            ).fetchone()[0]
            batch_removed = (
                primary_removed
                + retry_removed
                - batch_extended
                - batch_rescue
            )
            batch_unknown = len(final_unknown)
            processed_count += len(batch)
            resolved_count += batch_resolved
            unknown_count += batch_unknown
            removed_count += batch_removed
            rescue_count += batch_rescue
            extended_count += batch_extended
            percentage = processed_count / total_domains * 100
            current_progress_label = (
                progress_formatter(processed_count / total_domains)
                if progress_formatter is not None
                else ""
            )
            prefix = (
                f"{current_progress_label} "
                if current_progress_label
                else ""
            )
            print(
                f"{prefix}DNS batch {batch_index}/{total_batches} complete: "
                f"processed {processed_count:,}/{total_domains:,} "
                f"({percentage:.1f}%), resolved {resolved_count:,}, "
                f"removed {removed_count:,}, "
                f"pending rescue {rescue_count:,}, "
                f"pending extended {extended_count:,}, "
                f"pending dnsx {unknown_count:,}, "
                f"elapsed {time.monotonic() - started_at:.0f}s",
                flush=True,
            )

        _rescue_nxdomain_domains(
            connection,
            dns_config,
            public_suffixes or PublicSuffixList(),
            progress_formatter=rescue_progress_formatter,
        )
        _validate_extended_dns_database(
            connection,
            dns_config,
            progress_formatter=extended_progress_formatter,
        )

        pending_count = connection.execute(
            "SELECT COUNT(*) FROM dns_unknown"
        ).fetchone()[0]
        if pending_count:
            dnsx_output_path = temporary / "dnsx.jsonl"
            dnsx_error_path = temporary / "dnsx.err"
            dnsx_start_label = (
                dnsx_progress_formatter(0.0)
                if dnsx_progress_formatter is not None
                else ""
            )
            print(
                f"{dnsx_start_label + ' ' if dnsx_start_label else ''}"
                f"dnsx fallback started: rechecking "
                f"{_quantity(pending_count, 'domain')}",
                flush=True,
            )
            total_dnsx_batches = (
                pending_count + DNSX_BATCH_SIZE - 1
            ) // DNSX_BATCH_SIZE
            dnsx_cursor = connection.execute(
                "SELECT domain FROM dns_unknown ORDER BY domain"
            )
            dnsx_processed = 0
            recovered_count = 0
            dnsx_removed_count = 0
            dnsx_batch_index = 0
            while dnsx_batch := dnsx_cursor.fetchmany(DNSX_BATCH_SIZE):
                dnsx_batch_index += 1
                write_input(dnsx_batch)
                dnsx_output_path.write_text("", encoding="utf-8")
                command = [
                    dnsx_executable,
                    "-l",
                    str(input_path),
                    "-a",
                    "-aaaa",
                    "-json",
                    "-omit-raw",
                    "-silent",
                    "-retry",
                    "3",
                    "-r",
                    str(resolver_path),
                    "-duc",
                    "-o",
                    str(dnsx_output_path),
                ]
                with dnsx_error_path.open("w", encoding="utf-8") as errors:
                    try:
                        subprocess.run(
                            command,
                            stdout=subprocess.DEVNULL,
                            stderr=errors,
                            check=True,
                            timeout=command_timeout,
                        )
                    except (
                        subprocess.CalledProcessError,
                        subprocess.TimeoutExpired,
                    ) as error:
                        raise RuntimeError(
                            f"dnsx failed on batch {dnsx_batch_index}/"
                            f"{total_dnsx_batches}"
                        ) from error
                with dnsx_output_path.open(encoding="utf-8") as output:
                    batch_recovered, batch_removed = _store_dnsx_results(
                        connection,
                        output,
                    )
                    recovered_count += batch_recovered
                    dnsx_removed_count += batch_removed
                dnsx_processed += len(dnsx_batch)
                dnsx_progress_label = (
                    dnsx_progress_formatter(
                        dnsx_processed / pending_count
                    )
                    if dnsx_progress_formatter is not None
                    else ""
                )
                print(
                    f"{dnsx_progress_label + ' ' if dnsx_progress_label else ''}"
                    f"dnsx batch {dnsx_batch_index}/"
                    f"{total_dnsx_batches} complete: processed "
                    f"{dnsx_processed:,}/{pending_count:,} "
                    f"({dnsx_processed / pending_count * 100:.1f}%), "
                    f"recovered {recovered_count:,}, removed "
                    f"{dnsx_removed_count:,}, unknown "
                    f"{dnsx_processed - recovered_count - dnsx_removed_count:,}",
                    flush=True,
                )
            dnsx_end_label = (
                dnsx_progress_formatter(1.0)
                if dnsx_progress_formatter is not None
                else ""
            )
            print(
                f"{dnsx_end_label + ' ' if dnsx_end_label else ''}"
                f"dnsx fallback complete: recovered {recovered_count:,}, "
                f"removed {dnsx_removed_count:,}, unknown "
                f"{pending_count - recovered_count - dnsx_removed_count:,} "
                "kept",
                flush=True,
            )
        else:
            dnsx_end_label = (
                dnsx_progress_formatter(1.0)
                if dnsx_progress_formatter is not None
                else ""
            )
            print(
                f"{dnsx_end_label + ' ' if dnsx_end_label else ''}"
                "dnsx fallback skipped: no unknown domains",
                flush=True,
            )


store_massdns_results = _store_massdns_results
store_dnsx_results = _store_dnsx_results
check_extended_domain = _check_extended_domain
validate_extended_dns_database = _validate_extended_dns_database
rescue_nxdomain_domains = _rescue_nxdomain_domains
validate_dns_database = _validate_dns_database
