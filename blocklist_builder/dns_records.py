from __future__ import annotations

import asyncio
import ipaddress
import json
import sqlite3
from collections.abc import Callable, Iterable
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from blocklist_builder.parsing import normalize_domain

DNS_EXTENDED_BATCH_SIZE = 1_000
DNS_EXTENDED_CONCURRENCY = 200
DNS_EXTENDED_TIMEOUT_SECONDS = 3.0
DNS_EXTENDED_LIFETIME_SECONDS = 6.0
DNS_MAX_ALIAS_DEPTH = 8
ExtendedDnsResult = tuple[str, str | None]


def _quantity(count: int, noun: str) -> str:
    if count == 1:
        return f"{count:,} {noun}"
    plural = f"{noun[:-1]}ies" if noun.endswith("y") else f"{noun}s"
    return f"{count:,} {plural}"


def _store_massdns_results(
    connection: sqlite3.Connection,
    lines: Iterable[str],
    *,
    resolver: str | None = None,
    query_type: str | None = None,
) -> int:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_resolved (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID
        """
    )
    resolved_changes = 0
    rows: list[tuple[str]] = []
    observations: list[tuple[str, str, str, str]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
            domain = normalize_domain(payload["name"])
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError(
                f"Invalid MassDNS JSON on line {line_number}"
            ) from error
        if not domain:
            continue
        data = payload.get("data") or {}
        if not isinstance(data, dict):
            raise ValueError(
                f"Invalid MassDNS answer on line {line_number}"
            )
        answers = data.get("answers") or []
        if not isinstance(answers, list):
            raise ValueError(
                f"Invalid MassDNS answer on line {line_number}"
            )
        has_address = False
        for answer in answers:
            if not isinstance(answer, dict):
                raise ValueError(
                    f"Invalid MassDNS answer on line {line_number}"
                )
            record_type = answer.get("type")
            if record_type not in {"A", "AAAA"}:
                continue
            try:
                address = ipaddress.ip_address(answer["data"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(
                    f"Invalid MassDNS address on line {line_number}"
                ) from error
            if (
                (record_type == "A" and address.version == 4)
                or (record_type == "AAAA" and address.version == 6)
            ) and address.is_global and not address.is_multicast:
                has_address = True
                break
        if has_address:
            rows.append((domain,))
        if resolver is not None and query_type is not None:
            status = payload.get("status")
            if has_address:
                outcome = "resolved"
            elif status == "NXDOMAIN":
                outcome = "nxdomain"
            elif status == "NOERROR":
                outcome = "nodata"
            else:
                outcome = "unknown"
            observations.append(
                (domain, resolver, query_type, outcome)
            )
        if len(rows) >= 5000:
            changes_before = connection.total_changes
            connection.executemany(
                "INSERT OR IGNORE INTO dns_resolved VALUES (?)",
                rows,
            )
            resolved_changes += connection.total_changes - changes_before
            rows.clear()
        if len(observations) >= 5000:
            connection.executemany(
                """
                INSERT OR REPLACE INTO dns_retry_observations
                VALUES (?, ?, ?, ?)
                """,
                observations,
            )
            observations.clear()
    if rows:
        changes_before = connection.total_changes
        connection.executemany(
            "INSERT OR IGNORE INTO dns_resolved VALUES (?)",
            rows,
        )
        resolved_changes += connection.total_changes - changes_before
    if observations:
        connection.executemany(
            """
            INSERT OR REPLACE INTO dns_retry_observations
            VALUES (?, ?, ?, ?)
            """,
            observations,
        )
    return resolved_changes


def _store_dnsx_results(
    connection: sqlite3.Connection,
    lines: Iterable[str],
) -> tuple[int, int]:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_resolved (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID
        """
    )
    resolved_changes = 0
    negative_changes = 0
    rows: list[tuple[str]] = []
    negative_rows: list[tuple[str]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
            domain = normalize_domain(payload["host"])
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError(
                f"Invalid dnsx JSON on line {line_number}"
            ) from error
        if not domain:
            continue

        has_address = False
        for key, version in (("a", 4), ("aaaa", 6)):
            addresses = payload.get(key) or []
            if not isinstance(addresses, list):
                raise ValueError(
                    f"Invalid dnsx answer on line {line_number}"
                )
            for value in addresses:
                try:
                    address = ipaddress.ip_address(value)
                except (TypeError, ValueError) as error:
                    raise ValueError(
                        f"Invalid dnsx address on line {line_number}"
                    ) from error
                if (
                    address.version == version
                    and address.is_global
                    and not address.is_multicast
                ):
                    has_address = True
                    break
            if has_address:
                break
        if has_address:
            rows.append((domain,))
        else:
            status = payload.get("status_code")
            explicit_nodata = (
                status == "NOERROR"
                and "a" in payload
                and "aaaa" in payload
                and not payload["a"]
                and not payload["aaaa"]
            )
            if status == "NXDOMAIN" or explicit_nodata:
                negative_rows.append((domain,))
        if len(rows) >= 5000:
            changes_before = connection.total_changes
            connection.executemany(
                "INSERT OR IGNORE INTO dns_resolved VALUES (?)",
                rows,
            )
            resolved_changes += connection.total_changes - changes_before
            rows.clear()
        if len(negative_rows) >= 5000:
            changes_before = connection.total_changes
            connection.executemany(
                "INSERT OR IGNORE INTO dnsx_negative VALUES (?)",
                negative_rows,
            )
            negative_changes += connection.total_changes - changes_before
            negative_rows.clear()
    if rows:
        changes_before = connection.total_changes
        connection.executemany(
            "INSERT OR IGNORE INTO dns_resolved VALUES (?)",
            rows,
        )
        resolved_changes += connection.total_changes - changes_before
    if negative_rows:
        changes_before = connection.total_changes
        connection.executemany(
            "INSERT OR IGNORE INTO dnsx_negative VALUES (?)",
            negative_rows,
        )
        negative_changes += connection.total_changes - changes_before
    return resolved_changes, negative_changes


async def _query_dns(
    resolver: Any,
    domain: str,
    record_type: str,
) -> tuple[str, list[Any]]:
    try:
        answer = await resolver.resolve(
            domain,
            record_type,
            search=False,
            raise_on_no_answer=False,
        )
    except dns.resolver.NXDOMAIN:
        return "negative", []
    except dns.resolver.NoAnswer:
        return "ok", []
    except dns.exception.DNSException:
        return "unknown", []
    return "ok", list(answer)


def _has_global_address(records: Iterable[Any]) -> bool:
    for record in records:
        value = getattr(record, "address", None)
        if value is None:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_global and not address.is_multicast:
            return True
    return False


def _has_global_https_hint(records: Iterable[Any]) -> bool:
    for record in records:
        for parameter in getattr(record, "params", {}).values():
            for value in getattr(parameter, "addresses", ()):
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if address.is_global and not address.is_multicast:
                    return True
    return False


def _has_unknown_mandatory_https_parameter(record: Any) -> bool:
    mandatory = getattr(record, "params", {}).get(0)
    if mandatory is None:
        return False
    understood_keys = {1, 2, 3, 4, 5, 6, 7}
    return any(int(key) not in understood_keys for key in mandatory.keys)


async def _check_extended_domain(
    domain: str,
    resolver: Any,
    *,
    max_depth: int = 8,
) -> ExtendedDnsResult:
    async def query_addresses(name: str) -> tuple[str, bool]:
        results = await asyncio.gather(
            _query_dns(resolver, name, "A"),
            _query_dns(resolver, name, "AAAA"),
        )
        if any(_has_global_address(records) for _, records in results):
            return "resolved", True
        if any(status == "unknown" for status, _ in results):
            return "unknown", False
        return "negative", False

    async def check_name(
        name: str,
        visited: frozenset[str],
        depth: int,
        method: str | None,
        *,
        check_addresses: bool,
    ) -> ExtendedDnsResult:
        normalized_name = normalize_domain(name)
        if not normalized_name or depth > max_depth:
            return "unknown", None
        if normalized_name in visited:
            return "unknown", None
        next_visited = visited | {normalized_name}

        address_status = "negative"
        if check_addresses:
            address_status, has_address = await query_addresses(
                normalized_name
            )
            if has_address:
                return "resolved", method

        cname_status, cname_records = await _query_dns(
            resolver, normalized_name, "CNAME"
        )
        if cname_status == "negative":
            return "negative", None
        for record in cname_records:
            target = str(getattr(record, "target", "")).rstrip(".")
            return await check_name(
                target,
                next_visited,
                depth + 1,
                method or "cname",
                check_addresses=True,
            )

        https_status, https_records = await _query_dns(
            resolver, normalized_name, "HTTPS"
        )
        if https_status == "negative":
            return "negative", None

        saw_unknown = (
            address_status == "unknown"
            or cname_status == "unknown"
            or https_status == "unknown"
        )
        for record in https_records:
            if _has_unknown_mandatory_https_parameter(record):
                saw_unknown = True
                continue
            priority = getattr(record, "priority", None)
            target = str(getattr(record, "target", ""))
            if priority == 0:
                if target == ".":
                    continue
                result = await check_name(
                    target.rstrip("."),
                    next_visited,
                    depth + 1,
                    method or "https",
                    check_addresses=True,
                )
            else:
                endpoint = (
                    normalized_name if target == "." else target.rstrip(".")
                )
                if endpoint == normalized_name:
                    endpoint_status, has_address = await query_addresses(
                        endpoint
                    )
                    result = (
                        ("resolved", method or "https")
                        if has_address
                        else (endpoint_status, None)
                    )
                else:
                    result = await check_name(
                        endpoint,
                        next_visited,
                        depth + 1,
                        method or "https",
                        check_addresses=True,
                    )
                if result[0] != "resolved" and _has_global_https_hint(
                    [record]
                ):
                    return "resolved", "https-hint"
            if result[0] == "resolved":
                return result
            if result[0] == "unknown":
                saw_unknown = True

        if saw_unknown:
            return "unknown", None
        return "negative", None

    return await check_name(
        domain,
        frozenset(),
        0,
        None,
        check_addresses=False,
    )


def _validate_extended_dns_database(
    connection: sqlite3.Connection,
    dns_config: dict[str, Any],
    *,
    progress_formatter: Callable[[float], str] | None = None,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_resolved (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID
        """
    )
    total = connection.execute(
        "SELECT COUNT(*) FROM dns_extended_candidates"
    ).fetchone()[0]
    start_label = progress_formatter(0.0) if progress_formatter else ""
    if not total:
        print(
            f"{start_label + ' ' if start_label else ''}"
            "Extended DNS skipped: no A/AAAA NODATA domains",
            flush=True,
        )
        return

    resolvers = dns_config["resolvers"]
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [str(value) for value in resolvers]
    resolver.rotate = True
    resolver.timeout = DNS_EXTENDED_TIMEOUT_SECONDS
    resolver.lifetime = DNS_EXTENDED_LIFETIME_SECONDS
    total_batches = (
        total + DNS_EXTENDED_BATCH_SIZE - 1
    ) // DNS_EXTENDED_BATCH_SIZE
    print(
        f"{start_label + ' ' if start_label else ''}"
        f"Extended DNS started: checking {_quantity(total, 'domain')}",
        flush=True,
    )

    async def run() -> None:
        semaphore = asyncio.Semaphore(DNS_EXTENDED_CONCURRENCY)

        async def check(domain: str) -> tuple[str, ExtendedDnsResult]:
            async with semaphore:
                result = await _check_extended_domain(
                    domain,
                    resolver,
                    max_depth=DNS_MAX_ALIAS_DEPTH,
                )
                return domain, result

        cursor = connection.execute(
            "SELECT domain FROM dns_extended_candidates ORDER BY domain"
        )
        processed = 0
        counts = {
            "cname": 0,
            "https": 0,
            "https-hint": 0,
            "negative": 0,
            "unknown": 0,
        }
        batch_index = 0
        while rows := cursor.fetchmany(DNS_EXTENDED_BATCH_SIZE):
            batch_index += 1
            results = await asyncio.gather(
                *(check(domain) for (domain,) in rows)
            )
            resolved_rows: list[tuple[str]] = []
            unknown_rows: list[tuple[str]] = []
            for domain, (outcome, method) in results:
                if outcome == "resolved":
                    resolved_rows.append((domain,))
                    counts[method or "https"] += 1
                elif outcome == "unknown":
                    unknown_rows.append((domain,))
                    counts["unknown"] += 1
                else:
                    counts["negative"] += 1
            connection.executemany(
                "INSERT OR IGNORE INTO dns_resolved VALUES (?)",
                resolved_rows,
            )
            connection.executemany(
                "INSERT OR IGNORE INTO dns_extended_unknown VALUES (?)",
                unknown_rows,
            )
            processed += len(rows)
            fraction = processed / total
            recovered_count = (
                counts["cname"]
                + counts["https"]
                + counts["https-hint"]
            )
            label = progress_formatter(fraction) if progress_formatter else ""
            print(
                f"{label + ' ' if label else ''}"
                f"Extended DNS batch {batch_index}/{total_batches} complete: "
                f"processed {processed:,}/{total:,} ({fraction * 100:.1f}%), "
                f"recovered {recovered_count:,}, "
                f"removed {counts['negative']:,}, unknown {counts['unknown']:,}",
                flush=True,
            )

        end_label = progress_formatter(1.0) if progress_formatter else ""
        print(
            f"{end_label + ' ' if end_label else ''}"
            f"Extended DNS complete: CNAME {counts['cname']:,}, "
            f"HTTPS {counts['https']:,}, HTTPS hints "
            f"{counts['https-hint']:,}, removed {counts['negative']:,}, "
            f"unknown {counts['unknown']:,} kept",
            flush=True,
        )

    asyncio.run(run())


store_massdns_results = _store_massdns_results
store_dnsx_results = _store_dnsx_results
check_extended_domain = _check_extended_domain
validate_extended_dns_database = _validate_extended_dns_database

