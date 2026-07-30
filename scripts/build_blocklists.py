#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.request
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from io import StringIO, TextIOWrapper
from pathlib import Path
from typing import Any, TextIO

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer
import dns.transaction
import dns.zonefile
from abp.filters import FilterAction, SelectorType, parse_filterlist


DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
VALID_SCOPES = {"auto", "host", "suffix"}
PROGRESS_HEARTBEAT_SECONDS = 30
DNS_BATCH_SIZE = 10_000
DNS_RETRY_HASHMAP_SIZE = 100
DomainEmitter = Callable[[str, str], None]


def _quantity(count: int, noun: str) -> str:
    if count == 1:
        return f"{count:,} {noun}"
    plural = f"{noun[:-1]}ies" if noun.endswith("y") else f"{noun}s"
    return f"{count:,} {plural}"


def _step_label(step: int, total_steps: int) -> str:
    percentage = step / total_steps * 100
    return f"[step {step}/{total_steps} | {percentage:.0f}%]"


@contextmanager
def _progress_heartbeat(label: str):
    started_at = time.monotonic()
    stopped = threading.Event()

    def report() -> None:
        while not stopped.wait(PROGRESS_HEARTBEAT_SECONDS):
            elapsed = time.monotonic() - started_at
            print(
                f"{label} still running ({elapsed:.0f}s elapsed)",
                flush=True,
            )

    reporter = threading.Thread(target=report, daemon=True)
    reporter.start()
    try:
        yield
    finally:
        stopped.set()
        reporter.join()


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower().removesuffix(".")
    if not value or value == "localhost":
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253 or not DOMAIN_PATTERN.fullmatch(value):
        return None
    return value


def _emit_domain(
    emit: DomainEmitter,
    value: str,
    *,
    wildcard: bool = False,
    source_scope: str = "auto",
) -> None:
    if source_scope not in VALID_SCOPES:
        raise ValueError(f"Unsupported source scope: {source_scope}")
    if value.startswith("*."):
        wildcard = True
        value = value[2:]
    domain = normalize_domain(value)
    if not domain:
        return
    scope = "suffix" if wildcard or source_scope == "suffix" else "host"
    emit(domain, scope)


def _parse_domains(
    lines: Iterable[str],
    scope: str,
    emit: DomainEmitter,
) -> None:
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("!", ";")):
            continue
        _emit_domain(emit, line, source_scope=scope)


def _parse_hosts(
    lines: Iterable[str],
    scope: str,
    emit: DomainEmitter,
) -> None:
    for raw_line in lines:
        fields = raw_line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        try:
            ipaddress.ip_address(fields[0])
        except ValueError:
            continue
        for value in fields[1:]:
            _emit_domain(emit, value, source_scope=scope)


def _parse_adblock(
    lines: Iterable[str],
    scope: str,
    emit: DomainEmitter,
) -> None:
    def signature(entry: Any) -> tuple[Any, ...]:
        options = tuple(
            sorted(
                (name, repr(value))
                for name, value in entry.options
                if name != "badfilter"
            )
        )
        return (
            entry.action,
            entry.selector["type"],
            entry.selector["value"],
            options,
        )

    with sqlite3.connect("") as filters:
        filters.execute("PRAGMA temp_store = FILE")
        filters.execute(
            """
            CREATE TABLE candidates (
                signature TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                scope TEXT NOT NULL,
                disabled INTEGER NOT NULL
            ) WITHOUT ROWID
            """
        )
        rows: list[tuple[str, str, str, int]] = []
        for entry in parse_filterlist(lines):
            if (
                not hasattr(entry, "selector")
                or entry.action != FilterAction.BLOCK
                or entry.selector["type"] != SelectorType.URL_PATTERN
            ):
                continue

            pattern = entry.selector["value"]
            match = re.fullmatch(r"\|\|(.+)\^", pattern)
            wildcard = match is not None
            value = match.group(1) if match else pattern
            normalized: list[tuple[str, str]] = []
            _emit_domain(
                lambda domain, domain_scope: normalized.append(
                    (domain, domain_scope)
                ),
                value,
                wildcard=wildcard,
                source_scope=scope,
            )
            if not normalized:
                continue
            domain, domain_scope = normalized[0]
            rows.append(
                (
                    json.dumps(signature(entry), separators=(",", ":")),
                    domain,
                    domain_scope,
                    int(
                        any(
                            name == "badfilter" and value
                            for name, value in entry.options
                        )
                    ),
                )
            )
            if len(rows) >= 5000:
                filters.executemany(
                    """
                    INSERT INTO candidates
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(signature) DO UPDATE
                    SET disabled = MAX(disabled, excluded.disabled)
                    """,
                    rows,
                )
                rows.clear()
        if rows:
            filters.executemany(
                """
                INSERT INTO candidates
                VALUES (?, ?, ?, ?)
                ON CONFLICT(signature) DO UPDATE
                SET disabled = MAX(disabled, excluded.disabled)
                """,
                rows,
            )
        for domain, domain_scope in filters.execute(
            """
            SELECT domain, scope
            FROM candidates
            WHERE disabled = 0
            ORDER BY domain
            """
        ):
            emit(domain, domain_scope)


class _RpzTransactionManager(dns.transaction.TransactionManager):
    def __init__(self, emit: DomainEmitter, scope: str):
        self.origin = dns.name.from_text("rpz.invalid.")
        self.emit = emit
        self.scope = scope

    def reader(self):
        raise NotImplementedError

    def writer(self, replacement: bool = False):
        return _RpzTransaction(self, replacement)

    def get_class(self):
        return dns.rdataclass.IN

    def origin_information(self):
        return self.origin, True, dns.name.empty


class _RpzTransaction(dns.transaction.Transaction):
    def __init__(self, manager: _RpzTransactionManager, replacement: bool):
        super().__init__(manager, replacement, False)
        self.rpz_manager = manager

    def _get_rdataset(self, name, rdtype, covers):
        return None

    def _get_node(self, name):
        return None

    def _put_rdataset(self, name, rdataset):
        if rdataset.rdtype != dns.rdatatype.CNAME:
            return
        if any(record.target == dns.name.root for record in rdataset):
            _emit_domain(
                self.rpz_manager.emit,
                name.to_text(),
                source_scope=self.rpz_manager.scope,
            )

    def _delete_name(self, name):
        pass

    def _delete_rdataset(self, name, rdtype, covers):
        pass

    def _name_exists(self, name):
        return False

    def _changed(self):
        return True

    def _end_transaction(self, commit):
        pass

    def _set_origin(self, origin):
        self.rpz_manager.origin = origin

    def _iterate_rdatasets(self):
        return iter(())

    def _iterate_names(self):
        return iter(())


def _parse_rpz(
    lines: Iterable[str],
    scope: str,
    emit: DomainEmitter,
) -> None:
    manager = _RpzTransactionManager(emit, scope)
    with manager.writer(True) as transaction:
        tokenizer = dns.tokenizer.Tokenizer(lines, "<rpz>")
        reader = dns.zonefile.Reader(
            tokenizer,
            dns.rdataclass.IN,
            transaction,
            allow_include=False,
        )
        reader.read()


def parse_lines(
    lines: Iterable[str],
    source_format: str,
    *,
    emit: DomainEmitter,
    scope: str = "auto",
) -> None:
    parsers = {
        "adblock": _parse_adblock,
        "domains": _parse_domains,
        "hosts": _parse_hosts,
        "rpz": _parse_rpz,
    }
    try:
        parser = parsers[source_format]
    except KeyError as error:
        raise ValueError(f"Unsupported source format: {source_format}") from error
    parser(lines, scope, emit)


def parse_content(
    content: str,
    source_format: str,
    *,
    scope: str = "auto",
) -> dict[str, str]:
    domains: dict[str, str] = {}

    def collect(domain: str, domain_scope: str) -> None:
        if domains.get(domain) != "suffix":
            domains[domain] = domain_scope

    parse_lines(
        StringIO(content),
        source_format,
        emit=collect,
        scope=scope,
    )
    return domains


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
            outcome = (
                "resolved"
                if has_address
                else (
                    "negative"
                    if status in {"NOERROR", "NXDOMAIN"}
                    else "unknown"
                )
            )
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


def _remove_unresolved_domains(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        INSERT INTO removed(domain)
        SELECT global_domains.domain
        FROM (
            SELECT domain
            FROM domains
            GROUP BY domain
        ) AS global_domains
        WHERE NOT EXISTS (
            SELECT 1
            FROM dns_resolved AS resolved
            WHERE resolved.domain = global_domains.domain
        )
          AND NOT EXISTS (
              SELECT 1
              FROM dns_unknown AS unknown
              WHERE unknown.domain = global_domains.domain
          )
        """
    )


def _consume_remote(
    url: str,
    consume: Callable[[TextIO], None],
) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "dns-blocklists-builder/1.0"},
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                with TextIOWrapper(response, encoding="utf-8-sig") as lines:
                    consume(lines)
            return
        except Exception as error:
            last_error = error
            if attempt < 2:
                time.sleep(2**attempt)
    raise RuntimeError(f"Download failed for {url}: {last_error}")


class _DomainBatch:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.rows: list[tuple[str, int]] = []

    def emit(self, domain: str, scope: str) -> None:
        self.rows.append((domain, 1 if scope == "suffix" else 0))
        if len(self.rows) >= 5000:
            self.flush()

    def flush(self) -> None:
        if not self.rows:
            return
        self.connection.executemany(
            """
            INSERT INTO source_domains(domain, scope)
            VALUES (?, ?)
            ON CONFLICT(domain) DO UPDATE
            SET scope = MAX(scope, excluded.scope)
            """,
            self.rows,
        )
        self.rows.clear()


def _initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
        PRAGMA temp_store = FILE;
        CREATE TABLE source_domains (
            domain TEXT PRIMARY KEY,
            scope INTEGER NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE domains (
            category TEXT NOT NULL,
            domain TEXT NOT NULL,
            scope INTEGER NOT NULL,
            PRIMARY KEY (category, domain)
        ) WITHOUT ROWID;
        CREATE TABLE dns_unknown (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID;
        """
    )


def _parse_source_into_database(
    connection: sqlite3.Connection,
    lines: Iterable[str],
    source_format: str,
    scope: str,
) -> int:
    connection.execute("DELETE FROM source_domains")
    batch = _DomainBatch(connection)
    parse_lines(lines, source_format, emit=batch.emit, scope=scope)
    batch.flush()
    return connection.execute(
        "SELECT COUNT(*) FROM source_domains"
    ).fetchone()[0]


def _merge_source(
    connection: sqlite3.Connection,
    category: str,
) -> None:
    connection.execute(
        """
        INSERT INTO domains(category, domain, scope)
        SELECT ?, domain, scope FROM source_domains WHERE 1
        ON CONFLICT(category, domain) DO UPDATE
        SET scope = MAX(scope, excluded.scope)
        """,
        (category,),
    )


def _validate_dns_database(
    connection: sqlite3.Connection,
    dns_config: dict[str, Any],
    *,
    progress_label: str = "",
) -> None:
    resolvers = dns_config.get("resolvers")
    if not isinstance(resolvers, list) or not resolvers:
        raise ValueError("dns.resolvers must contain at least one resolver")
    command_timeout = int(dns_config.get("command_timeout_seconds", 3600))
    hashmap_size = int(dns_config.get("hashmap_size", 500))
    resolve_count = int(dns_config.get("resolve_count", 3))
    executable = str(dns_config.get("executable", "massdns"))
    resolved_executable = shutil.which(executable)
    if not resolved_executable:
        raise RuntimeError(f"massdns executable not found: {executable}")

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
        CREATE TEMP TABLE dns_retry_observations (
            domain TEXT NOT NULL,
            resolver TEXT NOT NULL,
            query_type TEXT NOT NULL,
            outcome TEXT NOT NULL,
            PRIMARY KEY (domain, resolver, query_type)
        ) WITHOUT ROWID;
        """
    )

    with tempfile.TemporaryDirectory(prefix="dns-blocklists-") as directory:
        temporary = Path(directory)
        input_path = temporary / "domains.txt"
        resolver_path = temporary / "resolvers.txt"
        output_path = temporary / "massdns.jsonl"
        error_path = temporary / "massdns.err"
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
        started_at = time.monotonic()
        batch_index = 0
        while batch := domain_cursor.fetchmany(DNS_BATCH_SIZE):
            batch_index += 1
            connection.execute("DELETE FROM dns_batch")
            connection.executemany(
                "INSERT INTO dns_batch VALUES (?)",
                batch,
            )
            with input_path.open("w", encoding="utf-8") as input_file:
                for (domain,) in batch:
                    input_file.write(f"{domain}\n")

            def run_massdns(
                *,
                input_file: Path,
                active_resolvers: list[str],
                active_hashmap_size: int,
                observed_resolver: str | None = None,
            ) -> None:
                resolver_path.write_text(
                    "".join(
                        f"{resolver}\n" for resolver in active_resolvers
                    ),
                    encoding="utf-8",
                )
                for active_query_type in ("A", "AAAA"):
                    command = [
                        resolved_executable,
                        "-r",
                        str(resolver_path),
                        "-t",
                        active_query_type,
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
                        str(input_file),
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
                                f"massdns {active_query_type} failed on "
                                f"batch {batch_index}/{total_batches}"
                            ) from error

                    with output_path.open(encoding="utf-8") as output:
                        _store_massdns_results(
                            connection,
                            output,
                            resolver=observed_resolver,
                            query_type=active_query_type,
                        )

            run_massdns(
                input_file=input_path,
                active_resolvers=resolvers,
                active_hashmap_size=hashmap_size,
            )

            retry_domains = list(
                connection.execute(
                    """
                    SELECT batch.domain
                    FROM dns_batch AS batch
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM dns_resolved AS resolved
                        WHERE resolved.domain = batch.domain
                    )
                    ORDER BY batch.domain
                    """
                )
            )
            connection.execute("DELETE FROM dns_retry_observations")
            if retry_domains:
                with input_path.open("w", encoding="utf-8") as input_file:
                    for (domain,) in retry_domains:
                        input_file.write(f"{domain}\n")
                for resolver in resolvers:
                    run_massdns(
                        input_file=input_path,
                        active_resolvers=[resolver],
                        active_hashmap_size=DNS_RETRY_HASHMAP_SIZE,
                        observed_resolver=resolver,
                    )

            required_negatives = len(resolvers) * 2
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
            batch_removed = connection.execute(
                """
                SELECT COUNT(*)
                FROM dns_batch AS batch
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM dns_resolved AS resolved
                    WHERE resolved.domain = batch.domain
                )
                  AND (
                      SELECT COUNT(*)
                      FROM dns_retry_observations AS observation
                      WHERE observation.domain = batch.domain
                        AND observation.outcome = 'negative'
                  ) = ?
                """,
                (required_negatives,),
            ).fetchone()[0]
            connection.execute(
                """
                INSERT OR IGNORE INTO dns_unknown(domain)
                SELECT batch.domain
                FROM dns_batch AS batch
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM dns_resolved AS resolved
                    WHERE resolved.domain = batch.domain
                )
                  AND (
                      SELECT COUNT(*)
                      FROM dns_retry_observations AS observation
                      WHERE observation.domain = batch.domain
                        AND observation.outcome = 'negative'
                  ) < ?
                """,
                (required_negatives,),
            )
            batch_unknown = len(batch) - batch_resolved - batch_removed
            processed_count += len(batch)
            resolved_count += batch_resolved
            unknown_count += batch_unknown
            removed_count += batch_removed
            kept_count = resolved_count + unknown_count
            percentage = processed_count / total_domains * 100
            prefix = f"{progress_label} " if progress_label else ""
            print(
                f"{prefix}DNS batch {batch_index}/{total_batches} complete: "
                f"processed {processed_count:,}/{total_domains:,} "
                f"({percentage:.1f}%), kept {kept_count:,}, "
                f"removed {removed_count:,}, unknown {unknown_count:,}, "
                f"elapsed {time.monotonic() - started_at:.0f}s",
                flush=True,
            )


def _atomic_write_domains(
    path: Path,
    rows: Iterable[tuple[str]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as temporary:
        separator = ""
        for (domain,) in rows:
            temporary.write(f"{separator}{domain}")
            separator = "\n"
        temporary_path = Path(temporary.name)
    try:
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def build(
    *,
    config: dict[str, Any],
    base_directory: Path,
    output_directory: Path,
    skip_dns: bool = False,
    fetch_text: Callable[[str], str] | None = None,
    dns_validator: Callable[
        [sqlite3.Connection, dict[str, Any]], None
    ] | None = None,
) -> dict[str, int]:
    started_at = time.monotonic()
    sources = config.get("sources")
    dns_config = config.get("dns", {})
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources must be a non-empty list")
    categories: list[str] = []
    for source in sources:
        category = source.get("category")
        if not isinstance(category, str) or not category:
            raise ValueError("every source requires a category")
        if category not in categories:
            categories.append(category)

    total_steps = len(sources) + 1 + len(categories)
    dns_step = len(sources) + 1
    print(
        f"Starting build: {_quantity(total_steps, 'total step')} "
        f"({_quantity(len(sources), 'source')}, "
        "DNS validation, "
        f"{_quantity(len(categories), 'category output')})",
        flush=True,
    )

    with tempfile.TemporaryDirectory(prefix="dns-blocklists-db-") as directory:
        database_path = Path(directory) / "build.sqlite3"
        with sqlite3.connect(database_path) as connection:
            _initialize_database(connection)

            for source_index, source in enumerate(sources, start=1):
                name = source.get("name", "<unnamed>")
                category = source.get("category")
                source_format = source.get("format", "<unknown>")
                step_label = _step_label(source_index, total_steps)
                print(
                    f"{step_label} [source {source_index}/{len(sources)}] "
                    "Processing "
                    f"{name} ({category}, {source_format})",
                    flush=True,
                )

                source_count = 0

                def consume(lines: TextIO) -> None:
                    nonlocal source_count
                    source_count = _parse_source_into_database(
                        connection,
                        lines,
                        source["format"],
                        source.get("scope", "auto"),
                    )

                try:
                    with _progress_heartbeat(
                        f"{step_label} Source {name}"
                    ):
                        if "url" in source:
                            if fetch_text is None:
                                _consume_remote(source["url"], consume)
                            else:
                                consume(StringIO(fetch_text(source["url"])))
                        elif "path" in source:
                            with (base_directory / source["path"]).open(
                                encoding="utf-8-sig"
                            ) as lines:
                                consume(lines)
                        else:
                            raise ValueError("source requires url or path")
                        _merge_source(connection, category)
                        connection.commit()
                except Exception as error:
                    raise RuntimeError(
                        f"Failed to process source {name}: {error}"
                    ) from error
                print(
                    f"{step_label} [source {source_index}/{len(sources)}] "
                    "Parsed "
                    f"{name}: {_quantity(source_count, 'domain')}",
                    flush=True,
                )

            connection.execute(
                "CREATE TABLE removed(domain TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            unique_count = connection.execute(
                "SELECT COUNT(*) FROM (SELECT domain FROM domains GROUP BY domain)"
            ).fetchone()[0]
            dns_step_label = _step_label(dns_step, total_steps)
            if not skip_dns:
                print(
                    f"{dns_step_label} DNS validation started: resolving "
                    f"{_quantity(unique_count, 'unique domain')}",
                    flush=True,
                )
                with _progress_heartbeat(
                    f"{dns_step_label} DNS validation"
                ):
                    if dns_validator is None:
                        _validate_dns_database(
                            connection,
                            dns_config,
                            progress_label=dns_step_label,
                        )
                    else:
                        dns_validator(connection, dns_config)
                    _remove_unresolved_domains(connection)
                removed_count = connection.execute(
                    "SELECT COUNT(*) FROM removed"
                ).fetchone()[0]
                print(
                    f"{dns_step_label} DNS validation complete: "
                    f"{_quantity(unique_count - removed_count, 'domain')} kept, "
                    f"{_quantity(removed_count, 'domain')} removed",
                    flush=True,
                )
            else:
                print(
                    f"{dns_step_label} DNS validation skipped: retaining "
                    f"{_quantity(unique_count, 'unique domain')}",
                    flush=True,
                )

            output_counts: dict[str, int] = {}
            for category in categories:
                count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM domains AS d
                    WHERE d.category = ?
                      AND NOT EXISTS (
                          SELECT 1 FROM removed AS r
                          WHERE r.domain = d.domain
                      )
                    """,
                    (category,),
                ).fetchone()[0]
                output_counts[category] = count

            expected_outputs = {
                f"{category}.txt" for category in categories
            }
            output_directory.mkdir(parents=True, exist_ok=True)
            for category_index, category in enumerate(categories, start=1):
                output_step = dns_step + category_index
                print(
                    f"{_step_label(output_step, total_steps)} "
                    f"[output {category_index}/{len(categories)}] Writing "
                    f"{category}.txt: "
                    f"{_quantity(output_counts[category], 'domain')}",
                    flush=True,
                )
                rows = connection.execute(
                    """
                    SELECT d.domain
                    FROM domains AS d
                    WHERE d.category = ?
                      AND NOT EXISTS (
                          SELECT 1 FROM removed AS r
                          WHERE r.domain = d.domain
                      )
                    ORDER BY d.domain
                    """,
                    (category,),
                )
                _atomic_write_domains(
                    output_directory / f"{category}.txt",
                    rows,
                )
            for old_output in output_directory.glob("*.txt"):
                if old_output.name not in expected_outputs:
                    old_output.unlink()
    print(
        f"{_step_label(total_steps, total_steps)} "
        f"Build complete in {time.monotonic() - started_at:.1f}s",
        flush=True,
    )
    return output_counts


def load_config(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as error:
        raise RuntimeError(
            "PyYAML is required; run this project through uv"
        ) from error
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Config must contain a YAML mapping")
    return payload


def main() -> None:
    repository = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Build domain-only blocklists")
    parser.add_argument(
        "--config",
        type=Path,
        default=repository / "sources.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repository / "output",
    )
    parser.add_argument(
        "--skip-dns",
        action="store_true",
        help="Build source lists without running or updating DNS validation",
    )
    args = parser.parse_args()

    config_path = args.config.resolve()
    counts = build(
        config=load_config(config_path),
        base_directory=config_path.parent,
        output_directory=args.output.resolve(),
        skip_dns=args.skip_dns,
    )
    for category, count in counts.items():
        print(f"{category}: {count} output domains")


if __name__ == "__main__":
    main()
