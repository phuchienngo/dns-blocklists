from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Callable, Iterable
from io import StringIO
from typing import Any

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
DomainEmitter = Callable[[str], None]


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


def _emit_domain(emit: DomainEmitter, value: str) -> None:
    if value.startswith("*."):
        value = value[2:]
    domain = normalize_domain(value)
    if domain:
        emit(domain)


def _parse_domains(
    lines: Iterable[str],
    emit: DomainEmitter,
) -> None:
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("!", ";")):
            continue
        _emit_domain(emit, line)


def _parse_hosts(
    lines: Iterable[str],
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
            _emit_domain(emit, value)


def _parse_adblock(
    lines: Iterable[str],
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
                disabled INTEGER NOT NULL
            ) WITHOUT ROWID
            """
        )
        rows: list[tuple[str, str, int]] = []
        for entry in parse_filterlist(lines):
            if (
                not hasattr(entry, "selector")
                or entry.action != FilterAction.BLOCK
                or entry.selector["type"] != SelectorType.URL_PATTERN
            ):
                continue

            pattern = entry.selector["value"]
            match = re.fullmatch(r"\|\|(.+)\^", pattern)
            value = match.group(1) if match else pattern
            normalized: list[str] = []
            _emit_domain(normalized.append, value)
            if not normalized:
                continue
            rows.append(
                (
                    json.dumps(signature(entry), separators=(",", ":")),
                    normalized[0],
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
                    VALUES (?, ?, ?)
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
                VALUES (?, ?, ?)
                ON CONFLICT(signature) DO UPDATE
                SET disabled = MAX(disabled, excluded.disabled)
                """,
                rows,
            )
        for (domain,) in filters.execute(
            """
            SELECT domain
            FROM candidates
            WHERE disabled = 0
            ORDER BY domain
            """
        ):
            emit(domain)


class _RpzTransactionManager(dns.transaction.TransactionManager):
    def __init__(self, emit: DomainEmitter):
        self.origin = dns.name.from_text("rpz.invalid.")
        self.emit = emit

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
            _emit_domain(self.rpz_manager.emit, name.to_text())

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
    emit: DomainEmitter,
) -> None:
    manager = _RpzTransactionManager(emit)
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
    source_format: str = "domains",
    *,
    emit: DomainEmitter,
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
    parser(lines, emit)


def parse_content(
    content: str,
    source_format: str = "domains",
) -> set[str]:
    domains: set[str] = set()
    parse_lines(StringIO(content), source_format, emit=domains.add)
    return domains

