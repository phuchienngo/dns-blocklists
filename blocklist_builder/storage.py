from __future__ import annotations

import sqlite3
import tempfile
from collections.abc import Iterable
from pathlib import Path

from publicsuffix2 import PublicSuffixList

from blocklist_builder.parsing import parse_lines


def _collapse_parent_domains(
    connection: sqlite3.Connection,
) -> int:
    connection.execute("DELETE FROM redundant")
    changes_before = connection.total_changes
    connection.execute(
        """
        WITH RECURSIVE ancestors(domain, parent) AS (
            SELECT
                child.domain,
                SUBSTR(child.domain, INSTR(child.domain, '.') + 1)
            FROM domains AS child
            WHERE INSTR(child.domain, '.') > 0

            UNION ALL

            SELECT
                domain,
                SUBSTR(parent, INSTR(parent, '.') + 1)
            FROM ancestors
            WHERE INSTR(parent, '.') > 0
        )
        INSERT OR IGNORE INTO redundant(domain)
        SELECT ancestor.domain
        FROM ancestors AS ancestor
        JOIN domains AS parent
          ON parent.domain = ancestor.parent
        """
    )
    collapsed_count = connection.total_changes - changes_before
    connection.execute(
        """
        DELETE FROM domains
        WHERE EXISTS (
            SELECT 1
            FROM redundant
            WHERE redundant.domain = domains.domain
        )
        """
    )
    connection.execute("DELETE FROM redundant")
    return collapsed_count


def _exclude_allowlisted_domains(
    connection: sqlite3.Connection,
) -> int:
    changes_before = connection.total_changes
    connection.execute(
        """
        DELETE FROM domains
        WHERE EXISTS (
            SELECT 1
            FROM allowlist_domains AS allowed
            WHERE domains.domain = allowed.domain
               OR domains.domain LIKE '%.' || allowed.domain
        )
        """
    )
    return connection.total_changes - changes_before


def _exclude_public_suffixes(
    connection: sqlite3.Connection,
    public_suffix_path: Path,
) -> int:
    with public_suffix_path.open(encoding="utf-8") as suffix_lines:
        public_suffixes = PublicSuffixList(suffix_lines, idna=True)

    connection.execute(
        """
        CREATE TEMP TABLE excluded_public_suffixes (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID
        """
    )
    excluded: list[tuple[str]] = []
    for (domain,) in connection.execute("SELECT domain FROM domains"):
        if public_suffixes.get_tld(domain, strict=True) == domain:
            excluded.append((domain,))
        if len(excluded) >= 5000:
            connection.executemany(
                "INSERT OR IGNORE INTO excluded_public_suffixes VALUES (?)",
                excluded,
            )
            excluded.clear()
    if excluded:
        connection.executemany(
            "INSERT OR IGNORE INTO excluded_public_suffixes VALUES (?)",
            excluded,
        )
    excluded_count = connection.execute(
        "SELECT COUNT(*) FROM excluded_public_suffixes"
    ).fetchone()[0]
    connection.execute(
        """
        DELETE FROM domains
        WHERE EXISTS (
            SELECT 1
            FROM excluded_public_suffixes AS suffix
            WHERE suffix.domain = domains.domain
        )
        """
    )
    connection.execute("DROP TABLE excluded_public_suffixes")
    return excluded_count


class _DomainBatch:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.rows: list[tuple[str]] = []

    def emit(self, domain: str) -> None:
        self.rows.append((domain,))
        if len(self.rows) >= 5000:
            self.flush()

    def flush(self) -> None:
        if not self.rows:
            return
        self.connection.executemany(
            """
            INSERT OR IGNORE INTO source_domains(domain)
            VALUES (?)
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
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID;
        CREATE TABLE domains (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID;
        CREATE TABLE allowlist_domains (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID;
        CREATE TABLE redundant (
            domain TEXT PRIMARY KEY
        ) WITHOUT ROWID;
        """
    )


def _parse_source_into_database(
    connection: sqlite3.Connection,
    lines: Iterable[str],
    source_format: str,
) -> int:
    connection.execute("DELETE FROM source_domains")
    batch = _DomainBatch(connection)
    parse_lines(lines, source_format, emit=batch.emit)
    batch.flush()
    return connection.execute(
        "SELECT COUNT(*) FROM source_domains"
    ).fetchone()[0]


def _merge_source(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        INSERT OR IGNORE INTO domains(domain)
        SELECT domain FROM source_domains
        """
    )


def _merge_allowlist(
    connection: sqlite3.Connection,
) -> None:
    connection.execute(
        """
        INSERT OR IGNORE INTO allowlist_domains(domain)
        SELECT domain FROM source_domains
        """
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


initialize_database = _initialize_database
collapse_parent_domains = _collapse_parent_domains
exclude_allowlisted_domains = _exclude_allowlisted_domains
exclude_public_suffixes = _exclude_public_suffixes
atomic_write_domains = _atomic_write_domains
parse_source_into_database = _parse_source_into_database
merge_source = _merge_source
merge_allowlist = _merge_allowlist
