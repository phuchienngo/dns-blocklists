from __future__ import annotations

import argparse
import shutil
import sqlite3
import tempfile
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from publicsuffix2 import PublicSuffixList

from blocklist_builder.dns import validate_dns_database as _validate_dns_database
from blocklist_builder.storage import (
    atomic_write_domains as _atomic_write_domains,
    collapse_parent_domains as _collapse_parent_domains,
    exclude_allowlisted_domains as _exclude_allowlisted_domains,
    exclude_public_suffixes as _exclude_public_suffixes,
    initialize_database as _initialize_database,
    merge_allowlist as _merge_allowlist,
    merge_source as _merge_source,
    parse_source_into_database as _parse_source_into_database,
    remove_unresolved_domains as _remove_unresolved_domains,
)

PROGRESS_PHASE_RANGES = (
    (0, 10),
    (10, 30),
    (30, 70),
    (70, 85),
    (85, 95),
    (95, 100),
)
CUSTOM_BLOCKLIST_PATH = "custom/blocklist.txt"
CUSTOM_ALLOWLIST_PATH = "custom/allowlist.txt"


def _quantity(count: int, noun: str) -> str:
    if count == 1:
        return f"{count:,} {noun}"
    plural = f"{noun[:-1]}ies" if noun.endswith("y") else f"{noun}s"
    return f"{count:,} {plural}"


def _phase_label(
    phase: int,
    *,
    progress: float = 1.0,
) -> str:
    start, end = PROGRESS_PHASE_RANGES[phase - 1]
    percentage = start + (end - start) * progress
    return f"[phase {phase}/{len(PROGRESS_PHASE_RANGES)} | {percentage:.1f}%]"


def _download_remote(
    url: str,
    destination: Path,
) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "dns-blocklists-builder/1.0"},
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                with destination.open("wb") as output:
                    shutil.copyfileobj(response, output)
            return
        except Exception as error:
            last_error = error
            if attempt < 2:
                time.sleep(2**attempt)
    raise RuntimeError(f"Download failed for {url}: {last_error}")


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
) -> int:
    started_at = time.monotonic()
    sources = config.get("sources")
    dns_config = config.get("dns", {})
    if not isinstance(sources, dict) or not sources:
        raise ValueError("sources must be a non-empty format mapping")
    source_configs: list[tuple[str, str, str, bool, str]] = []
    for source_format, locations in sources.items():
        if source_format not in {"adblock", "domains", "hosts", "rpz"}:
            raise ValueError(f"Unsupported source format: {source_format}")
        if not isinstance(locations, list):
            raise ValueError(f"sources.{source_format} must be a list")
        for location in locations:
            if not isinstance(location, str) or not location:
                raise ValueError(
                    f"sources.{source_format} entries must be URLs or paths"
                )
            source_configs.append(
                (
                    location,
                    location,
                    source_format,
                    bool(urllib.parse.urlparse(location).scheme),
                    "blocklist",
                )
            )
    if not source_configs:
        raise ValueError("sources must contain at least one URL or path")

    custom_blocklist = base_directory / CUSTOM_BLOCKLIST_PATH
    if custom_blocklist.is_file():
        source_configs.append(
            (
                CUSTOM_BLOCKLIST_PATH,
                CUSTOM_BLOCKLIST_PATH,
                "domains",
                False,
                "blocklist",
            )
        )
    custom_allowlist = base_directory / CUSTOM_ALLOWLIST_PATH
    if custom_allowlist.is_file():
        source_configs.append(
            (
                CUSTOM_ALLOWLIST_PATH,
                CUSTOM_ALLOWLIST_PATH,
                "domains",
                False,
                "allowlist",
            )
        )

    public_suffix_location = config.get("public_suffix_list")
    if public_suffix_location is not None:
        if (
            not isinstance(public_suffix_location, str)
            or not public_suffix_location
        ):
            raise ValueError("public_suffix_list must be a URL or path")
        source_configs.append(
            (
                public_suffix_location,
                public_suffix_location,
                "psl",
                bool(
                    urllib.parse.urlparse(public_suffix_location).scheme
                ),
                "public_suffix_list",
            )
        )

    print(
        "Starting build: 6 phases "
        "(download 0-10%, parse 10-30%, "
        "MassDNS 30-70%, subdomain rescue 70-85%, "
        "extended DNS 85-95%, dnsx 95-100%)",
        flush=True,
    )

    with tempfile.TemporaryDirectory(prefix="dns-blocklists-db-") as directory:
        temporary = Path(directory)
        database_path = temporary / "build.sqlite3"
        download_directory = temporary / "downloads"
        download_directory.mkdir()
        source_materials: list[tuple[str, str, Path, str]] = []

        for source_index, source_config in enumerate(
            source_configs,
            start=1,
        ):
            name, location, source_format, is_remote, role = source_config
            start_label = _phase_label(
                1,
                progress=(source_index - 1) / len(source_configs),
            )
            end_label = _phase_label(
                1,
                progress=source_index / len(source_configs),
            )
            if is_remote:
                source_path = download_directory / f"{source_index}.txt"
                print(
                    f"{start_label} "
                    f"[download {source_index}/{len(source_configs)}] "
                    f"Downloading {name}",
                    flush=True,
                )
                try:
                    if fetch_text is None:
                        _download_remote(location, source_path)
                    else:
                        source_path.write_text(
                            fetch_text(location),
                            encoding="utf-8",
                        )
                except Exception as error:
                    raise RuntimeError(
                        f"Failed to download source {name}: {error}"
                    ) from error
                print(
                    f"{end_label} "
                    f"[download {source_index}/{len(source_configs)}] "
                    f"Downloaded {name}",
                    flush=True,
                )
            else:
                source_path = base_directory / location
                if not source_path.is_file():
                    raise RuntimeError(f"Source file not found: {name}")
                print(
                    f"{end_label} "
                    f"[download {source_index}/{len(source_configs)}] "
                    f"Local source ready: {name}",
                    flush=True,
                )
            source_materials.append(
                (name, source_format, source_path, role)
            )

        with sqlite3.connect(database_path) as connection:
            _initialize_database(connection)
            public_suffix_path: Path | None = None

            for source_index, source_material in enumerate(
                source_materials,
                start=1,
            ):
                name, source_format, source_path, role = source_material
                start_label = _phase_label(
                    2,
                    progress=(source_index - 1) / len(source_materials),
                )
                end_label = _phase_label(
                    2,
                    progress=source_index / len(source_materials),
                )
                if role == "allowlist":
                    description = f"{name} (allowlist)"
                elif role == "public_suffix_list":
                    description = f"{name} (public suffix list)"
                else:
                    description = (
                        name if source_format == "domains"
                        else f"{name} ({source_format})"
                    )
                print(
                    f"{start_label} "
                    f"[parse {source_index}/{len(source_materials)}] "
                    f"Parsing {description}",
                    flush=True,
                )

                try:
                    if role == "public_suffix_list":
                        public_suffix_path = source_path
                        source_count = 0
                    else:
                        with source_path.open(encoding="utf-8-sig") as lines:
                            source_count = _parse_source_into_database(
                                connection,
                                lines,
                                source_format,
                            )
                        if role == "allowlist":
                            _merge_allowlist(connection)
                        else:
                            _merge_source(connection)
                    connection.commit()
                except Exception as error:
                    raise RuntimeError(
                        f"Failed to parse source {name}: {error}"
                    ) from error
                result = (
                    "public suffix data ready"
                    if role == "public_suffix_list"
                    else _quantity(source_count, "domain")
                )
                print(
                    f"{end_label} "
                    f"[parse {source_index}/{len(source_materials)}] "
                    f"Parsed {name}: {result}",
                    flush=True,
                )

            connection.execute(
                "CREATE TABLE removed(domain TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            allowlisted_count = _exclude_allowlisted_domains(connection)
            if custom_allowlist.is_file():
                print(
                    f"{_phase_label(2)} Allowlist applied: "
                    f"{_quantity(allowlisted_count, 'domain')} excluded",
                    flush=True,
                )
            if public_suffix_path is not None:
                public_suffix_count = _exclude_public_suffixes(
                    connection,
                    public_suffix_path,
                )
                print(
                    f"{_phase_label(2)} Public suffix filter applied: "
                    f"{_quantity(public_suffix_count, 'domain')} excluded",
                    flush=True,
                )
                with public_suffix_path.open(encoding="utf-8") as suffixes:
                    dns_public_suffixes = PublicSuffixList(
                        suffixes,
                        idna=True,
                    )
            else:
                dns_public_suffixes = PublicSuffixList()

            print(
                f"{_phase_label(2)} Parent-domain collapse started",
                flush=True,
            )
            collapsed_count = _collapse_parent_domains(connection)
            print(
                f"{_phase_label(2)} Parent-domain collapse complete: "
                f"{_quantity(collapsed_count, 'record')} removed",
                flush=True,
            )

            unique_count = connection.execute(
                "SELECT COUNT(*) FROM (SELECT domain FROM domains GROUP BY domain)"
            ).fetchone()[0]
            massdns_start_label = _phase_label(3, progress=0.0)
            massdns_end_label = _phase_label(3)
            rescue_end_label = _phase_label(4)
            extended_end_label = _phase_label(5)
            dnsx_end_label = _phase_label(6)
            if not skip_dns:
                print(
                    f"{massdns_start_label} MassDNS validation started: "
                    "resolving "
                    f"{_quantity(unique_count, 'unique domain')}",
                    flush=True,
                )
                if dns_validator is None:
                    _validate_dns_database(
                        connection,
                        dns_config,
                        public_suffixes=dns_public_suffixes,
                        progress_formatter=lambda fraction: _phase_label(
                            3,
                            progress=fraction,
                        ),
                        rescue_progress_formatter=lambda fraction: (
                            _phase_label(4, progress=fraction)
                        ),
                        extended_progress_formatter=lambda fraction: (
                            _phase_label(5, progress=fraction)
                        ),
                        dnsx_progress_formatter=lambda fraction: _phase_label(
                            6,
                            progress=fraction,
                        ),
                    )
                else:
                    dns_validator(connection, dns_config)
                _remove_unresolved_domains(connection)
                removed_count = connection.execute(
                    "SELECT COUNT(*) FROM removed"
                ).fetchone()[0]
                print(
                    f"{dnsx_end_label} DNS validation complete: "
                    f"{_quantity(unique_count - removed_count, 'domain')} kept, "
                    f"{_quantity(removed_count, 'domain')} removed",
                    flush=True,
                )
            else:
                print(
                    f"{massdns_end_label} MassDNS validation skipped: "
                    "retaining "
                    f"{_quantity(unique_count, 'unique domain')}",
                    flush=True,
                )
                print(
                    f"{rescue_end_label} Subdomain rescue skipped",
                    flush=True,
                )
                print(
                    f"{extended_end_label} Extended DNS skipped",
                    flush=True,
                )
                print(
                    f"{dnsx_end_label} dnsx fallback skipped",
                    flush=True,
                )

            output_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM domains AS d
                WHERE NOT EXISTS (
                      SELECT 1 FROM removed AS r
                      WHERE r.domain = d.domain
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM redundant
                      WHERE redundant.domain = d.domain
                  )
                """
            ).fetchone()[0]

            output_directory.mkdir(parents=True, exist_ok=True)
            print(
                f"{dnsx_end_label} "
                "Writing blocklist.txt: "
                f"{_quantity(output_count, 'domain')}",
                flush=True,
            )
            rows = connection.execute(
                """
                SELECT d.domain
                FROM domains AS d
                WHERE NOT EXISTS (
                      SELECT 1 FROM removed AS r
                      WHERE r.domain = d.domain
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM redundant
                      WHERE redundant.domain = d.domain
                  )
                ORDER BY d.domain
                """
            )
            _atomic_write_domains(
                output_directory / "blocklist.txt",
                rows,
            )
            for old_output in output_directory.glob("*.txt"):
                if old_output.name != "blocklist.txt":
                    old_output.unlink()
    print(
        f"{_phase_label(6)} "
        f"Build complete in {time.monotonic() - started_at:.1f}s",
        flush=True,
    )
    return output_count


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
    parser = argparse.ArgumentParser(description="Build a domain-only blocklist")
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
    count = build(
        config=load_config(config_path),
        base_directory=config_path.parent,
        output_directory=args.output.resolve(),
        skip_dns=args.skip_dns,
    )
    print(f"blocklist: {count} output domains")


if __name__ == "__main__":
    main()
