# Spec: Build Script Refactor

## Assumptions

1. Refactoring may split the current 2,495-line script into a small Python
   package plus a compatibility entrypoint.
2. This is behavior-preserving work: DNS policy, source parsing, progress text,
   config schema, output ordering, and failure semantics must not change.
3. `uv run --locked python scripts/build_blocklists.py` must remain valid.
4. Existing uncommitted CNAME, HTTPS, and Subfinder work belongs to the current
   scope and must be preserved.

## Objective

Make the blocklist builder easier to read, test, and extend by separating domain
parsing, SQLite build storage, DNS validation, and CLI orchestration. Success
means each module has one responsibility while the generated blocklist and logs
remain byte-for-byte and line-for-line compatible for the same inputs and mocked
tool results.

## Tech Stack

- Python 3.12
- Standard library, dnspython, publicsuffix2, python-abp, and PyYAML already
  locked by uv
- `unittest` with the existing subprocess and DNS fakes

## Commands

```bash
uv run --locked python -m unittest discover -s tests -v
uv run --locked python -m compileall -q blocklist_builder scripts tests
uv run --locked python scripts/build_blocklists.py --help
uv run --locked python scripts/build_blocklists.py --skip-dns
```

## Project Structure

```text
blocklist_builder/
  __init__.py       Public build and parsing API
  parsing.py        Domain normalization and domains/hosts/adblock/RPZ parsers
  storage.py        SQLite schema, filters, collapse, and atomic TXT writing
  dns.py            MassDNS and dnsx validation orchestration
  dns_records.py    MassDNS/dnsx parsing and async CNAME/HTTPS checks
  dns_discovery.py  Subfinder discovery and NXDOMAIN-parent rescue
  builder.py        Downloads, progress allocation, build orchestration, config
scripts/
  build_blocklists.py  Thin backward-compatible CLI and import façade
tests/
  test_parsing.py
  test_storage.py
  test_dns.py
  test_dns_records.py
  test_dns_discovery.py
  test_builder.py
```

Dependencies flow in one direction:

```text
scripts/build_blocklists.py -> builder -> storage/dns
dns -> dns_records/dns_discovery
dns_records/dns_discovery -> parsing.normalize_domain
dns_discovery -> storage.atomic_write_domains
builder -> parsing + storage + dns
```

## Code Style

Keep functions small and explicit, use typed arguments, and pass collaborators
instead of relying on mutable module globals when a test seam is required.

```python
def validate_dns(
    connection: sqlite3.Connection,
    config: DnsConfig,
    progress: ProgressFormatter | None = None,
) -> None:
    """Run DNS phases without owning source parsing or final output writing."""
```

Private helpers remain private to their owning module. The façade re-exports
the existing public functions `build`, `load_config`, `normalize_domain`,
`parse_lines`, and `parse_content`.

## Testing Strategy

- Add an architectural import test first so the new package boundary fails
  before implementation.
- Move existing tests by responsibility without weakening assertions.
- Preserve integration tests that verify exact progress logs, subprocess flags,
  SQLite streaming behavior, DNS classification, and no trailing newline.
- Run the full suite after each module extraction.
- Do not require live DNS or internet access in the test suite.

## Boundaries

- Always: preserve CLI/config/output/log behavior and streaming SQLite design.
- Always: retain pinned external binaries and existing GitHub Actions behavior.
- Ask first: dependency additions, config changes, or DNS-policy changes.
- Never: regenerate `output/blocklist.txt` as part of a pure refactor.
- Never: edit the two historical reference repositories.

## Success Criteria

1. The compatibility script is a thin façade and contains no DNS or parser
   implementation.
2. No implementation module exceeds roughly 1,000 lines.
3. Existing 30 tests plus the new architecture test pass.
4. CLI help and `--skip-dns` remain functional.
5. `git diff --check`, compileall, uv lock validation, and workflow YAML parsing
   pass.
6. No dependency, config, workflow behavior, or generated output changes.

## Open Questions

The proposed boundary is package-based rather than a single-file class refactor.
Approval of this spec confirms that splitting the script into the modules above
is desired.
