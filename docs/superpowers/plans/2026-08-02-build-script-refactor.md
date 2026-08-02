# Build Script Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use test-driven-development to implement this plan task-by-task. Execute inline because the user already approved implementation in the current task.

**Goal:** Split the 2,495-line build script into focused modules without changing its CLI, configuration, logs, DNS policy, or output.

**Architecture:** Introduce a `blocklist_builder` package with parsing, storage, DNS, and orchestration modules. Keep `scripts/build_blocklists.py` as a thin compatibility façade so existing commands and imports continue to work while tests move to their owning modules.

**Tech Stack:** Python 3.12, SQLite, dnspython, publicsuffix2, python-abp, PyYAML, unittest, uv.

---

### Task 1: Lock the package boundary

**Files:**
- Create: `tests/test_architecture.py`
- Create: `blocklist_builder/__init__.py`

- [ ] **Step 1: Write the failing architecture test**

```python
import unittest


class ArchitectureTest(unittest.TestCase):
    def test_builder_is_split_by_responsibility(self) -> None:
        from blocklist_builder import builder, dns, parsing, storage

        self.assertTrue(callable(builder.build))
        self.assertTrue(callable(dns.validate_dns_database))
        self.assertTrue(callable(parsing.parse_content))
        self.assertTrue(callable(storage.initialize_database))
```

- [ ] **Step 2: Verify RED**

Run:

```bash
uv run --locked python -m unittest tests.test_architecture -v
```

Expected: import failure because the new package modules do not exist.

- [ ] **Step 3: Add only the package shell**

Create an empty package initializer so module extraction can proceed without
changing runtime behavior.

- [ ] **Step 4: Keep the architecture test red until all four modules exist**

Run the same targeted command and confirm the missing-module failure remains.

### Task 2: Extract domain parsing

**Files:**
- Create: `blocklist_builder/parsing.py`
- Modify: `scripts/build_blocklists.py`
- Test: `tests/test_build_blocklists.py`

- [ ] **Step 1: Move normalization and format parsers**

Move `normalize_domain`, domains, hosts, Adblock, and RPZ parsing into
`parsing.py`, preserving these signatures:

```python
def normalize_domain(value: str) -> str | None: ...
def parse_lines(lines: Iterable[str], source_format: str = "domains", *, emit: DomainEmitter) -> None: ...
def parse_content(content: str, source_format: str = "domains") -> set[str]: ...
```

- [ ] **Step 2: Re-export the public parsing API from the compatibility script**

```python
from blocklist_builder.parsing import normalize_domain, parse_content, parse_lines
```

- [ ] **Step 3: Verify parser behavior**

Run:

```bash
uv run --locked python -m unittest tests.test_build_blocklists.ParseContentTest -v
```

Expected: all parser tests pass unchanged.

### Task 3: Extract SQLite build storage

**Files:**
- Create: `blocklist_builder/storage.py`
- Modify: `scripts/build_blocklists.py`
- Test: `tests/test_build_blocklists.py`

- [ ] **Step 1: Move database and output primitives**

Move database initialization, source batching/merging, allowlist/PSL filtering,
parent collapse, unresolved removal, and atomic TXT writing. Expose explicit
names without leading underscores inside the module:

```python
initialize_database = ...
collapse_parent_domains = ...
exclude_allowlisted_domains = ...
exclude_public_suffixes = ...
remove_unresolved_domains = ...
atomic_write_domains = ...
```

- [ ] **Step 2: Keep private compatibility aliases in the façade**

```python
_initialize_database = storage.initialize_database
_atomic_write_domains = storage.atomic_write_domains
_remove_unresolved_domains = storage.remove_unresolved_domains
```

- [ ] **Step 3: Verify storage behavior**

Run:

```bash
uv run --locked python -m unittest tests.test_build_blocklists.BuildTest.test_output_has_no_trailing_newline tests.test_build_blocklists.BuildTest.test_filters_exact_public_suffixes_before_parent_collapse -v
```

Expected: output and PSL/collapse assertions pass unchanged.

### Task 4: Extract DNS validation

**Files:**
- Create: `blocklist_builder/dns.py`
- Modify: `scripts/build_blocklists.py`
- Test: `tests/test_build_blocklists.py`

- [ ] **Step 1: Move all DNS phases and constants**

Move MassDNS/dnsx result storage, async CNAME/HTTPS validation, Subfinder rescue,
and the top-level DNS validator into `dns.py`. Inject shared storage operations
through direct module imports and retain the callable surface:

```python
store_massdns_results = ...
store_dnsx_results = ...
check_extended_domain = ...
validate_extended_dns_database = ...
rescue_nxdomain_domains = ...
validate_dns_database = ...
```

- [ ] **Step 2: Preserve test seams**

Patch subprocess and executable lookup at `blocklist_builder.dns.subprocess` and
`blocklist_builder.dns.shutil`; keep compatibility aliases in the façade for
existing callers.

- [ ] **Step 3: Verify DNS behavior**

Run:

```bash
uv run --locked python -m unittest tests.test_build_blocklists.DnsClassificationTest tests.test_build_blocklists.ExtendedDnsClassificationTest tests.test_build_blocklists.SubdomainRescueTest -v
```

Expected: exact classification, command, progress, and unknown-keep assertions
all pass.

### Task 5: Extract build orchestration and thin the CLI

**Files:**
- Create: `blocklist_builder/builder.py`
- Modify: `blocklist_builder/__init__.py`
- Replace: `scripts/build_blocklists.py`
- Test: `tests/test_architecture.py`

- [ ] **Step 1: Move downloads, phase progress, config, and build orchestration**

The package builder owns:

```python
def build(...) -> int: ...
def load_config(path: Path) -> dict[str, Any]: ...
def main() -> None: ...
```

- [ ] **Step 2: Make the script a compatibility façade**

```python
from blocklist_builder import build, load_config, normalize_domain, parse_content, parse_lines
from blocklist_builder.builder import main

if __name__ == "__main__":
    main()
```

Include the existing private aliases used by tests while callers migrate.

- [ ] **Step 3: Verify GREEN for the architecture test**

```bash
uv run --locked python -m unittest tests.test_architecture -v
```

Expected: package boundary assertions pass.

### Task 6: Reorganize tests and documentation

**Files:**
- Create: `tests/test_parsing.py`
- Create: `tests/test_storage.py`
- Create: `tests/test_dns.py`
- Create: `tests/test_builder.py`
- Delete: `tests/test_build_blocklists.py`
- Modify: `README.md`

- [ ] **Step 1: Move tests without changing assertions**

Group the current classes by owning module and update patch targets to the new
module paths. Do not delete or relax any behavior assertion.

- [ ] **Step 2: Document the package layout**

Add the four module responsibilities to README while retaining the same user
commands.

- [ ] **Step 3: Run complete verification**

```bash
git diff --check
uv lock --check
uv run --locked python -m compileall -q blocklist_builder scripts tests
uv run --locked python -m unittest discover -s tests -v
uv run --locked python scripts/build_blocklists.py --help
```

Expected: zero failures, valid CLI, unchanged lockfile, and no whitespace errors.

- [ ] **Step 4: Confirm refactor boundaries**

```bash
wc -l blocklist_builder/*.py scripts/build_blocklists.py
git status --short
```

Expected: no implementation module over roughly 1,000 lines, thin compatibility
script, and no generated `output/blocklist.txt` change.
