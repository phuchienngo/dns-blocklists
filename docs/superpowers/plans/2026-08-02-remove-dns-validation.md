# Remove DNS Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the blocklist entirely from trusted upstream sources without MassDNS, dnsx, Subfinder, or live DNS record checks.

**Architecture:** Keep the existing disk-backed download, parsing, allowlist, Public Suffix List, parent-collapse, and atomic-output pipeline. Reduce progress reporting to three phases and remove the DNS-only modules, database schema, command-line switch, configuration, CI installation, tests, and documentation.

**Tech Stack:** Python 3.12, SQLite, uv, unittest, GitHub Actions, YAML.

---

### Task 1: Lock the no-DNS build contract

**Files:**
- Modify: `tests/test_builder.py`
- Modify: `tests/test_architecture.py`
- Modify: `tests/test_storage.py`

- [ ] **Step 1: Write the failing build tests**

Update build calls to use the permanent no-DNS API, assert that a parent domain remains in the output without invoking a validator, and assert progress is reported as download, parse/filter, and output phases:

```python
count = build(
    config={"sources": {"domains": ["domains.txt"]}},
    base_directory=root,
    output_directory=root / "output",
)
self.assertEqual(count, 1)
self.assertEqual(output.read_text(encoding="utf-8"), "dead-parent.example")
self.assertIn("Starting build: 3 phases", log)
self.assertNotIn("DNS", log)
```

Update the architecture assertion so the package no longer exposes a DNS subsystem. Update storage initialization assertions so DNS-only tables and the `removed` table are absent.

- [ ] **Step 2: Run tests to verify RED**

Run: `uv run --locked python -m unittest tests.test_builder tests.test_architecture tests.test_storage -v`

Expected: FAIL because `build()` still accepts and executes DNS controls, progress still has six DNS phases, and DNS modules/tables still exist.

### Task 2: Remove DNS code and simplify the pipeline

**Files:**
- Modify: `blocklist_builder/builder.py`
- Modify: `blocklist_builder/storage.py`
- Delete: `blocklist_builder/dns.py`
- Delete: `blocklist_builder/dns_records.py`
- Delete: `blocklist_builder/dns_discovery.py`
- Delete: `tests/test_dns.py`
- Delete: `tests/test_dns_records.py`
- Delete: `tests/test_dns_discovery.py`

- [ ] **Step 1: Implement the no-DNS build path**

Change the progress ranges to three phases:

```python
PROGRESS_PHASE_RANGES = ((0, 20), (20, 90), (90, 100))
```

Remove `skip_dns`, `dns_validator`, DNS config loading, PublicSuffixList construction for discovery, DNS validation calls, and `--skip-dns`. After parent collapse, count and stream rows directly from `domains`, reporting output and completion through phase 3.

- [ ] **Step 2: Remove DNS persistence and modules**

Remove `_remove_unresolved_domains`, all `dns_*` tables, and `removed`. Make parent collapse operate only on the current `domains` table. Delete the three DNS implementation modules and their dedicated tests.

- [ ] **Step 3: Run focused tests to verify GREEN**

Run: `uv run --locked python -m unittest tests.test_builder tests.test_architecture tests.test_storage -v`

Expected: PASS with no DNS executable or network resolver required.

### Task 3: Remove operational DNS configuration and documentation

**Files:**
- Modify: `sources.yaml`
- Modify: `.github/workflows/update.yml`
- Modify: `README.md`
- Modify: `uv.lock` only if dependency resolution changes
- Delete: `docs/specs/massdns-subdomain-probing.md`

- [ ] **Step 1: Remove DNS operational setup**

Delete the `dns` mapping from `sources.yaml`. Remove MassDNS, dnsx, and Subfinder versions, downloads, PATH checks, and installation steps from GitHub Actions. Keep uv setup, dependency sync, tests, build, and output commit.

- [ ] **Step 2: Rewrite the README contract**

Describe the three-phase source-only pipeline and explicitly state that upstream domain entries are trusted and no live DNS validation is performed. Retain RPZ/adblock parsing, Public Suffix List filtering, allowlist exclusion, disk-backed SQLite, parent collapse, and no-trailing-newline behavior.

- [ ] **Step 3: Verify the repository**

Run: `uv run --locked python -m unittest discover -s tests -v`

Run: `uv run --locked python -m compileall -q blocklist_builder scripts tests`

Run: `rg -n -i 'massdns|dnsx|subfinder|skip-dns|dns validation|dns_config|dns_validator' --glob '!output/**' --glob '!docs/superpowers/plans/**' .`

Expected: all tests pass, compilation exits 0, and the search returns no stale runtime/config/documentation references.

