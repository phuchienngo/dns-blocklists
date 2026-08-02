# DNS blocklist

One domain-only blocklist built from the inputs in `sources.yaml`:

- `output/blocklist.txt`

The output is lowercase, sorted, deduplicated, and contains plain domains only.
Input wildcards such as `*.example.com` become `example.com`.

## Build

Install `uv`. It provisions Python 3.12 and all locked Python dependencies
automatically; no separate resolver executables are required.

```bash
uv run --locked python -m unittest discover -s tests -v
uv run --locked python scripts/build_blocklists.py
```

The executable in `scripts/build_blocklists.py` is a thin compatibility
entrypoint. Implementation is split by responsibility under
`blocklist_builder/`: `parsing.py` handles domain, hosts, Adblock, and RPZ
input; `storage.py` owns SQLite and atomic output; and `builder.py` coordinates
the complete build.

Blocklist inputs are grouped by format under `sources` in `sources.yaml`. Each
group contains URLs or repository-relative paths. Supported groups are
`domains`, `hosts`, `adblock`, and `rpz`; empty groups may be omitted.

`custom/blocklist.txt` and `custom/allowlist.txt` are loaded automatically when
present, so they do not need entries in `sources.yaml`. The blocklist file adds
domains; an allowlisted domain and all of its subdomains are excluded without
creating a separate output list. `public_suffix_list` points to the current
[Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat).

There are no categories or configured minimum and maximum list sizes.

Remote inputs are downloaded to temporary files and then parsed as streams.
Parsed domains, Adblock candidates, and deduplication indexes are kept in a
temporary SQLite database on disk; the sorted TXT output is written row by row.
RAM usage therefore does not grow with the total number of input domains, but
the system temporary directory must have enough free disk space for downloaded
sources and the build database.

Adblock syntax is parsed with `python-abp`; only blocking URL patterns that can
be converted safely to domains are kept. Exception, cosmetic, regular
expression, and disabled (`badfilter`) rules are ignored. RPZ zone syntax is
parsed with `dnspython`; only owners redirected by `CNAME .` are treated as
blocked domains.

The build fails instead of publishing partial output when a configured source
or the Public Suffix List cannot be downloaded or parsed.

The build logs real completed work without timer heartbeats. Overall progress is
split into download (0-20%), parse/filter/collapse (20-90%), and output
(90-100%). Download and parse advance after each completed source.

Before parent collapse, exact public suffixes are removed using the downloaded
ICANN and private sections of the Public Suffix List. This prevents entries
such as `duckdns.org` from blocking every registrant below that shared suffix.
A real domain below the suffix, such as `tracker.duckdns.org`, remains eligible.

Parent-domain collapse runs before writing the output. For example,
`a.example.com` and `b.a.example.com` are omitted when `example.com` is present,
which reduces the number of output records. `blocklist.txt` is written without
a trailing newline.

## Source trust

The build trusts configured upstream blocklists. Every syntactically valid
domain supplied by an upstream or `custom/blocklist.txt` is retained unless it
is excluded by `custom/allowlist.txt`, is itself a Public Suffix List entry, or
is redundant beneath an included parent domain. It does not perform live DNS
resolution or remove NXDOMAIN/NODATA entries. This avoids resolver-dependent
false negatives and keeps the build fast; stale domains remain the upstream
maintainer's responsibility.

GitHub Actions runs the same source-only build weekly without caches and commits
an updated output when its contents change.
