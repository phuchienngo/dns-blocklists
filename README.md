# DNS blocklist

One domain-only blocklist built from the inputs in `sources.yaml`:

- `output/blocklist.txt`

The output is lowercase, sorted, deduplicated, and contains plain domains only.
Input wildcards such as `*.example.com` become `example.com`.

## Build

Install `uv` and provide a compatible
[MassDNS](https://github.com/blechschmidt/massdns) executable on `PATH`. `uv`
provisions Python 3.12 and all locked Python dependencies automatically.

```bash
uv run --locked python -m unittest discover -s tests -v
uv run --locked python scripts/build_blocklists.py
```

To rebuild sources without performing or updating DNS validation:

```bash
uv run --locked python scripts/build_blocklists.py --skip-dns
```

Inputs are grouped by format in `sources.yaml`. Each group contains URLs or
repository-relative paths. Supported groups are `domains`, `hosts`, `adblock`,
and `rpz`; empty groups may be omitted.

There are no categories or configured minimum and maximum list sizes.

Large inputs are processed as streams. Parsed domains, Adblock candidates,
deduplication indexes, and resolved-domain markers are kept in temporary SQLite
databases on disk; the sorted TXT output is written row by row. RAM usage
therefore does not grow with the total number of input domains, but the system
temporary directory must have enough free disk space for the build database and
MassDNS JSONL output.

Adblock syntax is parsed with `python-abp`; only blocking URL patterns that can
be converted safely to domains are kept. Exception, cosmetic, regular
expression, and disabled (`badfilter`) rules are ignored. RPZ zone syntax is
parsed with `dnspython`; only owners redirected by `CNAME .` are treated as
blocked domains.

The build fails instead of publishing partial output when a source is
unavailable or MassDNS itself cannot complete.

The build logs each source as it is processed, the DNS validation totals, each
output as it is written, and the total elapsed time. Source processing and DNS
validation emit a heartbeat every 30 seconds so a slow or stuck phase remains
visible in CI logs. Every phase also includes its overall step and percentage;
the total consists of all sources, DNS validation, and all output files. During
DNS validation, each completed batch advances that overall percentage instead
of leaving it fixed for the entire DNS step.

DNS validation runs in batches of 10,000 domains. After every batch, the log
reports cumulative processed, kept, removed, and unknown counts. This provides
exact progress without loading the full domain list into RAM.

Before writing the output, descendants are collapsed when a retained parent
domain already exists. For example, `a.example.com` and `b.a.example.com` are
omitted when `example.com` is present. A parent removed by DNS validation does
not suppress its children.

## DNS validation

MassDNS first queries A records against the unfiltered resolver pool configured
in `sources.yaml`, using a hash-map size of 800. AAAA is queried only for names
without a global A address and without an NXDOMAIN response. Only transient or
missing results are retried, using the same resolver pool with a lower hash-map
size of 200.

- A domain with any globally routable A or AAAA answer is kept.
- NXDOMAIN is removed without an unnecessary AAAA query; NODATA is removed
  after both A and AAAA return no address.
- A domain with timeout, SERVFAIL, REFUSED, or missing output after retry is
  classified as unknown and kept to avoid false removal.
- Sinkhole and non-routable addresses such as unspecified, loopback, private,
  link-local, and reserved IPs do not count as resolved.

No DNS state is stored. GitHub Actions builds a pinned MassDNS commit from
source without a cache, runs full validation weekly, and commits updated output.
