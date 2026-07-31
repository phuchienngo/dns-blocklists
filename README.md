# DNS blocklists

Two independent, domain-only blocklists based on the sources used by Mullvad:

- `output/adblock.txt`
- `output/privacy.txt`

There is no combined list. Every output is lowercase, sorted, deduplicated, and
contains plain domains only. Input wildcards such as `*.example.com` become
`example.com`.

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

Remote and local inputs are declared in `sources.yaml`. Supported input formats
are `domains`, `hosts`, `adblock`, and `rpz`. Add manually maintained entries
under `custom/`.

Output categories are derived directly from the `category` fields in
`sources.yaml`; there are no configured minimum or maximum list sizes.

Large inputs are processed as streams. Parsed domains, Adblock candidates,
deduplication indexes, and resolved-domain markers are kept in a temporary
SQLite database on disk; sorted TXT outputs are written row by row. RAM usage
therefore does not grow with the total number of input domains, but the system
temporary directory must have enough free disk space for the build database and
MassDNS JSONL output.

Adblock syntax is parsed with `python-abp`; only blocking URL patterns that can
be converted safely to a domain are kept. Exception, cosmetic, regular
expression, and disabled (`badfilter`) rules are ignored. RPZ zone syntax is
parsed with `dnspython`; only owners redirected by `CNAME .` are treated as
blocked domains.

The build fails instead of publishing partial output when a source is
unavailable or MassDNS itself cannot complete.

The build logs each source as it is processed, the DNS validation totals, each
output as it is written, and the total elapsed time. Source processing and DNS
validation emit a heartbeat every 30 seconds so a slow or stuck phase remains
visible in CI logs. Every phase also includes its overall step and percentage;
the total consists of all sources, DNS validation, and all output files.

DNS validation runs in batches of 10,000 domains. After every batch, the log
reports cumulative processed, kept, removed, and unknown counts. This provides
exact progress without loading the full domain list into RAM.

Before writing each category, descendants are collapsed when a retained parent
domain already exists in the same category. For example, `a.example.com` and
`b.a.example.com` are omitted when `example.com` is present. Categories remain
independent, and a parent removed by DNS validation does not suppress its
children.

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
