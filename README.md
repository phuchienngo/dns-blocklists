# DNS blocklist

One domain-only blocklist built from the inputs in `sources.yaml`:

- `output/blocklist.txt`

The output is lowercase, sorted, deduplicated, and contains plain domains only.
Input wildcards such as `*.example.com` become `example.com`.

## Build

Install `uv` and provide compatible
[MassDNS](https://github.com/blechschmidt/massdns) and
[dnsx](https://github.com/projectdiscovery/dnsx) executables on `PATH`. `uv`
provisions Python 3.12 and all locked Python dependencies automatically.

```bash
uv run --locked python -m unittest discover -s tests -v
uv run --locked python scripts/build_blocklists.py
```

To rebuild sources without performing or updating DNS validation:

```bash
uv run --locked python scripts/build_blocklists.py --skip-dns
```

Blocklist inputs are grouped by format under `sources` in `sources.yaml`. Each
group contains URLs or repository-relative paths. Supported groups are
`domains`, `hosts`, `adblock`, and `rpz`; empty groups may be omitted.

`allowlist` contains domain-list URLs or paths whose entries must not appear in
the output. An allowlisted domain also excludes all of its subdomains; it does
not create a separate output list. `public_suffix_list` points to the current
[Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat).

There are no categories or configured minimum and maximum list sizes.

Remote inputs are downloaded to temporary files and then parsed as streams.
Parsed domains, Adblock candidates, deduplication indexes, and resolved-domain
markers are kept in temporary SQLite databases on disk; the sorted TXT output
is written row by row. RAM usage therefore does not grow with the total number
of input domains, but the system temporary directory must have enough free disk
space for downloaded sources, the build database, and DNS JSONL output.

Adblock syntax is parsed with `python-abp`; only blocking URL patterns that can
be converted safely to domains are kept. Exception, cosmetic, regular
expression, and disabled (`badfilter`) rules are ignored. RPZ zone syntax is
parsed with `dnspython`; only owners redirected by `CNAME .` are treated as
blocked domains.

The build fails instead of publishing partial output when a blocklist,
allowlist, the Public Suffix List, or either DNS validator cannot complete.

The build logs real completed work without timer heartbeats. Overall progress is
split into download (0-10%), parse and merge (10-30%), MassDNS (30-90%), and
dnsx fallback (90-100%). Download and parse advance after each source; MassDNS
and dnsx advance after each completed batch. dnsx reports recovered, explicitly
removed, and still-unknown counts, or reports that it was skipped when MassDNS
produced no unknown domains.

MassDNS validation runs in batches of 10,000 domains. After every batch, the
log reports cumulative processed, resolved, removed, and dnsx-pending counts.
The dnsx fallback processes batches of 2,000 and logs cumulative processed,
recovered, explicitly removed, and still-unknown counts. This provides exact
progress without loading the full domain list into RAM.

Before DNS validation, exact public suffixes are removed using the downloaded
ICANN and private sections of the Public Suffix List. This prevents entries such
as `duckdns.org` from blocking every registrant below that shared suffix. A real
domain below the suffix, such as `tracker.duckdns.org`, remains eligible.

Parent-domain collapse also runs before DNS validation. For example,
`a.example.com` and `b.a.example.com` are omitted when `example.com` is present,
so DNS only validates the parent. This reduces DNS work and output records, with
the deliberate trade-off that the children are not restored if the parent later
fails DNS validation.

## DNS validation

MassDNS first queries A records against the unfiltered resolver pool configured
in `sources.yaml`, using a hash-map size of 800. AAAA is queried only for names
without a global A address and without an NXDOMAIN response. Only transient or
missing results are retried, using the same resolver pool with a lower hash-map
size of 200. Remaining unknown domains are passed to dnsx in batches, with A and
AAAA queries, the same resolver pool, and three retries.

- A domain with any globally routable A or AAAA answer is kept.
- NXDOMAIN is removed without an unnecessary AAAA query; NODATA is removed
  after both A and AAAA return no address.
- A domain with timeout, SERVFAIL, REFUSED, or missing MassDNS output is kept
  pending until dnsx rechecks it. If dnsx still returns no global A or AAAA
  address, the domain remains unknown and is kept; missing dnsx output is not
  treated as proof that the domain is dead.
- An explicit dnsx NXDOMAIN, or NOERROR response containing empty A and AAAA
  result sets, is removed. Transient response codes are not treated as dead.
- Sinkhole and non-routable addresses such as unspecified, loopback, private,
  link-local, and reserved IPs do not count as resolved.

No DNS state is stored. GitHub Actions installs a pinned MassDNS Homebrew bottle
and a checksum-verified pinned dnsx binary without a cache, runs full validation
weekly, and commits updated output.
