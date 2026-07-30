# DNS blocklists

Five independent, domain-only blocklists:

- `output/adblock.txt`
- `output/privacy.txt`
- `output/adult.txt`
- `output/gambling.txt`
- `output/social.txt`

There is no combined list. Every output is lowercase, sorted, deduplicated, and
contains plain domains only. Input wildcards such as `*.example.com` become
`example.com`.

## Build

Install `uv` and provide `dnsx` 1.3.0. `uv` provisions Python 3.12 and all
locked Python dependencies automatically. Use the pinned binary from the
[dnsx v1.3.0 release](https://github.com/projectdiscovery/dnsx/releases/tag/v1.3.0)
or place a compatible `dnsx` executable on `PATH`.

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
dnsx JSONL output.

Adblock syntax is parsed with `python-abp`; only blocking URL patterns that can
be converted safely to a domain are kept. Exception, cosmetic, regular
expression, and disabled (`badfilter`) rules are ignored. RPZ zone syntax is
parsed with `dnspython`; only owners redirected by `CNAME .` are treated as
blocked domains.

The build fails instead of publishing partial output when a source is
unavailable or dnsx itself cannot complete.

## DNS validation

dnsx queries A and AAAA in stream mode using every resolver configured in
`sources.yaml`. It retries each unresolved domain up to three times and can use
UDP, TCP, DoH, or DoT resolver entries.

- A domain with any A or AAAA answer is kept.
- A domain without an A or AAAA address is removed immediately, including
  NXDOMAIN, NODATA, timeout, SERVFAIL, REFUSED, and missing output.

No DNS state is stored. GitHub Actions downloads dnsx 1.3.0 on every run,
verifies the pinned archive checksum, runs full validation weekly, and commits
updated output.
