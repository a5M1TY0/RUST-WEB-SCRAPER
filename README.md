# recon-scraper (Rust)

A scoped, polite web reconnaissance crawler. It maps a site, fingerprints the tech stack, audits security headers, and **detects** anti-bot defenses (CAPTCHAs, challenge pages, 403/429 blocks). When it hits a block it reports it and stops. It never tries to get around it.

## Design decisions
- **Scope allowlist.** Only hosts you list are fetched. Redirects that leave scope are refused.
- **robots.txt.** Parsed with `*` and `$` wildcard support. Longest rule wins, and a specific `ReconScraper` group beats `*`.
- **Honest identity.** Sends `ReconScraper/1.0` as its User-Agent. It does not pretend to be a browser.
- **Rate limiting.** Per-host time slots with jitter, so concurrent workers still space out requests. Backs off on 429/503 and honors `Retry-After`.
- **Detection, not evasion.** CDN/WAF presence (e.g. `cf-ray`) is reported as informational. Only real challenge signals (CAPTCHA markers, 401/403/429, `cf-mitigated`) stop the crawl.
- **Concurrency.** Fetches run concurrently with Tokio, but results keep input order so reports are reproducible.

## Build and run
```bash
cargo build --release
./target/release/recon-scraper https://books.toscrape.com --max-pages 20 -o report.json
cargo test
```

Options: `--scope host1 host2`, `--delay <secs>`, `--workers <n>`, `--proxy <url>`, `--ignore-robots` (only for hosts you own).

## Report fields
Per page: status, title, tech fingerprint, missing security headers, protection vendors, block signals, forms, scripts, external links. The report also lists skipped URLs with reasons.

## Ethics
Run it only against hosts you own or that explicitly allow scraping (`books.toscrape.com`, `quotes.toscrape.com`, your own lab).

## Roadmap
- Sitemap parsing
- HTML report output
- Dockerized nginx lab with rate limiting as a reproducible test target
