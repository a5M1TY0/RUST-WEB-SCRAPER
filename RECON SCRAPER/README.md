# ReconScraper

A scoped, polite web reconnaissance crawler written in Python.

It maps a target site, fingerprints its tech stack, audits security headers, and **detects** anti-bot defenses (Cloudflare, DataDome, CAPTCHAs, etc.), reporting them rather than bypassing them.

## Features
- Explicit scope allowlist: refuses to leave declared hosts
- robots.txt compliance
- Per-host rate limiting with jitter, exponential backoff, `Retry-After` support
- Anti-bot detection: WAF/CDN headers, challenge-page markers, 403/429 handling
- Tech fingerprinting and security header audit
- Inventory of links, forms, scripts, external domains
- JSON report output

## Usage
```bash
pip install -r requirements.txt
python recon_scraper.py https://books.toscrape.com --max-pages 20 -o report.json
```

## Ethics
Only run this against sites you own or that explicitly permit scraping
(books.toscrape.com, quotes.toscrape.com, your own lab). Respect each site's terms.

## Roadmap
- Sitemap parsing
- HTML report
- Async crawling (httpx)
- Dockerized test lab with a rate-limiting nginx target
