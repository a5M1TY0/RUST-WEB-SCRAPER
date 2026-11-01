#!/usr/bin/env python3
"""
recon_scraper.py - a scoped, polite web recon scraper.

What it does:
  * Crawls a target within an explicit scope (allowlisted hosts only)
  * Respects robots.txt, rate limits per host with jitter, backs off on 429/503
  * Detects anti-bot signals (CDN/WAF headers, challenge pages, captchas)
    and REPORTS them instead of bypassing them
  * Fingerprints tech stack, audits security headers, maps links/forms/scripts
  * Writes a JSON report

Only use it on hosts you own or that explicitly allow scraping
(e.g. books.toscrape.com, quotes.toscrape.com, your own lab).
"""
import argparse
import json
import random
import sys
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urldefrag
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]
BOT_TOKEN = "ReconScraper/1.0 (+portfolio project)"

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing: no forced HTTPS",
    "content-security-policy": "CSP missing: weaker XSS mitigation",
    "x-frame-options": "X-Frame-Options missing: clickjacking risk (unless CSP frame-ancestors)",
    "x-content-type-options": "X-Content-Type-Options missing: MIME sniffing allowed",
    "referrer-policy": "Referrer-Policy missing",
    "permissions-policy": "Permissions-Policy missing",
}

ANTIBOT_HEADER_HINTS = {
    "cf-ray": "Cloudflare",
    "cf-mitigated": "Cloudflare (challenge issued)",
    "x-sucuri-id": "Sucuri WAF",
    "x-akamai-transformed": "Akamai",
    "x-datadome": "DataDome",
    "x-px-": "PerimeterX/HUMAN",
    "x-amzn-waf-action": "AWS WAF",
}
CHALLENGE_MARKERS = [
    "g-recaptcha", "h-captcha", "cf-turnstile", "just a moment...",
    "attention required", "access denied", "verify you are human",
]
TECH_HINTS = {
    "wp-content": "WordPress", "/_next/": "Next.js", "ng-version": "Angular",
    "data-reactroot": "React", "__nuxt": "Nuxt", "cdn.shopify.com": "Shopify",
    "jquery": "jQuery", "bootstrap": "Bootstrap",
}


class Scope:
    def __init__(self, hosts):
        self.hosts = {h.lower() for h in hosts}

    def allows(self, url):
        host = (urlparse(url).hostname or "").lower()
        return host in self.hosts


class Fetcher:
    def __init__(self, delay, proxy=None, timeout=15):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        self.delay, self.timeout = delay, timeout
        self.last_hit = {}

    def _wait(self, host):
        gap = self.delay * random.uniform(0.8, 1.6)
        elapsed = time.monotonic() - self.last_hit.get(host, 0)
        if elapsed < gap:
            time.sleep(gap - elapsed)
        self.last_hit[host] = time.monotonic()

    def get(self, url, retries=3):
        host = urlparse(url).hostname
        for attempt in range(retries):
            self._wait(host)
            try:
                resp = self.session.get(url, timeout=self.timeout)
            except requests.RequestException as exc:
                time.sleep(2 ** attempt)
                if attempt == retries - 1:
                    return None, str(exc)
                continue
            if resp.status_code in (429, 503):
                retry_after = resp.headers.get("Retry-After", "")
                wait = int(retry_after) if retry_after.isdigit() else 2 ** (attempt + 2)
                time.sleep(min(wait, 60))
                continue
            return resp, None
        return resp, "gave up after backoff"


def detect_antibot(resp):
    signals = []
    lower = {k.lower(): v for k, v in resp.headers.items()}
    for key, vendor in ANTIBOT_HEADER_HINTS.items():
        if any(h.startswith(key) for h in lower):
            signals.append(f"header:{vendor}")
    body = resp.text[:20000].lower()
    for marker in CHALLENGE_MARKERS:
        if marker in body:
            signals.append(f"marker:{marker}")
    if resp.status_code in (401, 403, 429):
        signals.append(f"status:{resp.status_code}")
    return sorted(set(signals))


def audit_headers(resp):
    lower = {k.lower() for k in resp.headers}
    return [msg for h, msg in SECURITY_HEADERS.items() if h not in lower]


def fingerprint(resp, soup):
    found = set()
    for h in ("server", "x-powered-by", "x-generator"):
        if resp.headers.get(h):
            found.add(f"{h}: {resp.headers[h]}")
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content"):
        found.add(f"generator: {gen['content']}")
    html = resp.text.lower()
    for needle, name in TECH_HINTS.items():
        if needle in html:
            found.add(name)
    return sorted(found)


def load_robots(fetcher, start_url):
    root = f"{urlparse(start_url).scheme}://{urlparse(start_url).netloc}"
    rp = RobotFileParser()
    resp, _ = fetcher.get(urljoin(root, "/robots.txt"), retries=1)
    if resp is not None and resp.status_code == 200:
        rp.parse(resp.text.splitlines())
    else:
        rp.parse([])
    return rp


def analyse_page(url, resp, soup, scope):
    links, ext = set(), set()
    for a in soup.find_all("a", href=True):
        target = urldefrag(urljoin(url, a["href"]))[0]
        if urlparse(target).scheme not in ("http", "https"):
            continue
        (links if scope.allows(target) else ext).add(target)
    forms = [{
        "action": urljoin(url, f.get("action", "")),
        "method": f.get("method", "get").lower(),
        "inputs": [i.get("name") for i in f.find_all(["input", "textarea", "select"]) if i.get("name")],
    } for f in soup.find_all("form")]
    scripts = sorted({urljoin(url, s["src"]) for s in soup.find_all("script", src=True)})
    return {
        "url": url,
        "status": resp.status_code,
        "title": (soup.title.string or "").strip() if soup.title else "",
        "tech": fingerprint(resp, soup),
        "missing_security_headers": audit_headers(resp),
        "antibot_signals": detect_antibot(resp),
        "forms": forms,
        "scripts": scripts,
        "external_links": sorted(ext),
    }, links


def crawl(start, scope, max_pages, delay, proxy, ignore_robots):
    fetcher = Fetcher(delay, proxy)
    robots = load_robots(fetcher, start)
    queue, seen, pages, skipped = deque([start]), {start}, [], []
    while queue and len(pages) < max_pages:
        url = queue.popleft()
        if not ignore_robots and not robots.can_fetch(BOT_TOKEN, url):
            skipped.append({"url": url, "reason": "disallowed by robots.txt"})
            continue
        resp, err = fetcher.get(url)
        if resp is None:
            skipped.append({"url": url, "reason": err})
            continue
        soup = BeautifulSoup(resp.text, "html.parser")
        info, links = analyse_page(url, resp, soup, scope)
        pages.append(info)
        if info["antibot_signals"]:
            # Detect and stop: we report defenses, we do not bypass them.
            skipped.append({"url": url, "reason": f"anti-bot signals {info['antibot_signals']}, stopping crawl"})
            break
        for link in links:
            if link not in seen:
                seen.add(link)
                queue.append(link)
        print(f"[{len(pages)}/{max_pages}] {resp.status_code} {url}", file=sys.stderr)
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "start": start,
        "scope": sorted(scope.hosts),
        "pages_crawled": len(pages),
        "pages": pages,
        "skipped": skipped,
    }


def main():
    p = argparse.ArgumentParser(description="Scoped recon scraper")
    p.add_argument("url")
    p.add_argument("--scope", nargs="+", help="allowed hostnames (default: host of url)")
    p.add_argument("--max-pages", type=int, default=25)
    p.add_argument("--delay", type=float, default=1.5, help="base seconds between requests per host")
    p.add_argument("--proxy", help="optional http(s) proxy, e.g. for your own lab traffic capture")
    p.add_argument("--ignore-robots", action="store_true", help="only for hosts you own")
    p.add_argument("-o", "--output", default="report.json")
    args = p.parse_args()

    host = urlparse(args.url).hostname
    scope = Scope(args.scope or [host])
    if not scope.allows(args.url):
        sys.exit("Start URL is outside the declared scope.")

    report = crawl(args.url, scope, args.max_pages, args.delay, args.proxy, args.ignore_robots)
    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"Done: {report['pages_crawled']} pages -> {args.output}")


if __name__ == "__main__":
    main()
