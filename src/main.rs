//! recon-scraper: a scoped, polite web recon crawler.
//!
//! * Crawls only hosts you allowlist (redirects out of scope are refused)
//! * Obeys robots.txt (including `*` and `$` wildcards)
//! * Per-host rate limiting with jitter, backoff on 429/503, `Retry-After` support
//! * DETECTS anti-bot defenses and reports them. It never tries to bypass them:
//!   when a challenge/block is seen, the crawl stops.
//! * Fingerprints tech stack, audits security headers, inventories links/forms/scripts
//!
//! Only run it against hosts you own or that explicitly permit scraping.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use futures::stream::{self, StreamExt};
use rand::Rng;
use reqwest::header::{HeaderMap, CONTENT_TYPE, LOCATION, RETRY_AFTER};
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use scraper::{Html, Selector};
use serde::Serialize;
use tokio::sync::Mutex;
use url::Url;

const BOT_TOKEN: &str = "ReconScraper";
// Honest identification: we do not pretend to be a browser.
const USER_AGENT: &str = "ReconScraper/1.0 (+portfolio project)";

const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "HSTS missing: no forced HTTPS"),
    ("content-security-policy", "CSP missing: weaker XSS mitigation"),
    ("x-frame-options", "X-Frame-Options missing: clickjacking risk (unless CSP frame-ancestors)"),
    ("x-content-type-options", "X-Content-Type-Options missing: MIME sniffing allowed"),
    ("referrer-policy", "Referrer-Policy missing"),
    ("permissions-policy", "Permissions-Policy missing"),
];

/// Header prefixes that reveal a CDN/WAF is in front of the site. Informational only:
/// being behind Cloudflare is not the same as being blocked by it.
const PROTECTION_HINTS: &[(&str, &str)] = &[
    ("cf-ray", "Cloudflare"),
    ("x-sucuri-id", "Sucuri WAF"),
    ("x-akamai", "Akamai"),
    ("x-datadome", "DataDome"),
    ("x-px-", "PerimeterX/HUMAN"),
    ("x-amzn-waf", "AWS WAF"),
];

/// Signals that we are actually being challenged or blocked. These stop the crawl.
const CHALLENGE_MARKERS: &[&str] = &[
    "g-recaptcha",
    "h-captcha",
    "cf-turnstile",
    "just a moment...",
    "attention required",
    "verify you are human",
];

const TECH_HINTS: &[(&str, &str)] = &[
    ("wp-content", "WordPress"),
    ("/_next/", "Next.js"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
    ("__nuxt", "Nuxt"),
    ("cdn.shopify.com", "Shopify"),
    ("jquery", "jQuery"),
    ("bootstrap", "Bootstrap"),
];

#[derive(Parser)]
#[command(version, about = "Scoped, polite web recon crawler (detects anti-bot defenses, never bypasses them)")]
struct Args {
    /// Start URL
    url: String,
    /// Allowed hostnames (default: host of the start URL)
    #[arg(long, num_args = 1..)]
    scope: Vec<String>,
    #[arg(long, default_value_t = 25)]
    max_pages: usize,
    /// Base seconds between requests per host (jittered)
    #[arg(long, default_value_t = 1.5)]
    delay: f64,
    /// Concurrent in-flight requests (the per-host delay still applies)
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Optional proxy, e.g. for capturing your own lab traffic
    #[arg(long)]
    proxy: Option<String>,
    /// Ignore robots.txt (only for hosts you own)
    #[arg(long)]
    ignore_robots: bool,
    #[arg(short, long, default_value = "report.json")]
    output: String,
}

#[derive(Serialize, Debug)]
struct FormInfo {
    action: String,
    method: String,
    inputs: Vec<String>,
}

#[derive(Serialize, Debug)]
struct PageInfo {
    url: String,
    status: u16,
    title: String,
    tech: Vec<String>,
    missing_security_headers: Vec<String>,
    protection_vendors: Vec<String>,
    block_signals: Vec<String>,
    forms: Vec<FormInfo>,
    scripts: Vec<String>,
    external_links: Vec<String>,
}

#[derive(Serialize)]
struct Skipped {
    url: String,
    reason: String,
}

#[derive(Serialize)]
struct Report {
    generated: String,
    start: String,
    scope: Vec<String>,
    pages_crawled: usize,
    pages: Vec<PageInfo>,
    skipped: Vec<Skipped>,
}

// ---------------------------------------------------------------- rate limiting

/// Reserves time slots per host so requests are spaced out even when many run concurrently.
struct Limiter {
    delay: f64,
    next_slot: Mutex<HashMap<String, Instant>>,
}

impl Limiter {
    fn new(delay: f64) -> Self {
        Self { delay, next_slot: Mutex::new(HashMap::new()) }
    }

    async fn wait(&self, host: &str) {
        let slot = {
            let mut map = self.next_slot.lock().await;
            let now = Instant::now();
            let slot = map.get(host).copied().filter(|t| *t > now).unwrap_or(now);
            let gap = self.delay * rand::thread_rng().gen_range(0.8..1.6);
            map.insert(host.to_string(), slot + Duration::from_secs_f64(gap));
            slot
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(slot)).await;
    }
}

// ---------------------------------------------------------------- fetching

struct Fetched {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn fetch(
    client: &Client,
    limiter: &Limiter,
    url: &Url,
    retries: u32,
    require_html: bool,
) -> Result<Fetched, String> {
    let host = url.host_str().unwrap_or("").to_string();
    let mut last_err = String::from("request failed");
    for attempt in 0..retries {
        limiter.wait(&host).await;
        let resp = match client.get(url.clone()).send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = e.to_string();
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                continue;
            }
        };
        let status = resp.status();
        let retryable = status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE;
        if retryable && attempt + 1 < retries {
            let wait = resp
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1u64 << (attempt + 2));
            tokio::time::sleep(Duration::from_secs(wait.min(60))).await;
            continue;
        }
        if status.is_redirection() {
            let to = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("?");
            return Err(format!("redirect to {to} not followed (out of scope)"));
        }
        let headers = resp.headers().clone();
        if require_html && status.is_success() {
            let ctype = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
            if !ctype.to_lowercase().contains("html") {
                return Err(format!("non-HTML content-type: {ctype}"));
            }
        }
        let body = resp.text().await.map_err(|e| e.to_string())?;
        return Ok(Fetched { status, headers, body });
    }
    Err(last_err)
}

// ---------------------------------------------------------------- robots.txt

struct Robots {
    rules: Vec<(bool, String)>, // (is_allow, pattern)
}

fn pattern_matches(pattern: &str, path: &str) -> bool {
    let (pat, anchored) = match pattern.strip_suffix('$') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let parts: Vec<&str> = pat.split('*').collect();
    let n = parts.len();
    if !path.starts_with(parts[0]) {
        return false;
    }
    let mut pos = parts[0].len();
    if n == 1 {
        return !anchored || pos == path.len();
    }
    for part in &parts[1..n - 1] {
        match path[pos..].find(part) {
            Some(i) => pos += i + part.len(),
            None => return false,
        }
    }
    let last = parts[n - 1];
    if anchored {
        path.len() >= pos + last.len() && path.ends_with(last)
    } else {
        path[pos..].contains(last)
    }
}

impl Robots {
    fn parse(text: &str) -> Self {
        let mut groups: Vec<(Vec<String>, Vec<(bool, String)>)> = Vec::new();
        let mut agents: Vec<String> = Vec::new();
        let mut rules: Vec<(bool, String)> = Vec::new();
        let mut in_rules = false;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let Some((k, v)) = line.split_once(':') else { continue };
            let (k, v) = (k.trim().to_lowercase(), v.trim());
            match k.as_str() {
                "user-agent" => {
                    if in_rules {
                        groups.push((std::mem::take(&mut agents), std::mem::take(&mut rules)));
                        in_rules = false;
                    }
                    agents.push(v.to_lowercase());
                }
                "allow" | "disallow" => {
                    in_rules = true;
                    if !v.is_empty() {
                        rules.push((k == "allow", v.to_string()));
                    }
                }
                _ => {}
            }
        }
        if !agents.is_empty() {
            groups.push((agents, rules));
        }
        let token = BOT_TOKEN.to_lowercase();
        let specific = groups
            .iter()
            .find(|(a, _)| a.iter().any(|x| x != "*" && token.contains(x.as_str())));
        let chosen = specific.or_else(|| groups.iter().find(|(a, _)| a.iter().any(|x| x == "*")));
        Robots { rules: chosen.map(|g| g.1.clone()).unwrap_or_default() }
    }

    /// Longest matching rule wins; on a tie, Allow wins; no match means allowed.
    fn allows(&self, path_and_query: &str) -> bool {
        let mut best: Option<(usize, bool)> = None;
        for (allow, pattern) in &self.rules {
            if pattern_matches(pattern, path_and_query) {
                let len = pattern.len();
                match best {
                    Some((l, a)) if l > len || (l == len && a) => {}
                    _ => best = Some((len, *allow)),
                }
            }
        }
        best.map(|b| b.1).unwrap_or(true)
    }
}

fn path_and_query(u: &Url) -> String {
    match u.query() {
        Some(q) => format!("{}?{}", u.path(), q),
        None => u.path().to_string(),
    }
}

// ---------------------------------------------------------------- analysis

fn protection_vendors(headers: &HeaderMap) -> Vec<String> {
    let mut found = BTreeSet::new();
    for (name, _) in headers.iter() {
        for (prefix, vendor) in PROTECTION_HINTS {
            if name.as_str().starts_with(prefix) {
                found.insert((*vendor).to_string());
            }
        }
    }
    found.into_iter().collect()
}

fn detect_block_signals(status: StatusCode, headers: &HeaderMap, body: &str) -> Vec<String> {
    let mut s = BTreeSet::new();
    if headers.contains_key("cf-mitigated") {
        s.insert("header:cf-mitigated (Cloudflare challenge issued)".to_string());
    }
    let head: String = body.chars().take(20_000).collect::<String>().to_lowercase();
    for m in CHALLENGE_MARKERS {
        if head.contains(m) {
            s.insert(format!("marker:{m}"));
        }
    }
    if matches!(status.as_u16(), 401 | 403 | 429) {
        s.insert(format!("status:{}", status.as_u16()));
    }
    s.into_iter().collect()
}

fn audit_headers(headers: &HeaderMap) -> Vec<String> {
    SECURITY_HEADERS
        .iter()
        .filter(|(h, _)| !headers.contains_key(*h))
        .map(|(_, msg)| (*msg).to_string())
        .collect()
}

fn fingerprint(headers: &HeaderMap, doc: &Html, body_lower: &str) -> Vec<String> {
    let mut found = BTreeSet::new();
    for h in ["server", "x-powered-by", "x-generator"] {
        if let Some(v) = headers.get(h).and_then(|v| v.to_str().ok()) {
            found.insert(format!("{h}: {v}"));
        }
    }
    let gen_sel = Selector::parse(r#"meta[name="generator"]"#).unwrap();
    if let Some(content) = doc.select(&gen_sel).next().and_then(|m| m.value().attr("content")) {
        found.insert(format!("generator: {content}"));
    }
    for (needle, name) in TECH_HINTS {
        if body_lower.contains(needle) {
            found.insert((*name).to_string());
        }
    }
    found.into_iter().collect()
}

fn analyse(url: &Url, f: &Fetched, scope: &HashSet<String>) -> (PageInfo, Vec<Url>) {
    let doc = Html::parse_document(&f.body);
    let a_sel = Selector::parse("a[href]").unwrap();
    let form_sel = Selector::parse("form").unwrap();
    let input_sel = Selector::parse("input, textarea, select").unwrap();
    let script_sel = Selector::parse("script[src]").unwrap();
    let title_sel = Selector::parse("title").unwrap();

    let mut internal: Vec<Url> = Vec::new();
    let mut external = BTreeSet::new();
    let mut seen_internal = HashSet::new();
    for a in doc.select(&a_sel) {
        let Some(href) = a.value().attr("href") else { continue };
        let Ok(mut target) = url.join(href) else { continue };
        if !matches!(target.scheme(), "http" | "https") {
            continue;
        }
        target.set_fragment(None);
        let in_scope = target.host_str().map(|h| scope.contains(&h.to_lowercase())).unwrap_or(false);
        if in_scope {
            if seen_internal.insert(target.to_string()) {
                internal.push(target);
            }
        } else {
            external.insert(target.to_string());
        }
    }

    let forms = doc
        .select(&form_sel)
        .map(|f| {
            let action = f.value().attr("action").unwrap_or("");
            FormInfo {
                action: url.join(action).map(|u| u.to_string()).unwrap_or_else(|_| action.to_string()),
                method: f.value().attr("method").unwrap_or("get").to_lowercase(),
                inputs: f
                    .select(&input_sel)
                    .filter_map(|i| i.value().attr("name").map(String::from))
                    .collect(),
            }
        })
        .collect();

    let scripts: BTreeSet<String> = doc
        .select(&script_sel)
        .filter_map(|s| s.value().attr("src"))
        .filter_map(|src| url.join(src).ok())
        .map(|u| u.to_string())
        .collect();

    let title = doc
        .select(&title_sel)
        .next()
        .map(|t| t.text().collect::<String>().trim().to_string())
        .unwrap_or_default();

    let info = PageInfo {
        url: url.to_string(),
        status: f.status.as_u16(),
        title,
        tech: fingerprint(&f.headers, &doc, &f.body.to_lowercase()),
        missing_security_headers: audit_headers(&f.headers),
        protection_vendors: protection_vendors(&f.headers),
        block_signals: detect_block_signals(f.status, &f.headers, &f.body),
        forms,
        scripts: scripts.into_iter().collect(),
        external_links: external.into_iter().collect(),
    };
    (info, internal)
}

// ---------------------------------------------------------------- crawl

enum Outcome {
    Fetched(Fetched),
    Skipped(String),
}

async fn crawl(args: &Args, start: Url, scope: Arc<HashSet<String>>) -> Result<Report, Box<dyn std::error::Error>> {
    let redirect_scope = scope.clone();
    let mut builder = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(15))
        .redirect(Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error("too many redirects");
            }
            let ok = attempt
                .url()
                .host_str()
                .map(|h| redirect_scope.contains(&h.to_lowercase()))
                .unwrap_or(false);
            if ok {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }));
    if let Some(p) = &args.proxy {
        builder = builder.proxy(reqwest::Proxy::all(p)?);
    }
    let client = builder.build()?;
    let limiter = Limiter::new(args.delay);

    let robots = {
        let robots_url = start.join("/robots.txt")?;
        match fetch(&client, &limiter, &robots_url, 1, false).await {
            Ok(f) if f.status == StatusCode::OK => Robots::parse(&f.body),
            _ => Robots { rules: Vec::new() },
        }
    };

    let mut seen: HashSet<String> = HashSet::from([start.to_string()]);
    let mut frontier: VecDeque<Url> = VecDeque::from([start.clone()]);
    let mut pages: Vec<PageInfo> = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();
    let mut stop = false;

    while !frontier.is_empty() && pages.len() < args.max_pages && !stop {
        let room = args.max_pages - pages.len();
        let take = room.min(frontier.len());
        let batch: Vec<Url> = frontier.drain(..take).collect();

        let results: Vec<(Url, Outcome)> = stream::iter(batch)
            .map(|u| {
                let (client, limiter, robots) = (&client, &limiter, &robots);
                let ignore_robots = args.ignore_robots;
                async move {
                    if !ignore_robots && !robots.allows(&path_and_query(&u)) {
                        return (u, Outcome::Skipped("disallowed by robots.txt".into()));
                    }
                    match fetch(client, limiter, &u, 3, true).await {
                        Ok(f) => (u, Outcome::Fetched(f)),
                        Err(e) => (u, Outcome::Skipped(e)),
                    }
                }
            })
            .buffered(args.workers.max(1)) // concurrent, but results keep input order
            .collect()
            .await;

        for (u, outcome) in results {
            match outcome {
                Outcome::Skipped(reason) => skipped.push(Skipped { url: u.to_string(), reason }),
                Outcome::Fetched(f) => {
                    let (info, links) = analyse(&u, &f, &scope);
                    eprintln!("[{}/{}] {} {}", pages.len() + 1, args.max_pages, info.status, info.url);
                    let blocked = !info.block_signals.is_empty();
                    if blocked {
                        // Detect and stop: we report defenses, we do not bypass them.
                        skipped.push(Skipped {
                            url: u.to_string(),
                            reason: format!("block signals {:?}, stopping crawl", info.block_signals),
                        });
                    }
                    pages.push(info);
                    if blocked {
                        stop = true;
                        break;
                    }
                    for link in links {
                        if seen.insert(link.to_string()) {
                            frontier.push_back(link);
                        }
                    }
                }
            }
        }
    }

    let mut scope_list: Vec<String> = scope.iter().cloned().collect();
    scope_list.sort();
    Ok(Report {
        generated: chrono::Utc::now().to_rfc3339(),
        start: start.to_string(),
        scope: scope_list,
        pages_crawled: pages.len(),
        pages,
        skipped,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let start = Url::parse(&args.url)?;
    if !matches!(start.scheme(), "http" | "https") {
        return Err("start URL must be http or https".into());
    }
    let start_host = start.host_str().ok_or("start URL has no host")?.to_lowercase();
    let scope: HashSet<String> = if args.scope.is_empty() {
        HashSet::from([start_host.clone()])
    } else {
        args.scope.iter().map(|h| h.to_lowercase()).collect()
    };
    if !scope.contains(&start_host) {
        return Err("start URL is outside the declared scope".into());
    }

    let report = crawl(&args, start, Arc::new(scope)).await?;
    std::fs::write(&args.output, serde_json::to_string_pretty(&report)?)?;
    println!("Done: {} pages -> {}", report.pages_crawled, args.output);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_patterns() {
        assert!(pattern_matches("/private/", "/private/a.html"));
        assert!(!pattern_matches("/private/", "/public/a.html"));
        assert!(pattern_matches("/*.pdf$", "/docs/file.pdf"));
        assert!(!pattern_matches("/*.pdf$", "/docs/file.pdf?x=1"));
        assert!(pattern_matches("/*?session=", "/a/b?session=9"));
    }

    #[test]
    fn robots_longest_match_wins() {
        let r = Robots::parse("User-agent: *\nDisallow: /private/\nAllow: /private/open/\n");
        assert!(!r.allows("/private/secret"));
        assert!(r.allows("/private/open/page"));
        assert!(r.allows("/index.html"));
    }

    #[test]
    fn robots_specific_group_beats_wildcard() {
        let r = Robots::parse("User-agent: *\nDisallow:\n\nUser-agent: ReconScraper\nDisallow: /\n");
        assert!(!r.allows("/anything"));
    }

    #[test]
    fn block_signals_ignore_plain_cdn_headers() {
        let mut h = HeaderMap::new();
        h.insert("cf-ray", "abc".parse().unwrap());
        assert!(detect_block_signals(StatusCode::OK, &h, "<html>hello</html>").is_empty());
        assert_eq!(protection_vendors(&h), vec!["Cloudflare".to_string()]);
        let s = detect_block_signals(StatusCode::FORBIDDEN, &h, "<div class=\"g-recaptcha\"></div>");
        assert!(s.contains(&"status:403".to_string()));
        assert!(s.contains(&"marker:g-recaptcha".to_string()));
    }
}
