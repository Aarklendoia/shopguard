//! Domain history: when was the domain first seen, and has its site lived for long?
//!
//! - **Internet Archive** (Wayback Machine CDX API): the months in which the home page
//!   (`domain` and `www.domain`) was archived answering 200. Real shops have years of
//!   them; fake shops have none, or a few from a previous owner.
//! - **Certificate Transparency** through crt.sh: the first certificate ever logged for
//!   the domain. crt.sh is the only free full history and is often slow or failing:
//!   best effort, no signal when it does not answer.
//!
//! The first time the domain was seen (first certificate or first archive) stands in for
//! its age when RDAP gave none (`.de`, `.io`, `.eu`… have no public RDAP), and shows a
//! **recycled** domain: registered recently, yet seen long before (an expired domain
//! bought back for its history).
//!
//! Only the domain name is sent to these services.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode, Url, header};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::debug;

use crate::analysis::{Analyzer, BoxFuture, Signal};
use crate::rdap::{date, epoch_days, registered_day, today};

pub const WAYBACK_URL: &str = "https://web.archive.org/cdx/search/cdx";
pub const CRTSH_URL: &str = "https://crt.sh/";

const SOURCE: &str = "history";
/// History does not change much: a week, like RDAP.
const CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const CACHE_MAX: usize = 20_000;
/// Between two requests to the same service: both are free services run on donations.
const WAYBACK_SPACING: Duration = Duration::from_secs(1);
const CRTSH_SPACING: Duration = Duration::from_secs(2);
/// crt.sh answers big domains in 30 s or more, or never.
const CRTSH_TIMEOUT: Duration = Duration::from_secs(30);
/// A month per line, 15 bytes: 64 KB is over 300 years.
const WAYBACK_MAX_BODY: usize = 64 * 1024;
/// Thousands of certificates (a big site): the first one is not needed to judge it.
const CRTSH_MAX_BODY: usize = 4 * 1024 * 1024;
const BACKOFF: Duration = Duration::from_secs(300);
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// Weight of the first sighting by age in days, first match wins; only when RDAP gave
/// no registration date (it is weighted there otherwise). Lower than the RDAP weights:
/// a domain can exist unseen for a while.
const FIRST_SEEN_WEIGHTS: &[(u64, i32)] = &[(30, 30), (180, 15)];
/// Registered less than this many days ago…
const RECYCLED_REGISTERED: u64 = 365;
/// …but seen at least this many days before its registration.
const RECYCLED_GAP: u64 = 365;
const RECYCLED_WEIGHT: i32 = 20;
/// Home page never archived: no public history at all.
const ARCHIVE_NONE_WEIGHT: i32 = 10;
/// Archived live in this many months over this many years: an established site.
const ARCHIVE_LONG_MONTHS: usize = 24;
const ARCHIVE_LONG_YEARS: usize = 3;
const ARCHIVE_LONG_WEIGHT: i32 = -10;

/// Months (`YYYYMM`) in which the home page was archived answering 200.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Archive {
    months: BTreeSet<u32>,
}

/// Certificates logged for the domain.
#[derive(Debug, Clone, PartialEq)]
pub enum Certs {
    /// Day (since 1970) of the oldest `not_before`, and how many there are.
    First {
        day: u64,
        count: usize,
    },
    None,
    /// More than [`CRTSH_MAX_BODY`] of them.
    Many,
}

/// CDX answer (`fl=timestamp`): one `YYYYMMDDhhmmss` per line.
pub fn parse_cdx(body: &str) -> Archive {
    let months = body
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            (t.len() >= 6 && t.bytes().all(|b| b.is_ascii_digit()))
                .then(|| t[..6].parse().ok())
                .flatten()
        })
        .filter(|m: &u32| (1..=12).contains(&(m % 100)))
        .collect();
    Archive { months }
}

#[derive(Deserialize)]
struct CrtEntry {
    not_before: String,
}

/// crt.sh JSON answer: an array of certificates.
pub fn parse_crtsh(body: &[u8]) -> Result<Certs, String> {
    let entries: Vec<CrtEntry> =
        serde_json::from_slice(body).map_err(|e| format!("crt.sh: {e}"))?;
    let days: Vec<u64> = entries
        .iter()
        .filter_map(|e| epoch_days(&e.not_before))
        .collect();
    Ok(match days.iter().min() {
        Some(&day) => Certs::First {
            day,
            count: entries.len(),
        },
        None => Certs::None,
    })
}

fn month_day(m: u32) -> Option<u64> {
    epoch_days(&format!("{:04}-{:02}-01", m / 100, m % 100))
}

fn signal(name: &str, weight: i32, detail: String) -> Signal {
    Signal {
        source: SOURCE.into(),
        name: name.into(),
        weight,
        detail,
    }
}

/// Signals from what the services answered (`None`: no answer), the RDAP registration
/// day if known, and today (days since 1970).
pub fn signals(
    archive: Option<&Archive>,
    certs: Option<&Certs>,
    registered: Option<u64>,
    today: u64,
) -> Vec<Signal> {
    let mut out = Vec::new();

    let first_archive = archive
        .and_then(|a| a.months.first())
        .and_then(|m| month_day(*m));
    let first_cert = match certs {
        Some(Certs::First { day, .. }) => Some(*day),
        _ => None,
    };
    let first_seen = first_archive.into_iter().chain(first_cert).min();
    if let Some(seen) = first_seen {
        let age = today.saturating_sub(seen);
        let weight = if registered.is_some() {
            0
        } else {
            FIRST_SEEN_WEIGHTS
                .iter()
                .find(|(days, _)| age < *days)
                .map_or(0, |(_, w)| *w)
        };
        let mut how = Vec::new();
        if let Some(Certs::First { day, count }) = certs {
            how.push(format!("first of {count} certificates {}", date(*day)));
        }
        if let Some(d) = first_archive {
            how.push(format!("first archived {}", &date(d)[..7]));
        }
        out.push(signal(
            "first_seen_days",
            weight,
            format!("first seen {age} days ago ({})", how.join(", ")),
        ));
        if let Some(reg) = registered
            && today.saturating_sub(reg) < RECYCLED_REGISTERED
            && seen + RECYCLED_GAP <= reg
        {
            out.push(signal(
                "domain_recycled",
                RECYCLED_WEIGHT,
                format!(
                    "registered {} but seen since {}: an expired domain bought back",
                    date(reg),
                    date(seen)
                ),
            ));
        }
    }

    if let Some(a) = archive {
        let years: BTreeSet<u32> = a.months.iter().map(|m| m / 100).collect();
        if a.months.is_empty() {
            out.push(signal(
                "archive_none",
                ARCHIVE_NONE_WEIGHT,
                "home page never archived by the Internet Archive".into(),
            ));
        } else {
            let long = a.months.len() >= ARCHIVE_LONG_MONTHS && years.len() >= ARCHIVE_LONG_YEARS;
            out.push(signal(
                if long {
                    "archive_long"
                } else {
                    "archive_months"
                },
                if long { ARCHIVE_LONG_WEIGHT } else { 0 },
                format!(
                    "home page archived live in {} months over {} years",
                    a.months.len(),
                    years.len()
                ),
            ));
        }
    }
    out
}

/// A free service queried one request at a time, spaced, paused after a 429.
struct Service {
    host: &'static str,
    spacing: Duration,
    last: Option<Instant>,
    paused_until: Option<Instant>,
}

impl Service {
    fn new(host: &'static str, spacing: Duration) -> Self {
        Self {
            host,
            spacing,
            last: None,
            paused_until: None,
        }
    }

    /// Waits for the spacing; `Err` while paused.
    async fn turn(&mut self) -> Result<(), String> {
        if let Some(until) = self.paused_until {
            if Instant::now() < until {
                return Err(format!("{} rate-limits requests, try later", self.host));
            }
            self.paused_until = None;
        }
        if let Some(last) = self.last {
            tokio::time::sleep(self.spacing.saturating_sub(last.elapsed())).await;
        }
        self.last = Some(Instant::now());
        Ok(())
    }

    /// Checks the status of an answer; a 429 pauses the service.
    fn check(&mut self, resp: &reqwest::Response) -> Result<(), String> {
        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let wait = resp
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok())
                .map_or(BACKOFF, Duration::from_secs)
                .min(MAX_BACKOFF);
            self.paused_until = Some(Instant::now() + wait);
            return Err(format!("{} rate-limits requests, try later", self.host));
        }
        if status != StatusCode::OK {
            return Err(format!("{}: HTTP {status}", self.host));
        }
        Ok(())
    }
}

struct Cache<T> {
    map: HashMap<String, (Instant, T)>,
}

impl<T: Clone> Cache<T> {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    fn get(&self, k: &str) -> Option<T> {
        self.map
            .get(k)
            .filter(|(at, _)| at.elapsed() < CACHE_TTL)
            .map(|(_, v)| v.clone())
    }

    fn put(&mut self, k: &str, v: T) {
        if self.map.len() >= CACHE_MAX {
            self.map.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
            if self.map.len() >= CACHE_MAX {
                self.map.clear();
            }
        }
        self.map.insert(k.to_owned(), (Instant::now(), v));
    }
}

pub struct History {
    client: Client,
    wayback: Url,
    crtsh: Url,
    // one lock per service: a slow crt.sh does not hold the Wayback queries
    wb: Mutex<(Service, Cache<Archive>)>,
    ct: Mutex<(Service, Cache<Certs>)>,
}

impl History {
    pub fn new(client: Client, wayback: Url, crtsh: Url) -> Self {
        Self {
            client,
            wayback,
            crtsh,
            wb: Mutex::new((
                Service::new("web.archive.org", WAYBACK_SPACING),
                Cache::new(),
            )),
            ct: Mutex::new((Service::new("crt.sh", CRTSH_SPACING), Cache::new())),
        }
    }

    async fn archive(&self, domain: &str) -> Result<Archive, String> {
        let mut g = self.wb.lock().await;
        let (svc, cache) = &mut *g;
        if let Some(a) = cache.get(domain) {
            return Ok(a);
        }
        let mut all = Archive::default();
        for host in [domain.to_owned(), format!("www.{domain}")] {
            svc.turn().await?;
            let mut url = self.wayback.clone();
            url.query_pairs_mut()
                .append_pair("url", &host)
                .append_pair("fl", "timestamp")
                .append_pair("filter", "statuscode:200")
                .append_pair("collapse", "timestamp:6");
            let resp = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|e| format!("web.archive.org: {e}"))?;
            svc.check(&resp)?;
            let body = crate::http::read_limited(resp, WAYBACK_MAX_BODY).await?;
            all.months
                .extend(parse_cdx(&String::from_utf8_lossy(&body)).months);
        }
        cache.put(domain, all.clone());
        Ok(all)
    }

    async fn certs(&self, domain: &str) -> Result<Certs, String> {
        let mut g = self.ct.lock().await;
        let (svc, cache) = &mut *g;
        if let Some(c) = cache.get(domain) {
            return Ok(c);
        }
        svc.turn().await?;
        let mut url = self.crtsh.clone();
        url.query_pairs_mut()
            .append_pair("q", domain)
            .append_pair("output", "json")
            .append_pair("deduplicate", "Y");
        let resp = self
            .client
            .get(url)
            .header(header::ACCEPT, "application/json")
            .timeout(CRTSH_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("crt.sh: {e}"))?;
        svc.check(&resp)?;
        let c = match crate::http::read_limited(resp, CRTSH_MAX_BODY).await {
            Ok(body) => parse_crtsh(&body)?,
            Err(e) if e.contains("larger than") => Certs::Many,
            Err(e) => return Err(e),
        };
        cache.put(domain, c.clone());
        Ok(c)
    }
}

impl Analyzer for History {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn analyze<'a>(&'a self, domain: &'a str, earlier: &'a [Signal]) -> BoxFuture<'a, Vec<Signal>> {
        Box::pin(async move {
            let (archive, certs) = tokio::join!(self.archive(domain), self.certs(domain));
            let mut out = signals(
                archive.as_ref().ok(),
                certs.as_ref().ok(),
                registered_day(earlier),
                today(),
            );
            for e in [archive.err(), certs.err()].into_iter().flatten() {
                debug!(%domain, "history: {e}");
                out.push(signal("history_unavailable", 0, e));
            }
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::Query;
    use axum::routing::get;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn cdx_lines() {
        let a =
            parse_cdx("20190823090349\n20190901000000\n20231004094622\n\nerror\n20241300000000\n");
        assert_eq!(
            a.months.into_iter().collect::<Vec<_>>(),
            [201908, 201909, 202310]
        );
        assert!(parse_cdx("").months.is_empty());
    }

    #[test]
    fn crtsh_answers() {
        let body = br#"[{"issuer_ca_id":1,"not_before":"2021-05-02T10:00:00","not_after":"2021-07-31T10:00:00"},
                        {"issuer_ca_id":1,"not_before":"2016-03-30T00:00:00"}]"#;
        assert_eq!(
            parse_crtsh(body).unwrap(),
            Certs::First {
                day: epoch_days("2016-03-30").unwrap(),
                count: 2
            }
        );
        assert_eq!(parse_crtsh(b"[]").unwrap(), Certs::None);
        assert!(parse_crtsh(b"<html>502 Bad Gateway").is_err());
    }

    fn months(ms: &[u32]) -> Archive {
        Archive {
            months: ms.iter().copied().collect(),
        }
    }

    fn weights(s: &[Signal]) -> Vec<(&str, i32)> {
        s.iter().map(|s| (s.name.as_str(), s.weight)).collect()
    }

    const TODAY: &str = "2026-11-17";

    fn t() -> u64 {
        epoch_days(TODAY).unwrap()
    }

    #[test]
    fn new_domain_without_rdap() {
        // drmartensberlin.de style, but brand new: first certificate 20 days ago
        let c = Certs::First {
            day: t() - 20,
            count: 3,
        };
        let s = signals(Some(&months(&[])), Some(&c), None, t());
        assert_eq!(weights(&s), [("first_seen_days", 30), ("archive_none", 10)]);
        assert_eq!(
            s[0].detail,
            "first seen 20 days ago (first of 3 certificates 2026-10-28)"
        );
        // RDAP already weighted the age: no second time
        let s = signals(Some(&months(&[])), Some(&c), Some(t() - 20), t());
        assert_eq!(weights(&s), [("first_seen_days", 0), ("archive_none", 10)]);
    }

    #[test]
    fn recycled_domain() {
        // registered 2 months ago, home page archived in 2019 and 2023
        let s = signals(
            Some(&months(&[201908, 201909, 202310])),
            None,
            Some(t() - 60),
            t(),
        );
        assert_eq!(
            weights(&s),
            [
                ("first_seen_days", 0),
                ("domain_recycled", 20),
                ("archive_months", 0)
            ]
        );
        assert_eq!(
            s[1].detail,
            "registered 2026-09-18 but seen since 2019-08-01: an expired domain bought back"
        );
        // a domain renewed for years is not recycled
        let s = signals(Some(&months(&[201908])), None, Some(t() - 3000), t());
        assert!(!s.iter().any(|s| s.name == "domain_recycled"));
    }

    #[test]
    fn established_site() {
        let ms: Vec<u32> = (2015..=2026)
            .flat_map(|y| (1..=6).map(move |m| y * 100 + m))
            .collect();
        let c = Certs::First {
            day: epoch_days("2016-03-30").unwrap(),
            count: 459,
        };
        let s = signals(Some(&months(&ms)), Some(&c), None, t());
        assert_eq!(weights(&s), [("first_seen_days", 0), ("archive_long", -10)]);
        assert!(
            s[0].detail.contains("first archived 2015-01"),
            "{}",
            s[0].detail
        );
        // 23 months: not yet
        let s = signals(Some(&months(&ms[..23])), None, Some(0), t());
        assert_eq!(s[1].name, "archive_months");
    }

    #[test]
    fn nothing_answered() {
        assert!(signals(None, None, None, t()).is_empty());
        // crt.sh too big, Wayback down: nothing to say
        assert!(signals(None, Some(&Certs::Many), None, t()).is_empty());
    }

    async fn serve(app: Router) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn queries_and_cache() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = Router::new()
            .route(
                "/cdx",
                get(move |Query(q): Query<HashMap<String, String>>| {
                    let h = h.clone();
                    async move {
                        h.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(q["filter"], "statuscode:200");
                        match q["url"].as_str() {
                            "shop.fr" => "20240105000000\n",
                            "www.shop.fr" => "20240210000000\n20250101000000\n",
                            _ => "",
                        }
                    }
                }),
            )
            .route(
                "/crt",
                get(|Query(q): Query<HashMap<String, String>>| async move {
                    assert_eq!(q["output"], "json");
                    assert_eq!(q["q"], "shop.fr");
                    r#"[{"not_before":"2023-12-20T00:00:00"}]"#
                }),
            );
        let base = serve(app).await;
        let hist = History::new(
            crate::http::test_client(),
            Url::parse(&format!("{base}cdx")).unwrap(),
            Url::parse(&format!("{base}crt")).unwrap(),
        );
        let s = hist.analyze("shop.fr", &[]).await;
        assert_eq!(s[0].name, "first_seen_days");
        assert!(s[0].detail.contains("2023-12-20"), "{}", s[0].detail);
        assert_eq!(
            s[1].detail,
            "home page archived live in 3 months over 2 years"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        hist.analyze("shop.fr", &[]).await;
        assert_eq!(hits.load(Ordering::SeqCst), 2, "cached");
    }

    #[tokio::test]
    async fn failures_are_no_signal() {
        let app = Router::new()
            .route(
                "/cdx",
                get(|| async {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(header::RETRY_AFTER, "120")],
                        "slow down",
                    )
                }),
            )
            .route("/crt", get(|| async { (StatusCode::BAD_GATEWAY, "502") }));
        let base = serve(app).await;
        let hist = History::new(
            crate::http::test_client(),
            Url::parse(&format!("{base}cdx")).unwrap(),
            Url::parse(&format!("{base}crt")).unwrap(),
        );
        let s = hist.analyze("shop.fr", &[]).await;
        assert_eq!(
            weights(&s),
            [("history_unavailable", 0), ("history_unavailable", 0)]
        );
        assert!(s[0].detail.contains("rate-limits"), "{}", s[0].detail);
        assert!(s[1].detail.contains("502"), "{}", s[1].detail);
        // paused: the next domain does not even ask
        let s = hist.analyze("other.fr", &[]).await;
        assert!(s[0].detail.contains("rate-limits"), "{}", s[0].detail);
    }
}
