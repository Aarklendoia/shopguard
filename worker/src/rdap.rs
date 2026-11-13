//! Domain registration age through RDAP (the JSON successor of whois).
//!
//! The RDAP server of each TLD comes from the IANA bootstrap file, cached for a day.
//! A fake shop usually runs on a domain registered a few days or weeks earlier, often a
//! recycled one bought back after it expired: its registration date is then recent too.
//! Registrant data is not used: GDPR redaction is the norm in Europe.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::{Client, StatusCode, Url, header};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::debug;

use crate::analysis::{Analyzer, BoxFuture, Signal};
use crate::http;

pub const BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_TTL: Duration = Duration::from_secs(24 * 3600);
/// Registration dates do not change, unless the domain is dropped and registered again.
const CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const CACHE_MAX: usize = 20_000;
/// A 429 asking to wait at most this long is waited for, once; longer, the server is
/// skipped until then.
const MAX_WAIT: Duration = Duration::from_secs(30);
const DEFAULT_BACKOFF: Duration = Duration::from_secs(300);
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// Weights by registration age, first match wins. To tune with the feedback of #12.
const AGE_WEIGHTS: &[(u64, i32)] = &[
    (30, 40),  // less than a month: the typical fake shop
    (180, 20), // less than six months
    (365, 5),  // less than a year
];
/// A domain held for at least five years leans legitimate (a takeover by purchase keeps
/// the date, hence the small weight).
const OLD_DAYS: u64 = 5 * 365;
const OLD_WEIGHT: i32 = -10;
/// Re-registered within this many days (event `reregistration`).
const REREGISTERED_DAYS: u64 = 180;
const REREGISTERED_WEIGHT: i32 = 25;

const SOURCE: &str = "rdap";

/// IANA bootstrap: which RDAP servers serve which TLDs (RFC 9224).
#[derive(Debug, Default)]
struct Bootstrap {
    servers: HashMap<String, Url>,
}

#[derive(Deserialize)]
struct BootstrapFile {
    services: Vec<(Vec<String>, Vec<String>)>,
}

impl Bootstrap {
    fn parse(body: &[u8]) -> Result<Self, String> {
        let file: BootstrapFile = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        let mut servers = HashMap::new();
        for (tlds, urls) in file.services {
            // HTTPS only; the base URL must end with '/' for Url::join
            let Some(url) = urls
                .iter()
                .filter_map(|u| {
                    let u = if u.ends_with('/') {
                        u.clone()
                    } else {
                        format!("{u}/")
                    };
                    http::checked_url(&u)
                })
                .next()
            else {
                continue;
            };
            for tld in tlds {
                servers.insert(tld.to_ascii_lowercase(), url.clone());
            }
        }
        Ok(Self { servers })
    }

    /// Server for `domain`: the longest entry matching its trailing labels.
    fn server(&self, domain: &str) -> Option<&Url> {
        let mut rest = domain;
        loop {
            if let Some(u) = self.servers.get(rest) {
                return Some(u);
            }
            rest = rest.split_once('.')?.1;
        }
    }
}

/// What RDAP says about a domain.
#[derive(Debug, Clone, PartialEq)]
enum Lookup {
    Found {
        /// Days since the Unix epoch.
        registered: Option<u64>,
        reregistered: Option<u64>,
    },
    NotFound,
}

#[derive(Deserialize)]
struct DomainResponse {
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(rename = "eventAction")]
    action: String,
    #[serde(rename = "eventDate")]
    date: String,
}

fn parse_domain(body: &[u8]) -> Result<Lookup, String> {
    let r: DomainResponse = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let latest = |action: &str| {
        r.events
            .iter()
            .filter(|e| e.action.eq_ignore_ascii_case(action))
            .filter_map(|e| epoch_days(&e.date))
            .max()
    };
    Ok(Lookup::Found {
        registered: latest("registration"),
        reregistered: latest("reregistration"),
    })
}

/// Days since 1970-01-01 of an RFC 3339 date (`2024-03-05T10:00:00Z`); the time of day
/// does not matter here.
fn epoch_days(date: &str) -> Option<u64> {
    let d = date.get(..10)?;
    let mut parts = d.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    // days_from_civil (Howard Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
}

fn today() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

fn signal(name: &str, weight: i32, detail: String) -> Signal {
    Signal {
        source: SOURCE.into(),
        name: name.into(),
        weight,
        detail,
    }
}

fn date(days: u64) -> String {
    // inverse of epoch_days (civil_from_days)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Signals for a lookup made on day `today`.
fn signals(lookup: &Lookup, today: u64) -> Vec<Signal> {
    let (registered, reregistered) = match lookup {
        Lookup::NotFound => {
            return vec![signal(
                "domain_not_found",
                0,
                "not found in the registry RDAP".into(),
            )];
        }
        Lookup::Found {
            registered,
            reregistered,
        } => (*registered, *reregistered),
    };
    let mut out = Vec::new();
    match registered {
        None => out.push(signal(
            "domain_age_unknown",
            0,
            "no registration date in RDAP".into(),
        )),
        Some(r) => {
            let age = today.saturating_sub(r);
            let weight = AGE_WEIGHTS
                .iter()
                .find(|(days, _)| age < *days)
                .map(|(_, w)| *w)
                .unwrap_or(if age >= OLD_DAYS { OLD_WEIGHT } else { 0 });
            out.push(signal(
                "domain_age_days",
                weight,
                format!("registered {age} days ago ({})", date(r)),
            ));
        }
    }
    if let Some(rr) = reregistered {
        let age = today.saturating_sub(rr);
        if age < REREGISTERED_DAYS {
            out.push(signal(
                "domain_reregistered",
                REREGISTERED_WEIGHT,
                format!("registered again {age} days ago ({})", date(rr)),
            ));
        }
    }
    out
}

/// Seconds of a `Retry-After` header (the HTTP-date form is rare for RDAP: default).
fn retry_after(resp: &reqwest::Response) -> Duration {
    resp.headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_BACKOFF)
        .min(MAX_BACKOFF)
}

#[derive(Default)]
struct State {
    bootstrap: Option<(Instant, Bootstrap)>,
    cache: HashMap<String, (Instant, Lookup)>,
    /// RDAP host → no request before this instant (after a 429).
    backoff: HashMap<String, Instant>,
}

pub struct Rdap {
    client: Client,
    bootstrap_url: Url,
    state: Mutex<State>,
}

/// Why no signal could be computed. Reported as a weight-0 signal.
enum Failure {
    NoServer(String),
    RateLimited(String),
    Error(String),
}

impl Rdap {
    pub fn new(client: Client, bootstrap_url: Url) -> Self {
        Self {
            client,
            bootstrap_url,
            state: Mutex::default(),
        }
    }

    async fn server(&self, state: &mut State, domain: &str) -> Result<Url, Failure> {
        let fresh = state
            .bootstrap
            .as_ref()
            .is_some_and(|(at, _)| at.elapsed() < BOOTSTRAP_TTL);
        if !fresh {
            match self.fetch_bootstrap().await {
                Ok(b) => state.bootstrap = Some((Instant::now(), b)),
                // keep a stale copy rather than nothing
                Err(e) if state.bootstrap.is_none() => return Err(Failure::Error(e)),
                Err(e) => debug!("RDAP bootstrap refresh failed, keeping the old one: {e}"),
            }
        }
        let b = &state.bootstrap.as_ref().expect("set above").1;
        b.server(domain).cloned().ok_or_else(|| {
            let tld = domain.rsplit('.').next().unwrap_or(domain);
            Failure::NoServer(tld.into())
        })
    }

    async fn fetch_bootstrap(&self) -> Result<Bootstrap, String> {
        let resp = self
            .client
            .get(self.bootstrap_url.clone())
            .send()
            .await
            .map_err(|e| format!("bootstrap: {e}"))?
            .error_for_status()
            .map_err(|e| format!("bootstrap: {e}"))?;
        let body = resp.bytes().await.map_err(|e| format!("bootstrap: {e}"))?;
        Bootstrap::parse(&body)
    }

    async fn lookup(&self, domain: &str) -> Result<Lookup, Failure> {
        let mut state = self.state.lock().await;
        if let Some((at, l)) = state.cache.get(domain)
            && at.elapsed() < CACHE_TTL
        {
            return Ok(l.clone());
        }
        let base = self.server(&mut state, domain).await?;
        let host = base.host_str().unwrap_or_default().to_owned();
        if let Some(until) = state.backoff.get(&host) {
            if Instant::now() < *until {
                return Err(Failure::RateLimited(host));
            }
            state.backoff.remove(&host);
        }
        let url = base
            .join(&format!("domain/{domain}"))
            .map_err(|e| Failure::Error(e.to_string()))?;

        let mut waited = false;
        let resp = loop {
            let resp = self
                .client
                .get(url.clone())
                .header(header::ACCEPT, "application/rdap+json, application/json")
                .send()
                .await
                .map_err(|e| Failure::Error(format!("{host}: {e}")))?;
            if resp.status() != StatusCode::TOO_MANY_REQUESTS {
                break resp;
            }
            let wait = retry_after(&resp);
            if waited || wait > MAX_WAIT {
                state.backoff.insert(host.clone(), Instant::now() + wait);
                return Err(Failure::RateLimited(host));
            }
            debug!(%host, ?wait, "RDAP rate limit, waiting");
            tokio::time::sleep(wait).await;
            waited = true;
        };

        let lookup = match resp.status() {
            StatusCode::NOT_FOUND => Lookup::NotFound,
            s if s.is_success() => {
                let body = resp
                    .bytes()
                    .await
                    .map_err(|e| Failure::Error(format!("{host}: {e}")))?;
                parse_domain(&body).map_err(|e| Failure::Error(format!("{host}: {e}")))?
            }
            s => return Err(Failure::Error(format!("{host}: HTTP {s}"))),
        };
        if state.cache.len() >= CACHE_MAX {
            state.cache.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
            if state.cache.len() >= CACHE_MAX {
                state.cache.clear();
            }
        }
        state
            .cache
            .insert(domain.to_owned(), (Instant::now(), lookup.clone()));
        Ok(lookup)
    }
}

/// True when the registrable domain sits under a private suffix of the PSL
/// (`shop.myshopify.com`): the registry only knows the platform's own domain.
fn under_private_suffix(domain: &str) -> bool {
    psl::suffix(domain.as_bytes()).and_then(|s| s.typ()) == Some(psl::Type::Private)
}

impl Analyzer for Rdap {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn analyze<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<Signal>> {
        Box::pin(async move {
            if under_private_suffix(domain) {
                return Vec::new();
            }
            match self.lookup(domain).await {
                Ok(l) => signals(&l, today()),
                Err(Failure::NoServer(tld)) => vec![signal(
                    "rdap_unavailable",
                    0,
                    format!("no RDAP service for .{tld}"),
                )],
                Err(Failure::RateLimited(host)) => vec![signal(
                    "rdap_unavailable",
                    0,
                    format!("{host} rate-limits requests, try later"),
                )],
                Err(Failure::Error(e)) => {
                    debug!(%domain, "RDAP lookup failed: {e}");
                    vec![signal("rdap_error", 0, format!("RDAP lookup failed: {e}"))]
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOTSTRAP: &str = r#"{
      "version": "1.0",
      "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["fr"], ["http://rdap.nic.fr", "https://rdap.nic.fr"]],
        [["evil"], ["https://127.0.0.1/"]],
        [["co.example"], ["https://rdap.example/"]]
      ]
    }"#;

    #[test]
    fn bootstrap_picks_https_public_servers() {
        let b = Bootstrap::parse(BOOTSTRAP.as_bytes()).unwrap();
        assert_eq!(
            b.server("shop.com").unwrap().as_str(),
            "https://rdap.verisign.com/com/v1/"
        );
        // http entry skipped, trailing slash added
        assert_eq!(
            b.server("boutique.fr").unwrap().as_str(),
            "https://rdap.nic.fr/"
        );
        assert!(b.server("x.evil").is_none());
        assert!(b.server("x.de").is_none());
        // longest match
        assert_eq!(
            b.server("a.co.example").unwrap().as_str(),
            "https://rdap.example/"
        );
        assert_eq!(
            b.server("shop.com")
                .unwrap()
                .join("domain/shop.com")
                .unwrap()
                .as_str(),
            "https://rdap.verisign.com/com/v1/domain/shop.com"
        );
    }

    #[test]
    fn dates() {
        assert_eq!(epoch_days("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_days("2000-03-01T12:00:00.000+01:00"), Some(11_017));
        assert_eq!(epoch_days("2026-11-13"), Some(20_770));
        assert_eq!(epoch_days("2026-13-01"), None);
        assert_eq!(epoch_days("garbage"), None);
        for d in [0, 11_016, 11_017, 20_770, 59] {
            assert_eq!(epoch_days(&date(d)), Some(d), "{}", date(d));
        }
        assert_eq!(date(20_770), "2026-11-13");
    }

    #[test]
    fn parses_events() {
        let body = br#"{
          "objectClassName": "domain",
          "ldhName": "example.com",
          "events": [
            {"eventAction": "registration", "eventDate": "2026-10-20T08:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-11-01T08:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-10-20T08:00:00Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-11-13T08:00:00Z"}
          ]
        }"#;
        assert_eq!(
            parse_domain(body).unwrap(),
            Lookup::Found {
                registered: epoch_days("2026-10-20"),
                reregistered: None
            }
        );
        assert_eq!(
            parse_domain(b"{}").unwrap(),
            Lookup::Found {
                registered: None,
                reregistered: None
            }
        );
        assert!(parse_domain(b"<html>").is_err());
    }

    fn weights(l: &Lookup, today: u64) -> Vec<(String, i32)> {
        signals(l, today)
            .into_iter()
            .map(|s| (s.name, s.weight))
            .collect()
    }

    #[test]
    fn age_weights() {
        let t = 20_000;
        let at = |age: u64| Lookup::Found {
            registered: Some(t - age),
            reregistered: None,
        };
        let w = |age| weights(&at(age), t)[0].1;
        assert_eq!(w(3), 40);
        assert_eq!(w(29), 40);
        assert_eq!(w(30), 20);
        assert_eq!(w(179), 20);
        assert_eq!(w(200), 5);
        assert_eq!(w(800), 0);
        assert_eq!(w(OLD_DAYS), -10);
        assert_eq!(
            weights(
                &Lookup::Found {
                    registered: Some(t - 4000),
                    reregistered: Some(t - 10)
                },
                t
            ),
            vec![
                ("domain_age_days".into(), -10),
                ("domain_reregistered".into(), 25)
            ]
        );
        assert_eq!(
            weights(&Lookup::NotFound, t),
            vec![("domain_not_found".into(), 0)]
        );
    }

    #[test]
    fn private_suffixes_are_skipped() {
        assert!(under_private_suffix("fake-toys.myshopify.com"));
        assert!(!under_private_suffix("jouetaventure.com"));
        assert!(!under_private_suffix("example.co.uk"));
    }
}
