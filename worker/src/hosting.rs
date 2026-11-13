//! Which network hosts the site.
//!
//! - Origin AS of the site's address through Team Cymru's DNS service
//!   (`<reversed ip>.origin.asn.cymru.com` TXT): no database to ship. Only the address is
//!   sent, never the domain.
//! - Networks run by spammers and cyber-criminals, or hijacked: the DROP lists (ASN-DROP,
//!   DROP v4 and v6), downloaded once a day; their terms forbid redistributing them, so
//!   they are fetched at run time, not shipped.
//! - Known platforms and providers from `hosting.txt`, kept in the repository.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::analysis::{Analyzer, BoxFuture, Signal};
use crate::http;

const SOURCE: &str = "hosting";
const DROP_URLS: [&str; 3] = [
    "https://www.spamhaus.org/drop/asndrop.json",
    "https://www.spamhaus.org/drop/drop_v4.json",
    "https://www.spamhaus.org/drop/drop_v6.json",
];
const DROP_TTL: Duration = Duration::from_secs(24 * 3600);
/// After a failed download, wait this long before trying again.
const DROP_RETRY: Duration = Duration::from_secs(3600);
/// Address or network listed as run by criminals.
const DROP_WEIGHT: i32 = 30;

const KNOWN: &str = include_str!("hosting.txt");

/// An address range.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    fn parse(s: &str) -> Option<Self> {
        let (a, l) = s.split_once('/')?;
        let addr: IpAddr = a.parse().ok()?;
        let len: u8 = l.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (len <= max).then_some(Self { addr, len })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let bits = |a: IpAddr| -> (u128, u32) {
            match a {
                IpAddr::V4(v) => (u128::from(u32::from(v)) << 96, 32),
                IpAddr::V6(v) => (u128::from(v), 128),
            }
        };
        let ((net, w1), (ip, w2)) = (bits(self.addr), bits(ip));
        if w1 != w2 {
            return false;
        }
        let mask = if self.len == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(self.len))
        };
        net & mask == ip & mask
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Match {
    Prefix(Prefix),
    Asn(u32),
}

#[derive(Debug, Clone, PartialEq)]
struct Known {
    what: Match,
    weight: i32,
    label: String,
}

fn parse_known(text: &str) -> Result<Vec<Known>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bad = || format!("hosting.txt line {}: {line}", n + 1);
        let mut f = line.splitn(4, char::is_whitespace).map(str::trim);
        let (kind, value, weight, label) = (f.next(), f.next(), f.next(), f.next());
        let what = match (kind, value) {
            (Some("prefix"), Some(v)) => Match::Prefix(Prefix::parse(v).ok_or_else(bad)?),
            (Some("asn"), Some(v)) => Match::Asn(v.parse().map_err(|_| bad())?),
            _ => return Err(bad()),
        };
        let weight: i32 = weight.and_then(|w| w.parse().ok()).ok_or_else(bad)?;
        let label = label.filter(|l| !l.is_empty()).ok_or_else(bad)?.to_owned();
        out.push(Known {
            what,
            weight,
            label,
        });
    }
    Ok(out)
}

/// The DROP lists, merged.
#[derive(Debug, Default)]
struct Drop {
    asns: HashSet<u32>,
    prefixes: Vec<Prefix>,
}

#[derive(Deserialize)]
struct DropLine {
    asn: Option<u32>,
    cidr: Option<String>,
}

impl Drop {
    /// Adds the entries of one JSON-lines file (the last line is metadata).
    fn add(&mut self, body: &str) {
        for line in body.lines() {
            let Ok(l) = serde_json::from_str::<DropLine>(line) else {
                continue;
            };
            if let Some(a) = l.asn {
                self.asns.insert(a);
            }
            if let Some(p) = l.cidr.as_deref().and_then(Prefix::parse) {
                self.prefixes.push(p);
            }
        }
    }

    fn listed(&self, ip: IpAddr, asns: &[u32]) -> bool {
        asns.iter().any(|a| self.asns.contains(a)) || self.prefixes.iter().any(|p| p.contains(ip))
    }
}

/// Origin of an address according to Team Cymru.
#[derive(Debug, Clone, PartialEq)]
struct Origin {
    /// Several when the prefix is announced by more than one network.
    asns: Vec<u32>,
    prefix: String,
}

/// `"13335 | 23.227.38.0/23 | CA | arin | 2013-09-19"`
fn parse_origin(txt: &str) -> Option<Origin> {
    let mut f = txt.split('|').map(str::trim);
    let asns: Vec<u32> = f
        .next()?
        .split_whitespace()
        .filter_map(|a| a.parse().ok())
        .collect();
    let prefix = f.next()?.to_owned();
    (!asns.is_empty()).then_some(Origin { asns, prefix })
}

/// `"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"`
fn parse_as_name(txt: &str) -> Option<String> {
    let name = txt.split('|').nth(4)?.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// Name to query for the origin of `ip`.
fn origin_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, d] = v.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com.")
        }
        IpAddr::V6(v) => {
            let mut n = String::with_capacity(80);
            for byte in v.octets().iter().rev() {
                n.push_str(&format!("{:x}.{:x}.", byte & 0xf, byte >> 4));
            }
            n + "origin6.asn.cymru.com."
        }
    }
}

#[derive(Default)]
struct DropState {
    lists: Option<Drop>,
    /// When the lists were downloaded, or last tried.
    at: Option<Instant>,
    ok: bool,
}

pub struct Hosting {
    client: Client,
    dns: TokioResolver,
    known: Vec<Known>,
    drop: Mutex<DropState>,
}

fn signal(name: &str, weight: i32, detail: String) -> Signal {
    Signal {
        source: SOURCE.into(),
        name: name.into(),
        weight,
        detail,
    }
}

impl Hosting {
    pub fn new(client: Client) -> Result<Self, String> {
        let dns = TokioResolver::builder_tokio()
            .map_err(|e| format!("DNS resolver: {e}"))?
            .build()
            .map_err(|e| format!("DNS resolver: {e}"))?;
        let known = parse_known(KNOWN)?;
        Ok(Self {
            client,
            dns,
            known,
            drop: Mutex::default(),
        })
    }

    async fn txt(&self, name: &str) -> Option<String> {
        let lookup = self.dns.txt_lookup(name).await.ok()?;
        lookup.answers().iter().find_map(|r| match &r.data {
            hickory_resolver::proto::rr::RData::TXT(t) => Some(t.to_string()),
            _ => None,
        })
    }

    async fn origin(&self, ip: IpAddr) -> Option<Origin> {
        parse_origin(&self.txt(&origin_name(ip)).await?)
    }

    async fn as_name(&self, asn: u32) -> Option<String> {
        parse_as_name(&self.txt(&format!("AS{asn}.asn.cymru.com.")).await?)
    }

    async fn download(&self) -> Result<Drop, String> {
        let mut d = Drop::default();
        for url in DROP_URLS {
            let body = self
                .client
                .get(url)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| format!("{url}: {e}"))?
                .text()
                .await
                .map_err(|e| format!("{url}: {e}"))?;
            d.add(&body);
        }
        Ok(d)
    }

    /// Whether `ip` or one of `asns` is on a DROP list; `None` when the lists could not
    /// be downloaded yet.
    async fn dropped(&self, ip: IpAddr, asns: &[u32]) -> Option<bool> {
        let mut st = self.drop.lock().await;
        let due = match st.at {
            None => true,
            Some(at) => at.elapsed() >= if st.ok { DROP_TTL } else { DROP_RETRY },
        };
        if due {
            st.at = Some(Instant::now());
            match self.download().await {
                Ok(d) => {
                    debug!(
                        asns = d.asns.len(),
                        prefixes = d.prefixes.len(),
                        "DROP lists"
                    );
                    st.lists = Some(d);
                    st.ok = true;
                }
                // keep the previous lists, if any
                Err(e) => {
                    warn!("DROP lists: {e}");
                    st.ok = false;
                }
            }
        }
        st.lists.as_ref().map(|d| d.listed(ip, asns))
    }

    fn known(&self, ip: IpAddr, asns: &[u32]) -> Vec<&Known> {
        self.known
            .iter()
            .filter(|k| match &k.what {
                Match::Prefix(p) => p.contains(ip),
                Match::Asn(a) => asns.contains(a),
            })
            .collect()
    }

    /// The address the site would be reached on: IPv4 first, the domain then `www.`.
    async fn address(domain: &str) -> Option<IpAddr> {
        for host in [domain.to_owned(), format!("www.{domain}")] {
            if let Ok(addrs) = http::resolve_public(&host, 0).await {
                let mut ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
                ips.sort_by_key(|ip| ip.is_ipv6());
                return ips.first().copied();
            }
        }
        None
    }
}

impl Analyzer for Hosting {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn analyze<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<Signal>> {
        Box::pin(async move {
            // no public address: the TLS analyzer already says so
            let Some(ip) = Self::address(domain).await else {
                return Vec::new();
            };
            let Some(origin) = self.origin(ip).await else {
                return vec![signal(
                    "hosting_unknown",
                    0,
                    format!("no origin network found for {ip}"),
                )];
            };
            let asn = origin.asns[0];
            let name = self
                .as_name(asn)
                .await
                .unwrap_or_else(|| "unknown network".into());
            let mut out = vec![signal(
                "hosting_network",
                0,
                format!("{ip} ({}) is announced by AS{asn} {name}", origin.prefix),
            )];
            for k in self.known(ip, &origin.asns) {
                out.push(signal("hosting_known", k.weight, k.label.clone()));
            }
            if self.dropped(ip, &origin.asns).await == Some(true) {
                out.push(signal(
                    "hosting_drop",
                    DROP_WEIGHT,
                    format!(
                        "AS{asn} or {ip} is on a DROP list (network run by spammers or cyber-criminals)"
                    ),
                ));
            }
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn prefixes() {
        let p = Prefix::parse("23.227.38.0/24").unwrap();
        assert!(p.contains(ip("23.227.38.74")));
        assert!(!p.contains(ip("23.227.39.1")));
        assert!(!p.contains(ip("::ffff:23.227.38.74")));
        let p6 = Prefix::parse("2001:678:254::/48").unwrap();
        assert!(p6.contains(ip("2001:678:254:1::5")));
        assert!(!p6.contains(ip("2001:678:255::1")));
        assert!(Prefix::parse("0.0.0.0/0").unwrap().contains(ip("9.9.9.9")));
        assert!(Prefix::parse("1.2.3.4/33").is_none());
        assert!(Prefix::parse("1.2.3.4").is_none());
    }

    #[test]
    fn known_list_of_the_repository_parses() {
        let k = parse_known(KNOWN).unwrap();
        assert!(k.iter().any(|k| k.label == "Shopify"));
        assert_eq!(
            parse_known("asn 64500 15 Some host  # comment").unwrap(),
            vec![Known {
                what: Match::Asn(64500),
                weight: 15,
                label: "Some host".into()
            }]
        );
        assert!(parse_known("prefix nope 0 X").is_err());
        assert!(parse_known("asn 1 x X").is_err());
        assert!(parse_known("asn 1 0").is_err());
    }

    #[test]
    fn cymru_answers() {
        assert_eq!(
            parse_origin("13335 | 23.227.38.0/23 | CA | arin | 2013-09-19"),
            Some(Origin {
                asns: vec![13335],
                prefix: "23.227.38.0/23".into()
            })
        );
        assert_eq!(
            parse_origin("3215 5511 | 2.0.0.0/16 | FR | ripencc |")
                .unwrap()
                .asns,
            vec![3215, 5511]
        );
        assert_eq!(parse_origin("garbage"), None);
        assert_eq!(
            parse_as_name("13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US")
                .as_deref(),
            Some("CLOUDFLARENET - Cloudflare, Inc., US")
        );
        assert_eq!(parse_as_name("13335 | US"), None);
    }

    #[test]
    fn query_names() {
        assert_eq!(
            origin_name(ip("23.227.38.74")),
            "74.38.227.23.origin.asn.cymru.com."
        );
        assert_eq!(
            origin_name(ip("2001:db8::1")),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com."
        );
    }

    #[test]
    fn drop_lists() {
        let mut d = Drop::default();
        d.add(
            r#"{"asn":64500,"rir":"arin","domain":"x","cc":"US","asname":"X"}
{"type":"metadata","timestamp":1,"records":1}"#,
        );
        d.add(r#"{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"apnic"}"#);
        assert!(d.listed(ip("9.9.9.9"), &[1, 64500]));
        assert!(d.listed(ip("192.0.2.7"), &[1]));
        assert!(!d.listed(ip("9.9.9.9"), &[1]));
    }
}
