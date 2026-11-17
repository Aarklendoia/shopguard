//! Home page of the domain: is it an online shop?
//!
//! Fetches `https://<domain>/`, then `https://www.<domain>/`, through the shared
//! [`Fetcher`] (the later page analyzers find the page in its cache). Weight 0 for now:
//! the signal says what kind of site this is, the page analyzers (legal notice, shop
//! heuristics) only look deeper when it is a shop.

use std::sync::Arc;

use reqwest::Url;
use tracing::debug;

use crate::analysis::{Analyzer, BoxFuture, Signal};
use crate::fetch::{Fetcher, Page, shop_evidence};

const SOURCE: &str = "page";

pub struct HomePage {
    fetcher: Arc<Fetcher>,
}

impl HomePage {
    pub fn new(fetcher: Arc<Fetcher>) -> Self {
        Self { fetcher }
    }
}

/// Why there is no home page.
#[derive(Debug, Clone, PartialEq)]
pub enum NoHome {
    /// The site answered, but refuses automated visits (403, 429, challenge page): bot
    /// protection.
    Refused(Url, u16),
    Other(String),
}

/// The first home page that answers with HTML: the domain, then `www.`.
pub async fn home(fetcher: &Fetcher, domain: &str) -> Result<Page, NoHome> {
    let mut refused = None;
    let mut last = String::new();
    for host in [domain.to_owned(), format!("www.{domain}")] {
        let Ok(url) = Url::parse(&format!("https://{host}/")) else {
            continue;
        };
        match fetcher.get(&url).await {
            Ok(p) if p.refused() => {
                refused.get_or_insert(NoHome::Refused(p.url, p.status));
            }
            Ok(p) if p.status < 400 => return Ok(p),
            Ok(p) => last = format!("{url}: HTTP {}", p.status),
            Err(e) => last = e,
        }
    }
    Err(refused.unwrap_or(NoHome::Other(last)))
}

fn signal(name: &str, weight: i32, detail: String) -> Signal {
    Signal {
        source: SOURCE.into(),
        name: name.into(),
        weight,
        detail,
    }
}

impl Analyzer for HomePage {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn analyze<'a>(&'a self, domain: &'a str, _: &'a [Signal]) -> BoxFuture<'a, Vec<Signal>> {
        Box::pin(async move {
            match home(&self.fetcher, domain).await {
                Ok(page) => {
                    let evidence = shop_evidence(&page.html);
                    if evidence.is_empty() {
                        vec![signal(
                            "page_not_shop",
                            0,
                            format!("{} does not look like an online shop", page.url),
                        )]
                    } else {
                        vec![signal(
                            "page_shop",
                            0,
                            format!(
                                "{} looks like an online shop ({})",
                                page.url,
                                evidence.join(", ")
                            ),
                        )]
                    }
                }
                // bot protection that sees through the browser headers: big retailers, but
                // also fake shops (Cloudflare's is free), so no weight
                Err(NoHome::Refused(url, status)) => vec![signal(
                    "page_blocked",
                    0,
                    if status < 400 {
                        format!("{url} answers with a bot challenge page (bot protection)")
                    } else {
                        format!("{url} refuses automated visits (HTTP {status}, bot protection)")
                    },
                )],
                // most domains seen by a resolver are not websites: nothing to say
                Err(NoHome::Other(e)) => {
                    debug!(%domain, "no home page: {e}");
                    Vec::new()
                }
            }
        })
    }
}
