//! Scoring pipeline.
//!
//! Each [`Analyzer`] looks at one aspect of a domain (registration age, certificate,
//! hosting, page content…) and returns [`Signal`]s. The verdict score is the sum of the
//! signal weights, clamped to 0..=100: positive weights point to a fake shop, negative
//! ones to a legitimate site (a valid, active SIRET for example).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::store::Store;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Signal {
    /// Analyzer that produced the signal, e.g. `rdap`.
    pub source: String,
    /// Short machine-readable name, e.g. `domain_age_days`.
    pub name: String,
    /// Contribution to the score, -100..=100.
    pub weight: i32,
    /// Human-readable explanation shown in the OPNsense interface.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Verdict {
    pub domain: String,
    /// 0 (looks legitimate) to 100 (almost certainly a fake shop).
    pub score: u8,
    pub signals: Vec<Signal>,
    /// Unix time of the analysis.
    pub checked_at: u64,
}

impl Verdict {
    pub fn new(domain: String, signals: Vec<Signal>) -> Self {
        let score = signals.iter().map(|s| s.weight).sum::<i32>().clamp(0, 100) as u8;
        let checked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            domain,
            score,
            signals,
            checked_at,
        }
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Analyzer: Send + Sync {
    fn name(&self) -> &'static str;
    /// Signals for `domain` (a registrable domain), knowing the `earlier` signals of the
    /// analyzers run before this one (e.g. not weighting an age RDAP already weighted).
    /// Errors are reported as signals of weight 0 rather than failing the whole analysis.
    fn analyze<'a>(&'a self, domain: &'a str, earlier: &'a [Signal]) -> BoxFuture<'a, Vec<Signal>>;
}

/// Analyzers enabled in this build, in the order they run.
pub fn analyzers(client: reqwest::Client, user_agent: Option<&str>) -> Vec<Box<dyn Analyzer>> {
    let bootstrap = reqwest::Url::parse(crate::rdap::BOOTSTRAP_URL).expect("static URL");
    let mut list: Vec<Box<dyn Analyzer>> = vec![
        Box::new(crate::rdap::Rdap::new(client.clone(), bootstrap)),
        Box::new(crate::tls::Tls::new()),
    ];
    match crate::hosting::Hosting::new(client.clone()) {
        Ok(h) => list.push(Box::new(h)),
        Err(e) => warn!("hosting analyzer disabled: {e}"),
    }
    list.push(Box::new(crate::history::History::new(
        client.clone(),
        reqwest::Url::parse(crate::history::WAYBACK_URL).expect("static URL"),
        reqwest::Url::parse(crate::history::CRTSH_URL).expect("static URL"),
        reqwest::Url::parse(crate::history::ISSUANCES_URL).expect("static URL"),
    )));
    // one fetcher for every page analyzer: they share its cache and page budget
    let client_for_directory = client.clone();
    let fetcher = std::sync::Arc::new(crate::fetch::Fetcher::new(client, user_agent));
    list.push(Box::new(crate::page::HomePage::new(fetcher.clone())));
    list.push(Box::new(crate::shop::Shop::new(fetcher.clone())));
    let vies = crate::vies::Vies::new(
        client_for_directory.clone(),
        reqwest::Url::parse(crate::vies::API_URL).expect("static URL"),
    );
    let directory = crate::company::Directory::new(
        client_for_directory,
        reqwest::Url::parse(crate::company::API_URL).expect("static URL"),
    );
    list.push(Box::new(crate::legal::Legal::new(fetcher, directory, vies)));
    list
}

/// Background task: analyzes the domains received on `rx`, one at a time.
///
/// One at a time on purpose: a home network sees a few hundred new domains a day, and
/// the external services queried (RDAP servers, company directory) rate-limit clients.
/// Signals of analyzer `i`, run in its own task: a panic (a bug met on a hostile page)
/// loses this analyzer's signals for this domain, not the pipeline.
async fn isolated(
    analyzers: Arc<Vec<Box<dyn Analyzer>>>,
    i: usize,
    domain: String,
    earlier: Vec<Signal>,
) -> Vec<Signal> {
    let name = analyzers[i].name();
    let d = domain.clone();
    match tokio::spawn(async move { analyzers[i].analyze(&d, &earlier).await }).await {
        Ok(s) => {
            debug!(%domain, analyzer = name, signals = s.len());
            s
        }
        Err(e) => {
            error!(%domain, analyzer = name, "analyzer failed: {e}");
            vec![Signal {
                source: name.into(),
                name: "analysis_failed".into(),
                weight: 0,
                detail: "this analysis failed (worker bug)".into(),
            }]
        }
    }
}

/// Verdict on `domain` (a registrable domain): every analyzer in turn.
pub async fn verdict(analyzers: &Arc<Vec<Box<dyn Analyzer>>>, domain: String) -> Verdict {
    let mut signals = Vec::new();
    for i in 0..analyzers.len() {
        let s = isolated(analyzers.clone(), i, domain.clone(), signals.clone()).await;
        signals.extend(s);
    }
    Verdict::new(domain, signals)
}

pub async fn run(
    mut rx: mpsc::Receiver<String>,
    store: Arc<Store>,
    analyzers: Vec<Box<dyn Analyzer>>,
) {
    info!(analyzers = analyzers.len(), "analysis pipeline started");
    let analyzers = Arc::new(analyzers);
    while let Some(domain) = rx.recv().await {
        let verdict = verdict(&analyzers, domain).await;
        if verdict.score >= 50 {
            warn!(domain = %verdict.domain, score = verdict.score, "suspicious domain");
        }
        store.insert(verdict).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(i32);
    impl Analyzer for Fixed {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn analyze<'a>(&'a self, _: &'a str, _: &'a [Signal]) -> BoxFuture<'a, Vec<Signal>> {
            Box::pin(async move {
                assert!(self.0 >= 0, "hostile page");
                vec![sig(self.0)]
            })
        }
    }

    #[tokio::test]
    async fn a_panicking_analyzer_loses_only_its_signals() {
        let list: Arc<Vec<Box<dyn Analyzer>>> =
            Arc::new(vec![Box::new(Fixed(-1)), Box::new(Fixed(7))]);
        let failed = isolated(list.clone(), 0, "a.fr".into(), Vec::new()).await;
        assert_eq!(
            (failed[0].name.as_str(), failed[0].weight),
            ("analysis_failed", 0)
        );
        assert_eq!(isolated(list, 1, "a.fr".into(), Vec::new()).await, [sig(7)]);
    }

    fn sig(weight: i32) -> Signal {
        Signal {
            source: "t".into(),
            name: "t".into(),
            weight,
            detail: String::new(),
        }
    }

    #[test]
    fn score_is_clamped_sum() {
        assert_eq!(
            Verdict::new("a.fr".into(), vec![sig(30), sig(40)]).score,
            70
        );
        assert_eq!(
            Verdict::new("a.fr".into(), vec![sig(80), sig(60)]).score,
            100
        );
        assert_eq!(
            Verdict::new("a.fr".into(), vec![sig(20), sig(-60)]).score,
            0
        );
        assert_eq!(Verdict::new("a.fr".into(), vec![]).score, 0);
    }
}
