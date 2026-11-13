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
use tracing::{debug, info, warn};

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
    /// Signals for `domain` (a registrable domain). Errors are reported as signals of
    /// weight 0 rather than failing the whole analysis.
    fn analyze<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<Signal>>;
}

/// Analyzers enabled in this build, in the order they run.
pub fn analyzers(client: reqwest::Client) -> Vec<Box<dyn Analyzer>> {
    let bootstrap = reqwest::Url::parse(crate::rdap::BOOTSTRAP_URL).expect("static URL");
    vec![
        Box::new(crate::rdap::Rdap::new(client, bootstrap)),
        Box::new(crate::tls::Tls::new()),
    ]
}

/// Background task: analyzes the domains received on `rx`, one at a time.
///
/// One at a time on purpose: a home network sees a few hundred new domains a day, and
/// the external services queried (RDAP servers, company directory) rate-limit clients.
pub async fn run(
    mut rx: mpsc::Receiver<String>,
    store: Arc<Store>,
    analyzers: Vec<Box<dyn Analyzer>>,
) {
    info!(analyzers = analyzers.len(), "analysis pipeline started");
    while let Some(domain) = rx.recv().await {
        let mut signals = Vec::new();
        for a in &analyzers {
            let s = a.analyze(&domain).await;
            debug!(%domain, analyzer = a.name(), signals = s.len());
            signals.extend(s);
        }
        let verdict = Verdict::new(domain, signals);
        if verdict.score >= 50 {
            warn!(domain = %verdict.domain, score = verdict.score, "suspicious domain");
        }
        store.insert(verdict).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
