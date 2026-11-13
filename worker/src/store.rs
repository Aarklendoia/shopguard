//! Domains already seen and their verdicts.
//!
//! In memory for now: a restart re-analyzes the domains the plugin sends again.
//! Persistence (and re-checking verdicts after some time) is tracked in its own issue.

use std::collections::{HashMap, HashSet};

use tokio::sync::RwLock;

use crate::analysis::Verdict;

#[derive(Default)]
pub struct Store {
    seen: RwLock<HashSet<String>>,
    verdicts: RwLock<HashMap<String, Verdict>>,
}

impl Store {
    /// Records `domain` as seen. True if it was not seen before (and must be analyzed).
    pub async fn mark_seen(&self, domain: &str) -> bool {
        self.seen.write().await.insert(domain.to_owned())
    }

    /// Forgets that `domain` was seen, e.g. when the analysis queue is full.
    pub async fn unmark_seen(&self, domain: &str) {
        self.seen.write().await.remove(domain);
    }

    pub async fn insert(&self, verdict: Verdict) {
        self.verdicts
            .write()
            .await
            .insert(verdict.domain.clone(), verdict);
    }

    pub async fn get(&self, domain: &str) -> Option<Verdict> {
        self.verdicts.read().await.get(domain).cloned()
    }

    /// Verdicts with a score of at least `min_score`, highest score first.
    pub async fn verdicts(&self, min_score: u8) -> Vec<Verdict> {
        let mut v: Vec<Verdict> = self
            .verdicts
            .read()
            .await
            .values()
            .filter(|v| v.score >= min_score)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.domain.cmp(&b.domain)));
        v
    }

    pub async fn pending(&self) -> usize {
        let seen = self.seen.read().await.len();
        seen.saturating_sub(self.verdicts.read().await.len())
    }
}
