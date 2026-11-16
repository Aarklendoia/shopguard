//! French company directory: does a SIREN exist, is the company active?
//!
//! Public API *Recherche d'entreprises* of the French State
//! (<https://recherche-entreprises.api.gouv.fr>, no key, 7 requests per second at most):
//! requests are spaced by [`SPACING`] and answers kept [`TTL`], companies rarely change.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use tokio::sync::Mutex;

pub const API_URL: &str = "https://recherche-entreprises.api.gouv.fr/search";
const SPACING: Duration = Duration::from_millis(250);
const TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const CACHE_MAX: usize = 10_000;
const MAX_BODY: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Company {
    pub siren: String,
    pub name: String,
    /// `etat_administratif` A (active), not C (ceased).
    pub active: bool,
    /// `YYYY-MM-DD`
    pub created: Option<String>,
    pub closed: Option<String>,
    /// NAF code of the main activity, e.g. `47.91B` (distance selling).
    pub naf: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    Found(Company),
    /// No company with this SIREN.
    Unknown,
}

#[derive(Deserialize)]
struct Answer {
    results: Vec<Raw>,
}

#[derive(Deserialize)]
struct Raw {
    siren: String,
    nom_complet: Option<String>,
    etat_administratif: Option<String>,
    date_creation: Option<String>,
    date_fermeture: Option<String>,
    activite_principale: Option<String>,
}

/// The company `siren` in an answer of the API (a search: other companies may come
/// back, only an exact SIREN counts).
pub fn parse(body: &str, siren: &str) -> Result<Lookup, String> {
    let a: Answer = serde_json::from_str(body).map_err(|e| format!("company directory: {e}"))?;
    Ok(a.results
        .into_iter()
        .find(|r| r.siren == siren)
        .map_or(Lookup::Unknown, |r| {
            Lookup::Found(Company {
                siren: r.siren,
                name: r.nom_complet.unwrap_or_default(),
                active: r.etat_administratif.as_deref() == Some("A"),
                created: r.date_creation,
                closed: r.date_fermeture,
                naf: r.activite_principale,
            })
        }))
}

#[derive(Default)]
struct State {
    cache: HashMap<String, (Instant, Lookup)>,
    last: Option<Instant>,
}

pub struct Directory {
    client: Client,
    url: Url,
    state: Mutex<State>,
}

impl Directory {
    pub fn new(client: Client, url: Url) -> Self {
        Self {
            client,
            url,
            state: Mutex::default(),
        }
    }

    /// The company with this (valid) SIREN.
    pub async fn lookup(&self, siren: &str) -> Result<Lookup, String> {
        // one request at a time, spaced: the lock is held during the request
        let mut st = self.state.lock().await;
        if let Some((at, l)) = st.cache.get(siren)
            && at.elapsed() < TTL
        {
            return Ok(l.clone());
        }
        if let Some(last) = st.last {
            let wait = SPACING.saturating_sub(last.elapsed());
            tokio::time::sleep(wait).await;
        }
        st.last = Some(Instant::now());
        let mut url = self.url.clone();
        url.query_pairs_mut()
            .append_pair("q", siren)
            .append_pair("minimal", "true")
            .append_pair("page", "1")
            .append_pair("per_page", "5");
        let resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("company directory: {e}"))?;
        if resp.status() != StatusCode::OK {
            return Err(format!("company directory: HTTP {}", resp.status()));
        }
        let body = crate::http::read_limited(resp, MAX_BODY).await?;
        let l = parse(&String::from_utf8_lossy(&body), siren)?;
        if st.cache.len() >= CACHE_MAX {
            st.cache.retain(|_, (at, _)| at.elapsed() < TTL);
            if st.cache.len() >= CACHE_MAX {
                st.cache.clear();
            }
        }
        st.cache
            .insert(siren.to_owned(), (Instant::now(), l.clone()));
        Ok(l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECATHLON: &str = r#"{"results":[{"siren":"306138900","siren_conserve":null,
        "nom_complet":"DECATHLON","activite_principale":"68.20B","date_creation":"1977-01-01",
        "date_fermeture":null,"etat_administratif":"A","statut_diffusion":"O"}],
        "total_results":1,"page":1,"per_page":5,"total_pages":1}"#;

    #[test]
    fn answers() {
        assert_eq!(
            parse(DECATHLON, "306138900").unwrap(),
            Lookup::Found(Company {
                siren: "306138900".into(),
                name: "DECATHLON".into(),
                active: true,
                created: Some("1977-01-01".into()),
                closed: None,
                naf: Some("68.20B".into()),
            })
        );
        // a search answer about another company
        assert_eq!(parse(DECATHLON, "732829320").unwrap(), Lookup::Unknown);
        assert_eq!(
            parse(r#"{"results":[],"total_results":0}"#, "732829320").unwrap(),
            Lookup::Unknown
        );
        let closed = DECATHLON
            .replace(r#""etat_administratif":"A""#, r#""etat_administratif":"C""#)
            .replace(
                r#""date_fermeture":null"#,
                r#""date_fermeture":"2020-05-31""#,
            );
        let Lookup::Found(c) = parse(&closed, "306138900").unwrap() else {
            panic!()
        };
        assert!(!c.active);
        assert_eq!(c.closed.as_deref(), Some("2020-05-31"));
        assert!(parse("<html>", "306138900").is_err());
    }
}
