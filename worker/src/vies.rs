//! EU VAT numbers: VIES, the European Commission's VAT number validation service.
//!
//! REST API (<https://ec.europa.eu/taxation_customs/vies/>, no key): asks the member
//! state's registry whether a VAT number is valid, and gives the company name where that
//! state publishes it (not Germany). Member states' registries are often busy
//! (`MS_MAX_CONCURRENT_REQ`) or down: no answer then, never a verdict. Requests are spaced
//! by [`SPACING`] and answers kept [`TTL`].

use std::collections::HashMap;
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use tokio::sync::Mutex;

pub const API_URL: &str = "https://ec.europa.eu/taxation_customs/vies/rest-api/ms/";
const SPACING: Duration = Duration::from_secs(1);
const TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const CACHE_MAX: usize = 10_000;
const MAX_BODY: usize = 64 * 1024;
/// `userError` of a member state's registry handling too many requests.
const BUSY: &str = "MS_MAX_CONCURRENT_REQ";
const RETRY_AFTER: Duration = Duration::from_secs(2);

/// What the member state's registry says about a VAT number.
#[derive(Debug, Clone, PartialEq)]
pub enum Vat {
    /// Valid, with the company name when the state publishes it.
    Valid(Option<String>),
    Invalid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Answer {
    is_valid: bool,
    user_error: Option<String>,
    name: Option<String>,
}

/// A VIES answer. Only `VALID` and `INVALID` are verdicts: any other `userError`
/// (`MS_UNAVAILABLE`, `MS_MAX_CONCURRENT_REQ`, `TIMEOUT`…) is the registry not answering.
pub fn parse(body: &str) -> Result<Vat, String> {
    let a: Answer = serde_json::from_str(body).map_err(|e| format!("VIES: {e}"))?;
    match a.user_error.as_deref() {
        Some("VALID") | None if a.is_valid => {
            let name = a
                .name
                .map(|n| n.trim().to_owned())
                .filter(|n| !n.is_empty() && n != "---");
            Ok(Vat::Valid(name))
        }
        Some("INVALID") => Ok(Vat::Invalid),
        Some(e) => Err(format!("VIES: {e}")),
        None => Err("VIES: no verdict".into()),
    }
}

#[derive(Default)]
struct State {
    cache: HashMap<String, (Instant, Vat)>,
    last: Option<Instant>,
}

pub struct Vies {
    client: Client,
    url: Url,
    state: Mutex<State>,
}

impl Vies {
    pub fn new(client: Client, url: Url) -> Self {
        Self {
            client,
            url,
            state: Mutex::default(),
        }
    }

    async fn ask(&self, url: &Url) -> Result<Vat, String> {
        let resp = self
            .client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("VIES: {e}"))?;
        if resp.status() != StatusCode::OK {
            return Err(format!("VIES: HTTP {}", resp.status()));
        }
        let body = crate::http::read_limited(resp, MAX_BODY).await?;
        parse(&String::from_utf8_lossy(&body))
    }

    /// Checks `number` (country prefix included: `SK2021375994`).
    pub async fn check(&self, number: &str) -> Result<Vat, String> {
        let (country, rest) = number
            .split_at_checked(2)
            .filter(|(c, r)| c.bytes().all(|b| b.is_ascii_uppercase()) && !r.is_empty())
            .ok_or_else(|| format!("VIES: not a VAT number: {number}"))?;
        if !rest.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!("VIES: not a VAT number: {number}"));
        }
        // one request at a time, spaced: the lock is held during the request
        let mut st = self.state.lock().await;
        if let Some((at, v)) = st.cache.get(number)
            && at.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        if let Some(last) = st.last {
            tokio::time::sleep(SPACING.saturating_sub(last.elapsed())).await;
        }
        let url = self
            .url
            .join(&format!("{country}/vat/{rest}"))
            .map_err(|e| format!("VIES: {e}"))?;
        let mut v = self.ask(&url).await;
        // a busy registry (the Dutch one often is) answers the next request
        if v.as_ref().is_err_and(|e| e.contains(BUSY)) {
            tokio::time::sleep(RETRY_AFTER).await;
            v = self.ask(&url).await;
        }
        st.last = Some(Instant::now());
        let v = v?;
        if st.cache.len() >= CACHE_MAX {
            st.cache.retain(|_, (at, _)| at.elapsed() < TTL);
            if st.cache.len() >= CACHE_MAX {
                st.cache.clear();
            }
        }
        st.cache
            .insert(number.to_owned(), (Instant::now(), v.clone()));
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::Path;
    use axum::routing::get;

    #[test]
    fn answers() {
        let sk = r#"{"isValid":true,"requestDate":"2026-11-17T14:17:42.139Z","userError":"VALID",
            "name":"Tomar Creation s.r.o.","address":"Pod Šípkom 1153/1\n95806 Partizánske"}"#;
        assert_eq!(
            parse(sk).unwrap(),
            Vat::Valid(Some("Tomar Creation s.r.o.".into()))
        );
        // Germany gives no name
        let de = r#"{"isValid":true,"userError":"VALID","name":"---","address":"---"}"#;
        assert_eq!(parse(de).unwrap(), Vat::Valid(None));
        let nl = r#"{"isValid":false,"userError":"INVALID","name":"---"}"#;
        assert_eq!(parse(nl).unwrap(), Vat::Invalid);
        // the registry did not answer: no verdict
        let busy = r#"{"isValid":false,"userError":"MS_MAX_CONCURRENT_REQ","name":"---"}"#;
        assert!(parse(busy).unwrap_err().contains("MS_MAX_CONCURRENT_REQ"));
        assert!(parse(r#"{"isValid":false}"#).is_err());
        assert!(parse("<html>").is_err());
    }

    #[tokio::test]
    async fn queries_and_cache() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let app = Router::new().route(
            "/ms/{cc}/vat/{n}",
            get(|Path((cc, n)): Path<(String, String)>| async move {
                assert_eq!((cc.as_str(), n.as_str()), ("SK", "2021375994"));
                r#"{"isValid":true,"userError":"VALID","name":"Tomar Creation s.r.o."}"#
            }),
        );
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let v = Vies::new(
            crate::http::test_client(),
            Url::parse(&format!("http://{addr}/ms/")).unwrap(),
        );
        assert!(matches!(
            v.check("SK2021375994").await.unwrap(),
            Vat::Valid(Some(_))
        ));
        assert!(v.check("SK2021375994").await.is_ok(), "cached");
        assert!(v.check("sk1").await.is_err());
        assert!(v.check("SK12/../x").await.is_err());
    }
}
