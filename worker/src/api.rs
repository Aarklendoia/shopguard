//! HTTP API used by the OPNsense plugin.
//!
//! | Method | Path                    | Auth | Purpose                                         |
//! |--------|-------------------------|------|-------------------------------------------------|
//! | GET    | `/healthz`              | no   | liveness (container health check)               |
//! | GET    | `/v1/status`            | yes  | version, queue length                           |
//! | POST   | `/v1/domains`           | yes  | submit domains resolved by Unbound              |
//! | GET    | `/v1/verdicts`          | yes  | verdicts, highest score first (see below)       |
//! | GET    | `/v1/verdicts/{domain}` | yes  | one verdict                                     |
//! | GET    | `/v1/blocklist`         | yes  | domains scoring at least the threshold, as text |
//!
//! `/v1/verdicts` takes `min_score` (default 0), `q` (domain contains, case-insensitive),
//! `offset` (default 0) and `limit` (default: all, at most 1000 when given). The body is
//! the array of verdicts of the page; `X-Total-Count` gives the number matching the filter.
//!
//! Authenticated routes expect `Authorization: Bearer <SHOPGUARD_TOKEN>`.
//! The plugin only ever sends domain names: no client address, no timestamp.

use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::domain;
use crate::store::Store;

/// Most domains accepted in one request.
pub const MAX_BATCH: usize = 5000;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub queue: mpsc::Sender<String>,
    pub token: Arc<str>,
    pub threshold: u8,
}

pub fn router(state: AppState) -> Router {
    let v1 = Router::new()
        .route("/status", get(status))
        .route("/domains", post(submit))
        .route("/verdicts", get(verdicts))
        .route("/verdicts/{domain}", get(verdict))
        .route("/blocklist", get(blocklist))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth));
    Router::new()
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        )
        .nest("/v1", v1)
        .with_state(state)
}

/// Constant-time comparison, so the token cannot be guessed byte by byte from timings.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match given {
        Some(t) if same(t.as_bytes(), state.token.as_bytes()) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct Status {
    version: &'static str,
    /// Domains never analyzed yet.
    pending: usize,
    /// Domains known (analyzed or not).
    domains: usize,
    threshold: u8,
}

async fn status(State(state): State<AppState>) -> Json<Status> {
    Json(Status {
        version: env!("CARGO_PKG_VERSION"),
        pending: state.store.pending().await,
        domains: state.store.len().await,
        threshold: state.threshold,
    })
}

#[derive(Deserialize)]
struct Submission {
    domains: Vec<String>,
}

#[derive(Serialize, Debug, PartialEq)]
struct Accepted {
    /// New registrable domains queued for analysis.
    queued: usize,
    /// Already seen, or not a public domain name.
    ignored: usize,
    /// Queue full: send them again later.
    deferred: usize,
}

async fn submit(
    State(state): State<AppState>,
    Json(sub): Json<Submission>,
) -> Result<Json<Accepted>, StatusCode> {
    if sub.domains.len() > MAX_BATCH {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let mut res = Accepted {
        queued: 0,
        ignored: 0,
        deferred: 0,
    };
    for name in &sub.domains {
        let Some(d) = domain::registrable(name) else {
            res.ignored += 1;
            continue;
        };
        if !state.store.mark_seen(&d).await {
            res.ignored += 1;
            continue;
        }
        match state.queue.try_send(d) {
            Ok(()) => res.queued += 1,
            Err(mpsc::error::TrySendError::Full(d) | mpsc::error::TrySendError::Closed(d)) => {
                state.store.unmark_seen(&d).await;
                res.deferred += 1;
            }
        }
    }
    Ok(Json(res))
}

/// Most verdicts in one page when `limit` is given.
pub const MAX_PAGE: usize = 1000;

#[derive(Deserialize)]
struct VerdictQuery {
    #[serde(default)]
    min_score: u8,
    /// Part of the domain name.
    #[serde(default)]
    q: String,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

async fn verdicts(
    State(state): State<AppState>,
    Query(q): Query<VerdictQuery>,
) -> impl IntoResponse {
    let needle = q.q.trim().to_ascii_lowercase();
    let all: Vec<_> = state
        .store
        .verdicts(q.min_score)
        .await
        .into_iter()
        .filter(|v| needle.is_empty() || v.domain.contains(&needle))
        .collect();
    let total = all.len();
    let limit = q.limit.map_or(usize::MAX, |l| l.min(MAX_PAGE));
    let page: Vec<_> = all.into_iter().skip(q.offset).take(limit).collect();
    ([("x-total-count", total.to_string())], Json(page))
}

async fn verdict(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let Some(d) = domain::registrable(&name) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state.store.get(&d).await {
        Some(v) => Json(v).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// One domain per line, the format Unbound blocklists accept.
async fn blocklist(State(state): State<AppState>) -> impl IntoResponse {
    let mut body = String::new();
    for v in state.store.verdicts(state.threshold).await {
        body.push_str(&v.domain);
        body.push('\n');
    }
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{Signal, Verdict};
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn app(cap: usize) -> (Router, Arc<Store>, mpsc::Receiver<String>) {
        let store = Arc::new(Store::default());
        let (tx, rx) = mpsc::channel(cap);
        let state = AppState {
            store: store.clone(),
            queue: tx,
            token: TOKEN.into(),
            threshold: 70,
        };
        (router(state), store, rx)
    }

    fn req(method: &str, uri: &str, token: Option<&str>, body: Option<&str>) -> Request {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        match body {
            Some(json) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_owned())),
            None => b.body(Body::empty()),
        }
        .unwrap()
    }

    async fn text(resp: Response) -> String {
        String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn health_needs_no_token() {
        let (app, _, _) = app(10);
        assert_eq!(
            app.oneshot(req("GET", "/healthz", None, None))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn api_needs_the_token() {
        let (app, _, _) = app(10);
        for t in [
            None,
            Some("wrong"),
            Some("0123456789abcdef0123456789abcdeX"),
        ] {
            let r = app
                .clone()
                .oneshot(req("GET", "/v1/status", t, None))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{t:?}");
        }
        let r = app
            .oneshot(req("GET", "/v1/status", Some(TOKEN), None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn submit_queues_new_registrable_domains_once() {
        let (app, _, mut rx) = app(10);
        let body = r#"{"domains":["www.jouetaventure.com","cdn.jouetaventure.com","localhost","example.fr"]}"#;
        let r = app
            .clone()
            .oneshot(req("POST", "/v1/domains", Some(TOKEN), Some(body)))
            .await
            .unwrap();
        assert_eq!(text(r).await, r#"{"queued":2,"ignored":2,"deferred":0}"#);
        assert_eq!(rx.recv().await.as_deref(), Some("jouetaventure.com"));
        assert_eq!(rx.recv().await.as_deref(), Some("example.fr"));
        // seen domains are not queued again
        let r = app
            .oneshot(req(
                "POST",
                "/v1/domains",
                Some(TOKEN),
                Some(r#"{"domains":["example.fr"]}"#),
            ))
            .await
            .unwrap();
        assert_eq!(text(r).await, r#"{"queued":0,"ignored":1,"deferred":0}"#);
    }

    #[tokio::test]
    async fn full_queue_defers_and_forgets() {
        let (app, store, _rx) = app(1);
        let body = r#"{"domains":["a.fr","b.fr"]}"#;
        let r = app
            .oneshot(req("POST", "/v1/domains", Some(TOKEN), Some(body)))
            .await
            .unwrap();
        assert_eq!(text(r).await, r#"{"queued":1,"ignored":0,"deferred":1}"#);
        // b.fr can be submitted again later
        assert!(store.mark_seen("b.fr").await);
    }

    #[tokio::test]
    async fn blocklist_lists_domains_over_threshold() {
        let (app, store, _rx) = app(10);
        let sig = |w| Signal {
            source: "t".into(),
            name: "t".into(),
            weight: w,
            detail: String::new(),
        };
        store
            .insert(Verdict::new("fake.com".into(), vec![sig(90)]))
            .await;
        store
            .insert(Verdict::new("meh.com".into(), vec![sig(40)]))
            .await;
        let r = app
            .clone()
            .oneshot(req("GET", "/v1/blocklist", Some(TOKEN), None))
            .await
            .unwrap();
        assert_eq!(text(r).await, "fake.com\n");
        let r = app
            .oneshot(req("GET", "/v1/verdicts/www.fake.com", Some(TOKEN), None))
            .await
            .unwrap();
        assert!(text(r).await.contains(r#""score":90"#));
    }

    #[tokio::test]
    async fn verdicts_are_filtered_and_paged() {
        let (app, store, _rx) = app(10);
        let sig = |w| Signal {
            source: "t".into(),
            name: "t".into(),
            weight: w,
            detail: String::new(),
        };
        for (d, w) in [
            ("a-shop.fr", 90),
            ("b-shop.fr", 80),
            ("c.fr", 60),
            ("shopx.com", 10),
        ] {
            store.insert(Verdict::new(d.into(), vec![sig(w)])).await;
        }
        let get = |uri: &'static str| {
            let app = app.clone();
            async move {
                let r = app
                    .oneshot(req("GET", uri, Some(TOKEN), None))
                    .await
                    .unwrap();
                let total = r.headers()["x-total-count"].to_str().unwrap().to_owned();
                let body: Vec<Verdict> = serde_json::from_str(&text(r).await).unwrap();
                (
                    total,
                    body.into_iter().map(|v| v.domain).collect::<Vec<_>>(),
                )
            }
        };
        // compatible with the plain call: everything, highest score first
        assert_eq!(
            get("/v1/verdicts").await.1,
            ["a-shop.fr", "b-shop.fr", "c.fr", "shopx.com"]
        );
        assert_eq!(
            get("/v1/verdicts?q=SHOP&min_score=50").await,
            ("2".into(), vec!["a-shop.fr".into(), "b-shop.fr".into()])
        );
        assert_eq!(
            get("/v1/verdicts?offset=1&limit=2").await,
            ("4".into(), vec!["b-shop.fr".into(), "c.fr".into()])
        );
        assert_eq!(get("/v1/verdicts?offset=9").await, ("4".into(), vec![]));
    }
}
