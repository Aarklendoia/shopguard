//! Fetching pages of sites that are hostile by nature, for the page analyzers.
//!
//! Network rules come from [`crate::http::client`]: HTTPS only, every name resolved to
//! public addresses only and connected to those exact addresses, redirects checked and
//! limited. On top of that, here:
//!
//! - HTML only (`text/html`, `application/xhtml+xml`), never executed: the analyzers
//!   read it as text;
//! - the body is read chunk by chunk and dropped past [`MAX_BODY`] *decompressed* bytes
//!   (gzip and brotli are accepted like a browser does), so a small answer cannot
//!   inflate into memory;
//! - one request lasts at most [`TIMEOUT`];
//! - at most [`PAGES_PER_DOMAIN`] pages per domain and per [`WINDOW`], and the pages are
//!   kept for that time so that several analyzers share one download.
//!
//! The worker browses like a person: robots.txt is not read (it only looks at a handful
//! of pages of a domain someone on the network has just visited), and pages are asked
//! for with the headers of a desktop Firefox. Fake shops often show bots something else
//! than visitors (cloaking). Bot protections that compare that User-Agent with the TLS
//! fingerprint (rustls, not Firefox) refuse it, so a refused page (403, 429, challenge
//! page) is asked again once with [`HONEST_USER_AGENT`], which they often let through.
//! When both are refused the site ends up as `page_blocked`. The other clients of the
//! worker (RDAP, DROP lists…) keep their own User-Agent.
//!
//! An outdated Firefox gives a bot away, and Firefox now ships every two weeks: the
//! version is read once a day from Mozilla's [`FIREFOX_VERSIONS_URL`] (the one its own
//! sites use), [`FIREFOX`] until it answers. `SHOPGUARD_USER_AGENT` replaces all that
//! with a fixed User-Agent.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode, Url, header};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::domain;

/// Firefox release when this worker was built; the actual one comes from
/// [`FIREFOX_VERSIONS_URL`].
pub const FIREFOX: u32 = 160;
/// Current Firefox versions, published by Mozilla (`LATEST_FIREFOX_VERSION`).
pub const FIREFOX_VERSIONS_URL: &str =
    "https://product-details.mozilla.org/1.0/firefox_versions.json";
const FIREFOX_TTL: Duration = Duration::from_secs(24 * 3600);
const FIREFOX_RETRY: Duration = Duration::from_secs(3600);

/// User-Agent of desktop Firefox `major` on Windows (the most common one).
pub fn firefox_user_agent(major: u32) -> String {
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{major}.0) Gecko/20100101 Firefox/{major}.0"
    )
}

/// Major version in Mozilla's `firefox_versions.json`. Versions older than the built-in
/// one or absurdly far ahead are refused: a broken or tampered answer cannot make the
/// worker stand out.
pub fn parse_firefox_versions(body: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let major = v
        .get("LATEST_FIREFOX_VERSION")?
        .as_str()?
        .split('.')
        .next()?
        .parse::<u32>()
        .ok()?;
    (FIREFOX..=FIREFOX + 200).contains(&major).then_some(major)
}
/// Second try when the browser identity is refused: protections that compare the
/// browser User-Agent with the TLS fingerprint (rustls, not Firefox) block it, but often
/// let a client that says what it is through.
pub const HONEST_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (compatible; shopguard-worker/",
    env!("CARGO_PKG_VERSION"),
    "; +https://github.com/Aarklendoia/shopguard)"
);
pub const MAX_BODY: usize = 2 * 1024 * 1024;
pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const PAGES_PER_DOMAIN: u32 = 6;
pub const WINDOW: Duration = Duration::from_secs(600);
const CACHE_MAX: usize = 64;

/// A downloaded HTML page.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    /// Address after redirects.
    pub url: Url,
    pub status: u16,
    /// Decoded as UTF-8; invalid sequences replaced (pages in other charsets keep their
    /// ASCII, which is what the analyzers look for).
    pub html: String,
}

impl Page {
    /// The site refuses automated visits: 403, 429, or a bot challenge page.
    pub fn refused(&self) -> bool {
        self.status == 403 || self.status == 429 || is_challenge(&self.html)
    }
}

/// Interstitial pages of bot protections (Cloudflare, DataDome, Imperva, PerimeterX,
/// Akamai): served with 200 instead of the site.
pub fn is_challenge(html: &str) -> bool {
    if html.len() > 64 * 1024 {
        // challenge pages are small; a real page may mention these words
        return false;
    }
    let h = html.to_ascii_lowercase();
    [
        "/cdn-cgi/challenge-platform",
        "cf-chl-",
        "captcha-delivery.com",
        "_incapsula_resource",
        "px-captcha",
        "/_sec/cp_challenge",
    ]
    .iter()
    .any(|m| h.contains(m))
}

/// Current Firefox, refreshed daily.
struct Firefox {
    major: u32,
    checked: Option<Instant>,
    ok: bool,
}

#[derive(Default)]
struct State {
    cache: HashMap<String, (Instant, Result<Page, String>)>,
    /// registrable domain → (window start, pages fetched)
    budget: HashMap<String, (Instant, u32)>,
}

pub struct Fetcher {
    client: Client,
    /// `SHOPGUARD_USER_AGENT`: replaces the current Firefox
    fixed_user_agent: Option<String>,
    versions_url: Url,
    firefox: Mutex<Firefox>,
    state: Mutex<State>,
}

fn is_html(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    let mime = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime == "text/html" || mime == "application/xhtml+xml"
}

impl Fetcher {
    /// `user_agent`: a fixed browser User-Agent; `None` follows the Firefox releases.
    pub fn new(client: Client, user_agent: Option<&str>) -> Self {
        Self {
            client,
            fixed_user_agent: user_agent.map(str::to_owned),
            versions_url: Url::parse(FIREFOX_VERSIONS_URL).expect("static URL"),
            firefox: Mutex::new(Firefox {
                major: FIREFOX,
                checked: None,
                ok: false,
            }),
            state: Mutex::default(),
        }
    }

    #[cfg(test)]
    fn versions_url(mut self, url: Url) -> Self {
        self.versions_url = url;
        self
    }

    /// Browser User-Agent: the fixed one, or the current Firefox (checked once a day,
    /// every hour while Mozilla does not answer).
    pub async fn user_agent(&self) -> String {
        if let Some(ua) = &self.fixed_user_agent {
            return ua.clone();
        }
        let mut ff = self.firefox.lock().await;
        let due = match ff.checked {
            None => true,
            Some(at) => at.elapsed() >= if ff.ok { FIREFOX_TTL } else { FIREFOX_RETRY },
        };
        if due {
            ff.checked = Some(Instant::now());
            match self.latest_firefox().await {
                Ok(major) => {
                    ff.ok = true;
                    // never back: a stale mirror must not age the User-Agent
                    if major > ff.major {
                        info!(major, "Firefox User-Agent updated");
                        ff.major = major;
                    }
                }
                Err(e) => {
                    ff.ok = false;
                    warn!("Firefox version: {e}; staying on {}", ff.major);
                }
            }
        }
        firefox_user_agent(ff.major)
    }

    async fn latest_firefox(&self) -> Result<u32, String> {
        const MAX: usize = 64 * 1024;
        let url = &self.versions_url;
        let mut resp = self
            .client
            .get(url.clone())
            .timeout(TIMEOUT)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("{url}: {e}"))?;
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("{url}: {e}"))? {
            if body.len() + chunk.len() > MAX {
                return Err(format!("{url}: answer larger than {MAX} bytes"));
            }
            body.extend_from_slice(&chunk);
        }
        parse_firefox_versions(&String::from_utf8_lossy(&body))
            .ok_or_else(|| format!("{url}: no plausible LATEST_FIREFOX_VERSION"))
    }

    /// The page at `url`, from the cache when fetched less than [`WINDOW`] ago.
    pub async fn get(&self, url: &Url) -> Result<Page, String> {
        let key = url.as_str().to_owned();
        let site = url
            .host_str()
            .and_then(domain::registrable)
            .unwrap_or_else(|| url.host_str().unwrap_or("").to_owned());
        {
            let st = self.state.lock().await;
            if let Some((at, page)) = st.cache.get(&key)
                && at.elapsed() < WINDOW
            {
                return page.clone();
            }
        }
        if !self.take_budget(&site).await {
            return Err(format!("{site}: page budget used"));
        }
        let ua = self.user_agent().await;
        let mut page = self.download(url, &ua, true).await;
        if matches!(&page, Ok(p) if p.refused())
            && self.take_budget(&site).await
            && let Ok(p) = self.download(url, HONEST_USER_AGENT, false).await
            && !p.refused()
        {
            page = Ok(p);
        }
        let mut st = self.state.lock().await;
        if st.cache.len() >= CACHE_MAX {
            st.cache.retain(|_, (at, _)| at.elapsed() < WINDOW);
            st.budget.retain(|_, (at, _)| at.elapsed() < WINDOW);
            if st.cache.len() >= CACHE_MAX {
                st.cache.clear();
            }
        }
        st.cache.insert(key, (Instant::now(), page.clone()));
        page
    }

    /// One page of the domain's budget; false when used up.
    async fn take_budget(&self, site: &str) -> bool {
        let mut st = self.state.lock().await;
        let now = Instant::now();
        let used = st.budget.entry(site.to_owned()).or_insert((now, 0));
        if used.0.elapsed() >= WINDOW {
            *used = (now, 0);
        }
        if used.1 >= PAGES_PER_DOMAIN {
            return false;
        }
        used.1 += 1;
        true
    }

    async fn download(&self, url: &Url, user_agent: &str, browser: bool) -> Result<Page, String> {
        let mut req = self
            .client
            .get(url.clone())
            .header(header::USER_AGENT, user_agent)
            .header(
                header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header(
                header::ACCEPT_LANGUAGE,
                "fr-FR,fr;q=0.8,en-US;q=0.5,en;q=0.3",
            )
            .timeout(TIMEOUT);
        if browser {
            // what Firefox adds for a typed address; Accept-Encoding is set by reqwest
            req = req
                .header(header::UPGRADE_INSECURE_REQUESTS, "1")
                .header("sec-fetch-dest", "document")
                .header("sec-fetch-mode", "navigate")
                .header("sec-fetch-site", "none")
                .header("sec-fetch-user", "?1")
                .header("priority", "u=0, i");
        }
        let mut resp = req.send().await.map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status();
        if status == StatusCode::NOT_MODIFIED || status.is_informational() {
            return Err(format!("{url}: HTTP {status}"));
        }
        // errors (bot protection, missing page…) come back with their status and no body,
        // whatever their content type
        if status.is_client_error() || status.is_server_error() {
            return Ok(Page {
                url: resp.url().clone(),
                status: status.as_u16(),
                html: String::new(),
            });
        }
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if !is_html(ct.as_deref()) {
            return Err(format!(
                "{url}: not HTML ({})",
                ct.as_deref().unwrap_or("no content type")
            ));
        }
        if resp.content_length().is_some_and(|n| n > MAX_BODY as u64) {
            return Err(format!("{url}: page larger than {MAX_BODY} bytes"));
        }
        let final_url = resp.url().clone();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("{url}: {e}"))? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(format!("{url}: page larger than {MAX_BODY} bytes"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Page {
            url: final_url,
            status: status.as_u16(),
            html: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}

/// Why `html` looks like an online shop, if it does. Cheap text checks on the home
/// page, done before any deeper page is fetched.
pub fn shop_evidence(html: &str) -> Vec<&'static str> {
    let h = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let platforms: &[(&str, &[&str])] = &[
        (
            "Shopify",
            &["cdn.shopify.com", "shopify.theme", "myshopify.com"],
        ),
        (
            "WooCommerce",
            &["woocommerce", "wc-ajax", "wp-content/plugins/woocommerce"],
        ),
        ("PrestaShop", &["prestashop", "/modules/ps_shoppingcart"]),
        ("Magento", &["mage/cookies", "magento", "static/version"]),
        ("Wix Stores", &["wixstores", "wix-ecommerce"]),
        ("BigCommerce", &["cdn11.bigcommerce.com", "bigcommerce"]),
        ("Shopware", &["shopware"]),
        ("OpenCart", &["route=checkout/cart", "catalog/view/theme"]),
    ];
    for (name, marks) in platforms {
        if marks.iter().any(|m| h.contains(m)) {
            out.push(*name);
        }
    }
    if h.contains("schema.org/product")
        || h.contains("\"@type\":\"product\"")
        || h.contains("\"@type\": \"product\"")
        || h.contains("og:type\" content=\"product")
    {
        out.push("product markup");
    }
    let cart = [
        "href=\"/cart",
        "href=\"/panier",
        "href=\"/checkout",
        "href=\"/basket",
        "href=\"/commande",
        "href=\"/warenkorb",
        "href=\"/carrito",
        "/cart\"",
        "/panier\"",
        "add-to-cart",
        "ajout-panier",
        "ajouter au panier",
        "add to cart",
    ];
    if cart.iter().any(|c| h.contains(c)) {
        out.push("cart");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::header::CONTENT_TYPE;
    use axum::routing::get;

    async fn server() -> (String, tokio::task::JoinHandle<()>) {
        let big = "x".repeat(MAX_BODY + 1);
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    (
                        [(CONTENT_TYPE, "text/html; charset=utf-8")],
                        "<html><a href=\"/panier\">Panier</a> é</html>",
                    )
                }),
            )
            .route(
                "/json",
                get(|| async { ([(CONTENT_TYPE, "application/json")], "{}") }),
            )
            .route(
                "/big",
                get(move || {
                    let big = big.clone();
                    async move { ([(CONTENT_TYPE, "text/html")], big) }
                }),
            )
            .route(
                "/moved",
                get(|| async { axum::response::Redirect::temporary("/") }),
            )
            .route(
                "/bomb",
                get(|| async {
                    use std::io::Write;
                    let mut gz =
                        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
                    gz.write_all(&vec![b' '; 3 * MAX_BODY / 2]).unwrap();
                    (
                        [
                            (CONTENT_TYPE, "text/html"),
                            (axum::http::header::CONTENT_ENCODING, "gzip"),
                        ],
                        gz.finish().unwrap(),
                    )
                }),
            )
            .route(
                "/headers",
                get(|h: axum::http::HeaderMap| async move {
                    let v = |k: &str| {
                        h.get(k)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned()
                    };
                    (
                        [(CONTENT_TYPE, "text/html")],
                        format!(
                            "{}|{}|{}|{}",
                            v("user-agent"),
                            v("accept-language"),
                            v("accept-encoding"),
                            v("sec-fetch-mode")
                        ),
                    )
                }),
            )
            .route(
                "/picky",
                // like Cloudflare: browser User-Agent with a non-browser TLS → refused
                get(|h: axum::http::HeaderMap| async move {
                    let ua = h
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if ua.contains("Firefox") {
                        (
                            axum::http::StatusCode::OK,
                            [(CONTENT_TYPE, "text/html")],
                            "<script src=\"/cdn-cgi/challenge-platform/x.js\"></script>".to_owned(),
                        )
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            [(CONTENT_TYPE, "text/html")],
                            format!("<html>welcome {ua}</html>"),
                        )
                    }
                }),
            )
            .route(
                "/versions",
                get(|| async {
                    (
                        [(CONTENT_TYPE, "application/json")],
                        r#"{"LATEST_FIREFOX_VERSION": "171.0", "FIREFOX_ESR": "153.7.0esr"}"#,
                    )
                }),
            )
            .route(
                "/blocked",
                get(|| async {
                    (
                        axum::http::StatusCode::FORBIDDEN,
                        [(CONTENT_TYPE, "text/plain")],
                        "go away",
                    )
                }),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        (base, task)
    }

    fn url(base: &str, path: &str) -> Url {
        Url::parse(&format!("{base}{path}")).unwrap()
    }

    /// Following the Firefox releases of the test server.
    fn fetcher(base: &str) -> Fetcher {
        Fetcher::new(crate::http::test_client(), None).versions_url(url(base, "/versions"))
    }

    #[tokio::test]
    async fn html_only_and_size_limit() {
        let (base, task) = server().await;
        let f = fetcher(&base);
        let p = f.get(&url(&base, "/moved")).await.unwrap();
        assert_eq!(p.url.path(), "/");
        assert!(p.html.contains("é"));
        assert!(
            f.get(&url(&base, "/json"))
                .await
                .unwrap_err()
                .contains("not HTML")
        );
        assert!(
            f.get(&url(&base, "/big"))
                .await
                .unwrap_err()
                .contains("larger")
        );
        // a few KB of gzip inflating past the limit
        assert!(
            f.get(&url(&base, "/bomb"))
                .await
                .unwrap_err()
                .contains("larger")
        );
        // browser headers
        let h = f.get(&url(&base, "/headers")).await.unwrap().html;
        let parts: Vec<&str> = h.split('|').collect();
        // the Firefox of the day
        assert_eq!(parts[0], firefox_user_agent(171));
        assert!(parts[1].starts_with("fr-FR"));
        assert!(parts[2].contains("gzip") && parts[2].contains("br"), "{h}");
        assert_eq!(parts[3], "navigate");
        // challenge for the browser identity: asked again with the honest one
        // (fresh fetcher: the requests above used this server's page budget)
        let fresh = fetcher(&base);
        let p = fresh.get(&url(&base, "/picky")).await.unwrap();
        assert!(!p.refused() && p.html.contains("shopguard-worker"), "{p:?}");
        // an error comes back with its status, even when it is not HTML
        let p = f.get(&url(&base, "/blocked")).await.unwrap();
        assert_eq!((p.status, p.html.as_str()), (403, ""));
        task.abort();
    }

    #[tokio::test]
    async fn cache_and_budget() {
        let (base, task) = server().await;
        let f = fetcher(&base);
        // cached: does not use the budget again
        for _ in 0..10 {
            f.get(&url(&base, "/")).await.unwrap();
        }
        for i in 1..PAGES_PER_DOMAIN {
            let _ = f.get(&url(&base, &format!("/?p={i}"))).await;
        }
        assert!(
            f.get(&url(&base, "/?p=last"))
                .await
                .unwrap_err()
                .contains("budget")
        );
        task.abort();
    }

    #[tokio::test]
    async fn firefox_version() {
        let (base, task) = server().await;
        // Mozilla does not answer (no such page): the built-in version
        let f = Fetcher::new(crate::http::test_client(), None).versions_url(url(&base, "/404"));
        assert_eq!(f.user_agent().await, firefox_user_agent(FIREFOX));
        assert_eq!(fetcher(&base).user_agent().await, firefox_user_agent(171));
        // fixed by SHOPGUARD_USER_AGENT: Mozilla is not asked
        let f = Fetcher::new(crate::http::test_client(), Some("Custom/1.0"))
            .versions_url(url(&base, "/versions"));
        assert_eq!(f.user_agent().await, "Custom/1.0");
        task.abort();
    }

    #[test]
    fn firefox_versions() {
        assert_eq!(
            parse_firefox_versions(r#"{"LATEST_FIREFOX_VERSION": "163.0.1"}"#),
            Some(163)
        );
        assert_eq!(
            parse_firefox_versions(&format!(r#"{{"LATEST_FIREFOX_VERSION": "{FIREFOX}.0"}}"#)),
            Some(FIREFOX)
        );
        // older than the built-in one, absurd, missing, not JSON
        for bad in [
            r#"{"LATEST_FIREFOX_VERSION": "115.0"}"#,
            r#"{"LATEST_FIREFOX_VERSION": "9999.0"}"#,
            r#"{"LATEST_FIREFOX_VERSION": 170}"#,
            r#"{"FIREFOX_ESR": "153.7.0esr"}"#,
            "<html>",
        ] {
            assert_eq!(parse_firefox_versions(bad), None, "{bad}");
        }
        assert_eq!(
            firefox_user_agent(170),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:170.0) Gecko/20100101 Firefox/170.0"
        );
    }

    #[test]
    fn challenge_pages() {
        assert!(is_challenge(
            r#"<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/x"></script>"#
        ));
        assert!(is_challenge(
            r#"<script src="https://ct.captcha-delivery.com/c.js"></script>"#
        ));
        assert!(!is_challenge("<html><h1>Boutique</h1></html>"));
        let big = format!("{}cf-chl-", "x".repeat(70 * 1024));
        assert!(!is_challenge(&big));
    }

    #[test]
    fn content_types() {
        assert!(is_html(Some("text/html")));
        assert!(is_html(Some("Text/HTML; charset=ISO-8859-1")));
        assert!(is_html(Some("application/xhtml+xml")));
        assert!(!is_html(Some("application/json")));
        assert!(!is_html(None));
    }

    #[test]
    fn shops_are_recognized() {
        assert_eq!(
            shop_evidence(
                r#"<script src="https://cdn.shopify.com/s/x.js"></script><a href="/cart">"#
            ),
            ["Shopify", "cart"]
        );
        assert_eq!(
            shop_evidence(r#"<script type="application/ld+json">{"@type": "Product"}</script>"#),
            ["product markup"]
        );
        assert_eq!(
            shop_evidence(r#"<body class="woocommerce-page"><button>Ajouter au panier</button>"#),
            ["WooCommerce", "cart"]
        );
        assert!(shop_evidence("<html><h1>Mairie de Trifouilly</h1></html>").is_empty());
    }
}
