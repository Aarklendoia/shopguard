//! Fetching pages of sites that are hostile by nature, for the page analyzers.
//!
//! Network rules come from [`crate::http::client`]: HTTPS only, every name resolved to
//! public addresses only and connected to those exact addresses, redirects checked and
//! limited. On top of that, here:
//!
//! - HTML only (`text/html`, `application/xhtml+xml`), never executed: the analyzers
//!   read it as text;
//! - the body is read chunk by chunk and dropped past [`MAX_BODY`]; no compression is
//!   asked for (reqwest is built without it), so a small answer cannot inflate;
//! - one request lasts at most [`TIMEOUT`];
//! - at most [`PAGES_PER_DOMAIN`] pages per domain and per [`WINDOW`], and the pages are
//!   kept for that time so that several analyzers share one download.
//!
//! robots.txt is not read: it is meant for crawlers, and the worker is not one. It only
//! looks at a handful of pages of a domain a person on the network has just visited,
//! like a browser would, and a fake shop could use robots.txt to hide from it. The
//! User-Agent says who is asking.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode, Url, header};
use tokio::sync::Mutex;

use crate::domain;

/// Honest, but in the usual browser form: some sites only answer those.
pub const USER_AGENT: &str = concat!(
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

#[derive(Default)]
struct State {
    cache: HashMap<String, (Instant, Result<Page, String>)>,
    /// registrable domain → (window start, pages fetched)
    budget: HashMap<String, (Instant, u32)>,
}

pub struct Fetcher {
    client: Client,
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
    pub fn new(client: Client) -> Self {
        Self {
            client,
            state: Mutex::default(),
        }
    }

    /// The page at `url`, from the cache when fetched less than [`WINDOW`] ago.
    pub async fn get(&self, url: &Url) -> Result<Page, String> {
        let key = url.as_str().to_owned();
        let site = url
            .host_str()
            .and_then(domain::registrable)
            .unwrap_or_else(|| url.host_str().unwrap_or("").to_owned());
        {
            let mut st = self.state.lock().await;
            if let Some((at, page)) = st.cache.get(&key)
                && at.elapsed() < WINDOW
            {
                return page.clone();
            }
            let now = Instant::now();
            let used = st.budget.entry(site.clone()).or_insert((now, 0));
            if used.0.elapsed() >= WINDOW {
                *used = (now, 0);
            }
            if used.1 >= PAGES_PER_DOMAIN {
                return Err(format!("{site}: page budget used"));
            }
            used.1 += 1;
        }
        let page = self.download(url).await;
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

    async fn download(&self, url: &Url) -> Result<Page, String> {
        let mut resp = self
            .client
            .get(url.clone())
            .header(header::USER_AGENT, USER_AGENT)
            .header(header::ACCEPT, "text/html,application/xhtml+xml;q=0.9")
            .header(header::ACCEPT_LANGUAGE, "fr,en;q=0.5")
            .timeout(TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
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

    #[tokio::test]
    async fn html_only_and_size_limit() {
        let (base, task) = server().await;
        let f = Fetcher::new(crate::http::test_client());
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
        // an error comes back with its status, even when it is not HTML
        let p = f.get(&url(&base, "/blocked")).await.unwrap();
        assert_eq!((p.status, p.html.as_str()), (403, ""));
        task.abort();
    }

    #[tokio::test]
    async fn cache_and_budget() {
        let (base, task) = server().await;
        let f = Fetcher::new(crate::http::test_client());
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
