//! HTTP client shared by the analyzers.
//!
//! - TLS through rustls (ring) with the Mozilla roots compiled in: the image is `scratch`,
//!   there is no system certificate store to read.
//! - Every name is resolved by [`PublicResolver`], which drops addresses rejected by
//!   [`netguard::is_public`]: a hostile domain cannot point the worker at the LAN.
//!   reqwest connects to the addresses the resolver returned, so there is no second
//!   lookup an attacker could answer differently (DNS rebinding).
//! - IP literals do not go through a resolver: the redirect policy checks them, and
//!   [`checked_url`] must be used for any URL built from untrusted input.
//! - HTTPS only, few redirects, short timeouts, no proxy from the environment.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Url, redirect};

use crate::netguard;

pub const USER_AGENT: &str = concat!(
    "shopguard-worker/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Aarklendoia/shopguard)"
);

const MAX_REDIRECTS: usize = 3;

/// Resolves with the system resolver and keeps only public addresses.
struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| netguard::is_public(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host}: no public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// True when `url` may be fetched: `https`, and not an IP literal outside the public
/// address space (names are checked by the resolver).
pub fn allowed(url: &Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(_)) => true,
        Some(url::Host::Ipv4(ip)) => netguard::is_public(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => netguard::is_public(IpAddr::V6(ip)),
        None => false,
    }
}

/// Parses `url` and checks it with [`allowed`].
pub fn checked_url(url: &str) -> Option<Url> {
    Url::parse(url).ok().filter(allowed)
}

fn tls() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// The client the analyzers use to reach external services.
pub fn client() -> Client {
    Client::builder()
        .tls_backend_preconfigured(tls())
        .dns_resolver(Arc::new(PublicResolver))
        .https_only(true)
        .redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else if !allowed(attempt.url()) {
                attempt.error("redirect to a refused address")
            } else {
                attempt.follow()
            }
        }))
        .no_proxy()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .expect("static HTTP client configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_to_public_hosts() {
        for ok in [
            "https://rdap.nic.fr/domain/x.fr",
            "https://23.227.38.65/",
            "https://[2606:4700::6810:84e5]/",
        ] {
            assert!(checked_url(ok).is_some(), "{ok}");
        }
        for bad in [
            "http://rdap.nic.fr/",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://[::ffff:192.168.1.1]/",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(checked_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn client_builds() {
        client();
    }

    #[tokio::test]
    async fn resolver_drops_private_addresses() {
        let r = PublicResolver.resolve("localhost".parse().unwrap()).await;
        assert!(r.is_err());
    }
}
