//! Signals from the TLS certificate a domain presents on port 443.
//!
//! The worker opens a TLS connection to the domain (then `www.`), reads the certificate
//! chain and closes: no HTTP request is sent. The chain is validated against the
//! compiled-in Mozilla roots, but an invalid certificate does not abort the handshake:
//! it is the signal.
//!
//! The age of the presented certificate alone means little (Let's Encrypt certificates
//! live 90 days); it is reported for information and becomes useful with the
//! Certificate Transparency history (first certificate ever issued for the domain).

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::analysis::{Analyzer, BoxFuture, Signal};
use crate::{domain, http};

const SOURCE: &str = "tls";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Neither the domain nor `www.` answers TLS on port 443: a shop takes payments, it has
/// HTTPS. Small weight: many domains seen by a resolver are not websites (APIs, mail…).
const NO_HTTPS_WEIGHT: i32 = 10;
/// Expired, self-signed, wrong name…: browsers warn, real shops fix it.
const INVALID_WEIGHT: i32 = 15;
/// One certificate covering this many unrelated registrable domains: shared platform.
const SHARED_DOMAINS: usize = 20;
const SHARED_WEIGHT: i32 = 10;
/// OV/EV certificate (an organization in the subject, checked by the CA): leans legitimate.
const ORGANIZATION_WEIGHT: i32 = -10;

/// What the handshake showed.
#[derive(Debug, Clone, PartialEq)]
struct Probe {
    host: String,
    /// `None` when the chain is valid for `host`, else why it is not.
    invalid: Option<String>,
    issuer: String,
    /// Organization in the subject (OV/EV certificates only).
    organization: Option<String>,
    /// Unix time.
    not_before: i64,
    /// DNS names of the subjectAltName extension.
    names: Vec<String>,
}

/// Validates like a browser would, records the outcome, and lets the handshake go on.
#[derive(Debug)]
struct Recorder {
    inner: Arc<WebPkiServerVerifier>,
    outcome: Mutex<Option<String>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Err(e) = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            *self.outcome.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.to_string());
        }
        // nothing is sent over this connection: reading the certificate is the point
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub struct Tls {
    verifier: Arc<WebPkiServerVerifier>,
}

impl Tls {
    pub fn new() -> Self {
        Self::with_roots(http::roots())
    }

    fn with_roots(roots: Arc<rustls::RootCertStore>) -> Self {
        let verifier = WebPkiServerVerifier::builder_with_provider(roots, http::crypto())
            .build()
            .expect("non-empty root store");
        Self { verifier }
    }

    /// TLS handshake with `host` on the first of `addrs` that accepts a connection.
    async fn probe(&self, host: &str, addrs: &[SocketAddr]) -> Result<Probe, String> {
        let mut tcp = None;
        for a in addrs {
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
                Ok(Ok(s)) => {
                    tcp = Some(s);
                    break;
                }
                Ok(Err(e)) => debug!(%host, addr = %a, "connect: {e}"),
                Err(_) => debug!(%host, addr = %a, "connect: timeout"),
            }
        }
        let tcp = tcp.ok_or("port 443 closed or unreachable")?;

        let recorder = Arc::new(Recorder {
            inner: self.verifier.clone(),
            outcome: Mutex::new(None),
        });
        let config = rustls::ClientConfig::builder_with_provider(http::crypto())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(recorder.clone())
            .with_no_client_auth();
        let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
        let stream = timeout(
            HANDSHAKE_TIMEOUT,
            TlsConnector::from(Arc::new(config)).connect(name, tcp),
        )
        .await
        .map_err(|_| "TLS handshake timeout".to_owned())?
        .map_err(|e| format!("TLS handshake: {e}"))?;

        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or("no certificate")?;
        let invalid = recorder
            .outcome
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        parse_leaf(host, leaf, invalid)
    }
}

fn parse_leaf(host: &str, der: &[u8], invalid: Option<String>) -> Result<Probe, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("certificate: {e}"))?;
    let first = |name: &x509_parser::x509::X509Name, org: bool| {
        let mut it: Box<dyn Iterator<Item = _>> = if org {
            Box::new(name.iter_organization())
        } else {
            Box::new(name.iter_common_name())
        };
        it.next()
            .and_then(|a| a.as_str().ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    let issuer = first(cert.issuer(), true)
        .or_else(|| first(cert.issuer(), false))
        .unwrap_or_else(|| "unknown issuer".into());
    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(d) => Some(d.to_ascii_lowercase()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Probe {
        host: host.to_owned(),
        invalid,
        issuer,
        organization: first(cert.subject(), true),
        not_before: cert.validity().not_before.timestamp(),
        names,
    })
}

/// Registrable domains other than `domain` among the certificate names.
fn other_domains(domain: &str, names: &[String]) -> usize {
    names
        .iter()
        .filter_map(|n| domain::registrable(n.trim_start_matches("*.")))
        .filter(|d| d != domain)
        .collect::<BTreeSet<_>>()
        .len()
}

fn signal(name: &str, weight: i32, detail: String) -> Signal {
    Signal {
        source: SOURCE.into(),
        name: name.into(),
        weight,
        detail,
    }
}

/// Signals for the probe of `domain`, made at Unix time `now`.
fn signals(domain: &str, p: &Probe, now: i64) -> Vec<Signal> {
    let age = (now - p.not_before).max(0) / 86_400;
    let mut out = vec![signal(
        "tls_cert_age_days",
        0,
        format!(
            "{} presents a certificate issued {age} days ago by {}",
            p.host, p.issuer
        ),
    )];
    if let Some(why) = &p.invalid {
        out.push(signal(
            "tls_invalid",
            INVALID_WEIGHT,
            format!("browsers reject the certificate of {}: {why}", p.host),
        ));
    }
    let others = other_domains(domain, &p.names);
    if others >= SHARED_DOMAINS {
        out.push(signal(
            "tls_shared",
            SHARED_WEIGHT,
            format!("certificate shared with {others} other domains (hosting platform)"),
        ));
    }
    if let (Some(org), None) = (&p.organization, &p.invalid) {
        out.push(signal(
            "tls_organization",
            ORGANIZATION_WEIGHT,
            format!("certificate issued to the organization \"{org}\" (OV/EV)"),
        ));
    }
    out
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Analyzer for Tls {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn analyze<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<Signal>> {
        Box::pin(async move {
            let mut resolved = false;
            let mut last_error = String::new();
            for host in [domain.to_owned(), format!("www.{domain}")] {
                let addrs = match http::resolve_public(&host, 443).await {
                    Ok(a) => a,
                    Err(e) => {
                        debug!(%host, "{e}");
                        continue;
                    }
                };
                resolved = true;
                match self.probe(&host, &addrs).await {
                    Ok(p) => return signals(domain, &p, now()),
                    Err(e) => {
                        debug!(%host, "TLS probe: {e}");
                        last_error = e;
                    }
                }
            }
            if !resolved {
                return vec![signal(
                    "tls_no_address",
                    0,
                    format!("neither {domain} nor www.{domain} has a public address"),
                )];
            }
            vec![signal(
                "tls_none",
                NO_HTTPS_WEIGHT,
                format!("no HTTPS on {domain} nor www.{domain} ({last_error})"),
            )]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(names: &[&str], invalid: Option<&str>, org: Option<&str>) -> Probe {
        Probe {
            host: "shop.fr".into(),
            invalid: invalid.map(Into::into),
            issuer: "Let's Encrypt".into(),
            organization: org.map(Into::into),
            not_before: 0,
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn weights(p: &Probe) -> Vec<(String, i32)> {
        signals("shop.fr", p, 86_400 * 10)
            .into_iter()
            .map(|s| (s.name, s.weight))
            .collect()
    }

    #[test]
    fn plain_valid_certificate() {
        let p = probe(&["shop.fr", "www.shop.fr"], None, None);
        assert_eq!(weights(&p), vec![("tls_cert_age_days".into(), 0)]);
        assert!(
            signals("shop.fr", &p, 86_400 * 10)[0]
                .detail
                .contains("10 days ago")
        );
    }

    #[test]
    fn invalid_and_organization() {
        assert_eq!(
            weights(&probe(&[], Some("expired"), None))[1],
            ("tls_invalid".into(), INVALID_WEIGHT)
        );
        assert_eq!(
            weights(&probe(&[], None, Some("Shop SAS")))[1],
            ("tls_organization".into(), ORGANIZATION_WEIGHT)
        );
        // an organization on an invalid certificate proves nothing
        assert_eq!(weights(&probe(&[], Some("expired"), Some("X"))).len(), 2);
    }

    #[test]
    fn shared_certificate() {
        let many: Vec<String> = (0..25).map(|i| format!("*.store{i}.com")).collect();
        let names: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            other_domains(
                "shop.fr",
                &names.iter().map(|s| s.to_string()).collect::<Vec<_>>()
            ),
            25
        );
        assert!(
            weights(&probe(&names, None, None)).contains(&("tls_shared".into(), SHARED_WEIGHT))
        );
        // subdomains of the same domain do not count
        let own = ["shop.fr", "www.shop.fr", "cdn.shop.fr", "*.shop.fr"].map(String::from);
        assert_eq!(other_domains("shop.fr", &own), 0);
    }

    /// TLS server on loopback with a self-signed certificate for `shop.test`.
    async fn server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let mut params =
            rcgen::CertificateParams::new(vec!["shop.test".into(), "www.shop.test".into()])
                .unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Fake Shop");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(http::crypto())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                let _ = acceptor.accept(s).await;
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn reads_an_invalid_certificate() {
        let (addr, task) = server().await;
        let p = Tls::new().probe("shop.test", &[addr]).await.unwrap();
        task.abort();
        assert!(
            p.invalid.as_deref().unwrap().contains("UnknownIssuer"),
            "{p:?}"
        );
        assert_eq!(p.names, vec!["shop.test", "www.shop.test"]);
        assert_eq!(p.organization.as_deref(), Some("Fake Shop"));
        let w = weights(&p);
        assert!(w.contains(&("tls_invalid".into(), INVALID_WEIGHT)));
        assert!(!w.iter().any(|(n, _)| n == "tls_organization"));
    }

    #[tokio::test]
    async fn closed_port() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        assert!(Tls::new().probe("shop.test", &[addr]).await.is_err());
    }
}
