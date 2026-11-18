//! Registration date through WHOIS (port 43), for the TLDs without RDAP whose registry
//! WHOIS gives a creation date (#52).
//!
//! Only registries checked by hand are listed: most ccTLD servers without RDAP answer
//! without any date (`.de`, `.ch`, `.eu`) or not at all (`.shop`). These servers throttle
//! per IP address: [`crate::rdap`] queries them one at a time, spaced, and caches the
//! answers like its own.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::http;
use crate::rdap::epoch_days;

const PORT: u16 = 43;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole exchange, connection included.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// A WHOIS answer is a few kilobytes; more is not a WHOIS answer.
const MAX_ANSWER: u64 = 64 * 1024;

/// TLD → WHOIS server answering with a `Creation Date:` line, checked on 18 November 2026.
const SERVERS: &[(&str, &str)] = &[
    // Identity Digital
    ("ac", "whois.nic.ac"),
    ("io", "whois.nic.io"),
    ("lc", "whois.nic.lc"),
    ("me", "whois.nic.me"),
    ("mn", "whois.nic.mn"),
    ("sh", "whois.nic.sh"),
    ("vc", "whois.identitydigital.services"),
    // GoDaddy Registry
    ("co", "whois.registry.co"),
];

/// WHOIS server for `domain`, by its TLD.
pub fn server(domain: &str) -> Option<&'static str> {
    let tld = domain.rsplit('.').next()?;
    SERVERS
        .iter()
        .find(|(t, _)| t.eq_ignore_ascii_case(tld))
        .map(|(_, s)| *s)
}

/// What the registry WHOIS says about a domain.
#[derive(Debug, PartialEq)]
pub enum Answer {
    /// Creation day, in days since the Unix epoch.
    Created(u64),
    NotFound,
}

/// Reads a WHOIS answer: the `Creation Date:` line, or a "not found" message. Anything
/// else (a refusal when throttled, a changed format) is an error.
pub fn parse(text: &str) -> Result<Answer, String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("creation date")
        {
            return epoch_days(value.trim())
                .map(Answer::Created)
                .ok_or_else(|| format!("unreadable creation date: {}", value.trim()));
        }
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("domain not found") || lower.contains("does not exist") {
        return Ok(Answer::NotFound);
    }
    let first = text.lines().map(str::trim).find(|l| !l.is_empty());
    Err(format!(
        "no creation date in the answer ({})",
        first.unwrap_or("empty")
    ))
}

/// Queries `server` about `domain`. The server name is resolved through
/// [`http::resolve_public`] like any other connection of the worker.
pub async fn query(server: &str, domain: &str) -> Result<Answer, String> {
    let addrs = http::resolve_public(server, PORT)
        .await
        .map_err(|e| e.to_string())?;
    let text = timeout(QUERY_TIMEOUT, exchange(&addrs, domain))
        .await
        .map_err(|_| "timeout".to_owned())??;
    parse(&text)
}

/// Sends the query to the first of `addrs` that accepts a connection and reads the answer
/// until the server closes the connection.
async fn exchange(addrs: &[SocketAddr], domain: &str) -> Result<String, String> {
    let mut stream = None;
    for a in addrs {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            Ok(Err(e)) => debug!(addr = %a, "WHOIS connect: {e}"),
            Err(_) => debug!(addr = %a, "WHOIS connect: timeout"),
        }
    }
    let mut stream = stream.ok_or("port 43 closed or unreachable")?;
    stream
        .write_all(format!("{domain}\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    (&mut stream)
        .take(MAX_ANSWER)
        .read_to_end(&mut answer)
        .await
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&answer).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_by_tld() {
        assert_eq!(server("fake-shop.io"), Some("whois.nic.io"));
        assert_eq!(server("Boutique.ME"), Some("whois.nic.me"));
        assert_eq!(server("shop.com.co"), Some("whois.registry.co"));
        assert_eq!(server("example.de"), None);
        assert_eq!(server("example.shop"), None);
    }

    #[test]
    fn identity_digital_answer() {
        let text = "Domain Name: google.io\r\n\
                    Registry Domain ID: REDACTED\r\n\
                    Updated Date: 2026-09-01T00:00:00Z\r\n\
                    Creation Date: 2002-10-01T01:00:00Z\r\n\
                    Registry Expiry Date: 2027-10-01T01:00:00Z\r\n";
        assert_eq!(
            parse(text),
            Ok(Answer::Created(epoch_days("2002-10-01").unwrap()))
        );
    }

    #[test]
    fn indented_and_fractional_seconds() {
        let text = "   Domain Name: GOOGLE.CO\n   Creation Date: 2010-02-25T01:04:59.0Z\n";
        assert_eq!(
            parse(text),
            Ok(Answer::Created(epoch_days("2010-02-25").unwrap()))
        );
    }

    #[test]
    fn not_found() {
        assert_eq!(
            parse(
                "Domain not found.\r\n>>> Last update of WHOIS database: 2026-11-18T13:14:11Z <<<\r\n"
            ),
            Ok(Answer::NotFound)
        );
        assert_eq!(
            parse("The queried object does not exist: DOMAIN NOT FOUND\n"),
            Ok(Answer::NotFound)
        );
    }

    #[test]
    fn refusals_are_errors() {
        assert!(parse("").is_err());
        let e = parse("\r\nQuery rate limit exceeded\r\n").unwrap_err();
        assert!(e.contains("Query rate limit exceeded"), "{e}");
        assert!(parse("Creation Date: soon\n").is_err());
    }

    #[tokio::test]
    async fn exchange_with_a_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"fake-shop.io\r\n");
            s.write_all(b"Creation Date: 2026-11-10T08:00:00Z\r\n")
                .await
                .unwrap();
        });
        let text = exchange(&[addr], "fake-shop.io").await.unwrap();
        server.await.unwrap();
        assert_eq!(
            parse(&text),
            Ok(Answer::Created(epoch_days("2026-11-10").unwrap()))
        );
    }
}
