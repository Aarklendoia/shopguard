//! Domain names as the worker handles them: the registrable domain (eTLD+1).
//!
//! The resolver sees `www.shop.example.co.uk`, `cdn.shop.example.co.uk`…: they are all
//! scored once, as `example.co.uk`, using the Public Suffix List compiled into `psl`.

/// Registrable domain of `name`, lowercase, without trailing dot.
///
/// Returns `None` for names that cannot be a public website: bare public suffixes
/// (`co.uk`), single labels (`localhost`, `router`), IP literals, reverse zones and
/// names with characters a hostname cannot hold.
pub fn registrable(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || !name.contains('.') {
        return None;
    }
    if name.ends_with(".arpa") || name.ends_with(".local") || name.ends_with(".internal") {
        return None;
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let valid_label = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if !name.split('.').all(valid_label) {
        return None;
    }
    let domain = psl::domain(name.as_bytes())?;
    // a suffix missing from the list (.lan, .home, .box…) is a local name, not a website.
    // Private suffixes (github.io, myshopify.com…) are known: each hosted shop stays a
    // separate domain, which is what we want.
    if !domain.suffix().is_known() {
        return None;
    }
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::registrable;

    #[test]
    fn keeps_registrable_domain() {
        assert_eq!(
            registrable("www.JouetAventure.com."),
            Some("jouetaventure.com".into())
        );
        assert_eq!(
            registrable("a.b.example.co.uk"),
            Some("example.co.uk".into())
        );
        assert_eq!(registrable("shop.example.fr"), Some("example.fr".into()));
    }

    #[test]
    fn hosted_shops_stay_separate() {
        // myshopify.com is a private suffix in the PSL
        assert_eq!(
            registrable("fake-toys.myshopify.com"),
            Some("fake-toys.myshopify.com".into())
        );
    }

    #[test]
    fn rejects_non_public_names() {
        for name in [
            "",
            "localhost",
            "co.uk",
            "192.0.2.1",
            "2001:db8::1",
            "1.2.0.192.in-addr.arpa",
            "printer.local",
            "router.lan",
            "nas.home",
            "bad..example.com",
            "-bad.example.com",
            "spa ce.example.com",
        ] {
            assert_eq!(registrable(name), None, "{name}");
        }
    }
}
