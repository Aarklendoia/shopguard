//! Legal notice: who runs the shop?
//!
//! French online shops must publish their company identifier (SIREN, SIRET, or the VAT
//! number that contains the SIREN) in their legal notice (LCEN, article 6). For a site
//! that looks like a shop (see [`crate::page`]), the identifier is looked for in the home
//! page (often in the footer), then in the legal notice, terms of sale or about pages
//! linked from it, and checked in the French company directory ([`crate::company`]):
//!
//! - an existing, active company weighs towards a legitimate shop (less when it is
//!   recent); fake shops sometimes copy the number of a real company, so it does not
//!   clear a shop on its own;
//! - a number that does not exist, a closed company, or a number with a wrong check
//!   digit weigh heavily towards a fake shop;
//! - no number at all weighs only for French sites (`.fr`, or a page in French): other
//!   countries have other registries and rules.
//!
//! Identifiers of the web host (also mandatory in the legal notice) are skipped.

use std::sync::Arc;

use reqwest::Url;
use tracing::debug;

use crate::analysis::{Analyzer, BoxFuture, Signal};
use crate::company::{Company, Directory, Lookup};
use crate::fetch::{Fetcher, shop_evidence};
use crate::html::{self, Link, fold};
use crate::{domain, page, rdap, siret};

const SOURCE: &str = "legal";
const ACTIVE_WEIGHT: i32 = -20;
/// Active, but created less than [`RECENT_DAYS`] ago.
const RECENT_WEIGHT: i32 = -10;
const RECENT_DAYS: u64 = 365;
const CLOSED_WEIGHT: i32 = 30;
const UNKNOWN_WEIGHT: i32 = 30;
const INVALID_WEIGHT: i32 = 25;
const MISSING_WEIGHT: i32 = 15;
/// Pages read after the home page.
const MAX_PAGES: usize = 3;

/// A company identifier found in a page.
#[derive(Debug, Clone, PartialEq)]
pub enum Id {
    /// Valid check digits: the SIREN.
    Valid(String),
    /// Written as an identifier, but with a wrong check digit.
    Invalid(String),
}

const KEYWORDS: &[&str] = &[
    "siret",
    "siren",
    "rcs",
    "r.c.s",
    "immatricul",
    "registre du commerce",
    "tva",
    "vat",
];

fn floor(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn is_sep(c: char) -> bool {
    matches!(c, ' ' | '\u{a0}' | '\u{202f}' | '.' | '-' | '/')
}

/// Groups of digits at the start of `s`, separated by single separators
/// (`732 829 320 00074`, `732.829.320`).
fn digit_groups(s: &str) -> Vec<String> {
    let mut groups = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            cur.push(c);
            continue;
        }
        if is_sep(c) && !cur.is_empty() && chars.peek().is_some_and(char::is_ascii_digit) {
            groups.push(std::mem::take(&mut cur));
            continue;
        }
        break;
    }
    if !cur.is_empty() {
        groups.push(cur);
    }
    groups
}

/// The identifier written right after a keyword, if any.
fn after_keyword(window: &str) -> Option<Id> {
    let start = window.find(|c: char| c.is_ascii_digit())?;
    let groups = digit_groups(&window[start..]);
    let all: String = groups.concat();
    // intra-community VAT number: FR, a 2-digit key, the SIREN
    if all.len() == 11 && window[..start].trim_end().ends_with("fr") {
        let (key, siren) = all.split_at(2);
        let ok = siret::siren(siren).is_some_and(|s| {
            let n: u64 = s.parse().unwrap_or(0);
            key.parse::<u64>().ok() == Some((12 + 3 * (n % 97)) % 97)
        });
        return Some(if ok {
            Id::Valid(siren.to_owned())
        } else {
            Id::Invalid(format!("FR{all}"))
        });
    }
    let mut prefix = String::new();
    let (mut nine, mut fourteen) = (None, None);
    for g in &groups {
        prefix.push_str(g);
        match prefix.len() {
            9 => nine = Some(prefix.clone()),
            14 => fourteen = Some(prefix.clone()),
            _ => {}
        }
    }
    if let Some(s) = fourteen.as_deref().and_then(siret::siret) {
        return Some(Id::Valid(s[..9].to_owned()));
    }
    if let Some(s) = nine.as_deref().and_then(siret::siren) {
        return Some(Id::Valid(s));
    }
    fourteen.or(nine).map(Id::Invalid)
}

/// Company identifiers in the text of a page, in order, without the web host's.
pub fn identifiers(text: &str) -> Vec<Id> {
    let t = fold(text);
    let mut at: Vec<(usize, usize)> = Vec::new();
    for k in KEYWORDS {
        let mut from = 0;
        while let Some(p) = t[from..].find(k) {
            let pos = from + p;
            from = pos + k.len();
            // whole word start: "parcs" is not "rcs"
            if t[..pos].ends_with(|c: char| c.is_alphanumeric()) {
                continue;
            }
            at.push((pos, pos + k.len()));
        }
    }
    at.sort_unstable();
    let mut out = Vec::new();
    for (pos, end) in at {
        let before = &t[floor(&t, pos.saturating_sub(120))..pos];
        if before.contains("heberg") || before.contains("host") {
            continue;
        }
        let window = &t[end..floor(&t, end + 100)];
        if let Some(id) = after_keyword(window)
            && !out.contains(&id)
        {
            out.push(id);
        }
    }
    out
}

const NOTICE: &[&str] = &[
    "mentions legales",
    "mention legale",
    "mentionslegales",
    "legal notice",
    "informations legales",
    "imprint",
    "impressum",
];
const TERMS: &[&str] = &[
    "cgv",
    "conditions generales",
    "conditions de vente",
    "terms of sale",
    "terms of service",
    "cgu",
];
const ABOUT: &[&str] = &["a propos", "qui sommes nous", "about", "legal"];

/// Rank of a link as a page holding the legal notice: lower is better. What the link
/// says counts more than its address: big sites file many pages under
/// `/mentions-legales/` (privacy, guarantees…) that hold no company number.
fn legal_rank(link: &Link) -> Option<u8> {
    let norm = |s: &str| fold(s).replace(['-', '_', '/', '.'], " ");
    let (text, path) = (norm(&link.text), norm(link.url.path()));
    let has = |s: &str, list: &[&str]| list.iter().any(|w| s.contains(w));
    [
        (&text, NOTICE),
        (&text, TERMS),
        (&path, NOTICE),
        (&path, TERMS),
        (&text, ABOUT),
        (&path, ABOUT),
    ]
    .iter()
    .position(|(s, list)| has(s, list))
    .map(|r| r as u8)
}

/// Whether the shop sells to France: `.fr`, a page in French, or French shop words.
pub fn is_french(domain: &str, html: &str, text: &str) -> bool {
    if domain.ends_with(".fr") || html::lang(html).is_some_and(|l| l.starts_with("fr")) {
        return true;
    }
    let lower = html.to_ascii_lowercase();
    if lower.contains("content=\"fr_fr\"") || lower.contains("content=\"fr-fr\"") {
        return true;
    }
    let t = fold(text);
    [
        "panier",
        "livraison",
        "mentions legales",
        "conditions generales",
        "commande",
        "paiement",
    ]
    .iter()
    .filter(|w| t.contains(*w))
    .count()
        >= 3
}

/// Where shop platforms put the legal notice, for sites that do not link it from the
/// home page (or build their footer in JavaScript).
pub fn platform_pages(evidence: &[&str]) -> &'static [&'static str] {
    if evidence.contains(&"Shopify") {
        &["/policies/legal-notice", "/policies/terms-of-service"]
    } else if evidence.contains(&"PrestaShop") {
        &["/content/2-mentions-legales"]
    } else {
        &[]
    }
}

/// Pages of the same site that may hold the legal notice, best first: the links of the
/// home page, with the `platform` pages after the links that name a legal notice or terms
/// of sale. The site is the one of `base`, the home page actually shown: a domain that
/// redirects elsewhere (`bouygtel.fr` → `bouyguestelecom.fr`) is judged on where it leads.
pub fn legal_links(html: &str, base: &Url, platform: &[&str]) -> Vec<Url> {
    let site = base.host_str().and_then(domain::registrable);
    let mut ranked: Vec<(u8, Url)> = html::links(html, base, usize::MAX)
        .into_iter()
        .filter_map(|l| Some((legal_rank(&l)?, l.url)))
        .filter(|(_, u)| u.host_str().and_then(domain::registrable) == site)
        .filter_map(|(r, mut u)| {
            u.set_fragment(None);
            if u.scheme() == "http" {
                u.set_scheme("https").ok()?;
            }
            Some((r, u))
        })
        .collect();
    // rank 1: after the links saying "legal notice", with those saying "terms of sale"
    ranked.extend(
        platform
            .iter()
            .filter_map(|p| Some((1, base.join(p).ok()?))),
    );
    ranked.sort_by_key(|(r, _)| *r);
    let mut out: Vec<Url> = Vec::new();
    for (_, u) in ranked {
        if u != *base && !out.contains(&u) {
            out.push(u);
        }
    }
    out.truncate(MAX_PAGES);
    out
}

pub struct Legal {
    fetcher: Arc<Fetcher>,
    directory: Directory,
}

impl Legal {
    pub fn new(fetcher: Arc<Fetcher>, directory: Directory) -> Self {
        Self { fetcher, directory }
    }
}

fn signal(name: &str, weight: i32, detail: String) -> Signal {
    Signal {
        source: SOURCE.into(),
        name: name.into(),
        weight,
        detail,
    }
}

fn describe(c: &Company) -> String {
    let mut s = format!("SIREN {}", c.siren);
    if !c.name.is_empty() {
        s.push_str(&format!(" ({})", c.name));
    }
    s
}

/// Signal for the company found in the directory.
pub fn company_signal(c: &Company, page: &Url, today: u64) -> Signal {
    let naf = c
        .naf
        .as_deref()
        .map(|n| format!(", activity {n}"))
        .unwrap_or_default();
    if !c.active {
        let when = c
            .closed
            .as_deref()
            .map(|d| format!(" on {d}"))
            .unwrap_or_default();
        return signal(
            "legal_company_closed",
            CLOSED_WEIGHT,
            format!(
                "{} given on {page} is a company that ceased{when}",
                describe(c)
            ),
        );
    }
    let age = c
        .created
        .as_deref()
        .and_then(rdap::epoch_days)
        .map(|d| today.saturating_sub(d));
    let created = c
        .created
        .as_deref()
        .map(|d| format!(", created {d}"))
        .unwrap_or_default();
    let (name, weight) = match age {
        Some(a) if a < RECENT_DAYS => ("legal_company_recent", RECENT_WEIGHT),
        _ => ("legal_company_active", ACTIVE_WEIGHT),
    };
    signal(
        name,
        weight,
        format!(
            "{} given on {page} is an active company{created}{naf}",
            describe(c)
        ),
    )
}

impl Analyzer for Legal {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn analyze<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<Signal>> {
        Box::pin(async move {
            // the home page comes from the fetcher's cache: the page analyzer got it
            let Ok(home) = page::home(&self.fetcher, domain).await else {
                return Vec::new();
            };
            let evidence = shop_evidence(&home.html);
            if evidence.is_empty() {
                return Vec::new();
            }
            let home_text = html::text(&home.html);
            let french = is_french(domain, &home.html, &home_text);

            let mut ids: Vec<(Id, Url)> = identifiers(&home_text)
                .into_iter()
                .map(|id| (id, home.url.clone()))
                .collect();
            let mut legal_page = None;
            if !ids.iter().any(|(id, _)| matches!(id, Id::Valid(_))) {
                for url in legal_links(&home.html, &home.url, platform_pages(&evidence)) {
                    let Ok(p) = self.fetcher.get(&url).await else {
                        continue;
                    };
                    if p.status >= 400 || p.refused() {
                        continue;
                    }
                    legal_page.get_or_insert_with(|| p.url.clone());
                    let found = identifiers(&html::text(&p.html));
                    let valid = found.iter().any(|id| matches!(id, Id::Valid(_)));
                    for id in found {
                        if !ids.iter().any(|(i, _)| *i == id) {
                            ids.push((id, p.url.clone()));
                        }
                    }
                    if valid {
                        break;
                    }
                }
            }

            // at most two numbers checked: the shop's, and one more when it is unknown
            let valid: Vec<(&str, &Url)> = ids
                .iter()
                .filter_map(|(id, u)| match id {
                    Id::Valid(s) => Some((s.as_str(), u)),
                    Id::Invalid(_) => None,
                })
                .take(2)
                .collect();
            let mut worst: Option<Signal> = None;
            for (siren, url) in &valid {
                let s = match self.directory.lookup(siren).await {
                    Ok(Lookup::Found(c)) => company_signal(&c, url, rdap::today()),
                    Ok(Lookup::Unknown) => signal(
                        "legal_company_unknown",
                        UNKNOWN_WEIGHT,
                        format!("SIREN {siren} given on {url} belongs to no French company"),
                    ),
                    Err(e) => {
                        debug!(%domain, "company directory: {e}");
                        signal(
                            "legal_check_failed",
                            0,
                            format!("SIREN {siren} given on {url} could not be checked: {e}"),
                        )
                    }
                };
                if s.weight <= 0 && s.name != "legal_check_failed" {
                    return vec![s];
                }
                if worst.as_ref().is_none_or(|w| s.weight > w.weight) {
                    worst = Some(s);
                }
            }
            if let Some(s) = worst {
                return vec![s];
            }
            if let Some((Id::Invalid(n), url)) = ids.first() {
                return vec![signal(
                    "legal_number_invalid",
                    INVALID_WEIGHT,
                    format!("company number {n} given on {url} has a wrong check digit"),
                )];
            }
            let where_ = match &legal_page {
                Some(u) => format!("on the home page nor on {u}"),
                None => "on the home page, and no legal notice page was found".into(),
            };
            let (weight, why) = if french {
                (MISSING_WEIGHT, "a French shop must publish it")
            } else {
                (0, "not a French site: other rules")
            };
            vec![signal(
                "legal_id_missing",
                weight,
                format!("no company number (SIREN, SIRET, VAT) {where_} ({why})"),
            )]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_in_text() {
        let t = "Boutique SAS au capital de 10 000 €, RCS Lille B 306 138 900 – SIRET : 306 138 900 01294 \
                 – TVA intracommunautaire : FR 51 306138900. Hébergeur : OVH SAS, RCS Lille 424 761 419.";
        assert_eq!(identifiers(t), [Id::Valid("306138900".into())]);
        // SIRET with dots, VAT stuck together
        assert_eq!(
            identifiers("N° SIRET 552.100.554.00005"),
            [Id::Valid("552100554".into())]
        );
        assert_eq!(
            identifiers("VAT number: FR51306138900"),
            [Id::Valid("306138900".into())]
        );
        // wrong check digits: SIRET, VAT key
        assert_eq!(
            identifiers("Siret : 123 456 789 00012"),
            [Id::Invalid("12345678900012".into())]
        );
        assert_eq!(
            identifiers("TVA FR 52 306138900"),
            [Id::Invalid("FR52306138900".into())]
        );
        // not identifiers: a phone number, a word containing a keyword, no number
        assert!(identifiers("SIRET en cours. Tél : 01 23 45 67 89").is_empty());
        assert!(identifiers("nos parcs 306 138 900").is_empty());
        assert!(identifiers("site hébergé par Gandi, RCS Paris 423 093 459").is_empty());
    }

    /// Every cut of messy HTML full of multi-byte characters goes through every reader
    /// without panicking.
    #[test]
    fn hostile_text_does_not_panic() {
        let base = Url::parse("https://shop.fr/").unwrap();
        let h = "<html lang='fré'>&é;&#x1F600;&#99999999;&amp<a href=\"/mentions-légales\">Mentions légales</a\
                 >SIRET : 3é06 138 900 é01294 RCS\u{a0}Paris 3\u{202f}0\u{202f}6 hébergé TVA FRé51<script>é</scr\
                 <a href='//x'><a hrefé=1>siren 306138900é</a";
        for (i, _) in h.char_indices() {
            let cut = &h[..i];
            let t = html::text(cut);
            identifiers(&t);
            identifiers(cut);
            legal_links(cut, &base, &["/policies/legal-notice"]);
            html::lang(cut);
            html::decode(cut);
        }
    }

    #[test]
    fn digits() {
        assert_eq!(
            digit_groups("732 829 320 00074 - tel"),
            ["732", "829", "320", "00074"]
        );
        assert_eq!(digit_groups("12  34"), ["12"]);
        assert!(digit_groups("x1").is_empty());
    }

    #[test]
    fn legal_pages_first() {
        let base = Url::parse("https://www.shop.fr/").unwrap();
        let h = r#"<a href="/pages/a-propos">Qui sommes-nous</a>
            <a href="/policies/terms-of-service">CGV</a>
            <a href="http://shop.fr/pages/mentions-legales#top">Mentions légales</a>
            <a href="https://mentions.legales.example.com/">Mentions légales</a>
            <a href="/collections/all">Tout</a><a href="/pages/mentions-legales">ML</a>"#;
        let got: Vec<String> = legal_links(h, &base, &[])
            .iter()
            .map(Url::to_string)
            .collect();
        assert_eq!(
            got,
            [
                "https://shop.fr/pages/mentions-legales",
                "https://www.shop.fr/policies/terms-of-service",
                "https://www.shop.fr/pages/mentions-legales",
            ]
        );
        // what the link says first: pages filed under /mentions-legales/ come after the
        // terms of sale (a big shop, its legal links at the end of 1800 others)
        let h = format!(
            "{}<a href=\"/mentions-legales/donnees.html\">Données personnelles</a>\
             <a href=\"/cgv.html#art9\">Conditions générales de vente</a><a href=\"/cgv.html\">CGV</a>",
            "<a href=\"/rayon\">Rayon</a>".repeat(1800)
        );
        let got: Vec<String> = legal_links(&h, &base, &[])
            .iter()
            .map(Url::to_string)
            .collect();
        assert_eq!(
            got,
            [
                "https://www.shop.fr/cgv.html",
                "https://www.shop.fr/mentions-legales/donnees.html",
            ]
        );
    }

    #[test]
    fn platform_fallback() {
        let base = Url::parse("https://shop.fr/").unwrap();
        let shopify = platform_pages(&["Shopify", "cart"]);
        // no link at all (footer in JavaScript)
        let got: Vec<String> = legal_links("<html>", &base, shopify)
            .iter()
            .map(Url::to_string)
            .collect();
        assert_eq!(
            got,
            [
                "https://shop.fr/policies/legal-notice",
                "https://shop.fr/policies/terms-of-service"
            ]
        );
        // a link naming the legal notice comes first, the same page only once
        let h = r#"<a href="/pages/ml">Mentions légales</a><a href="/policies/legal-notice">x</a>"#;
        let got: Vec<String> = legal_links(h, &base, shopify)
            .iter()
            .map(Url::to_string)
            .collect();
        assert_eq!(
            got,
            [
                "https://shop.fr/pages/ml",
                "https://shop.fr/policies/legal-notice",
                "https://shop.fr/policies/terms-of-service"
            ]
        );
        assert!(platform_pages(&["WooCommerce"]).is_empty());
    }

    /// A domain redirecting to another one: the legal notice is looked for on the site
    /// the visitor lands on, any of its hosts, and nowhere else.
    #[test]
    fn site_of_the_page_shown() {
        // bouygtel.fr → https://www.bouyguestelecom.fr/
        let base = Url::parse("https://www.bouyguestelecom.fr/").unwrap();
        let h = r#"<a href="https://www.corporate.bouyguestelecom.fr/mentions-legales">Mentions légales</a>
            <a href="https://www.bouygtel.fr/mentions-legales">Mentions légales</a>
            <a href="https://www.bouygues.com/mentions-legales">Mentions légales</a>"#;
        let got: Vec<String> = legal_links(h, &base, &[])
            .iter()
            .map(Url::to_string)
            .collect();
        assert_eq!(
            got,
            ["https://www.corporate.bouyguestelecom.fr/mentions-legales"]
        );
    }

    #[test]
    fn french_sites() {
        assert!(is_french("shop.fr", "", ""));
        assert!(is_french("shop.com", "<html lang=\"fr\">", ""));
        assert!(is_french(
            "shop.com",
            "<meta property=\"og:locale\" content=\"fr_FR\">",
            ""
        ));
        assert!(is_french(
            "shop.com",
            "<html>",
            "Mon panier – Livraison offerte – Paiement sécurisé"
        ));
        assert!(!is_french(
            "shop.com",
            "<html lang=\"en\">",
            "Cart – Free shipping"
        ));
    }

    #[test]
    fn company_signals() {
        let page = Url::parse("https://shop.fr/").unwrap();
        let today = rdap::epoch_days("2026-11-16").unwrap();
        let mut c = Company {
            siren: "306138900".into(),
            name: "DECATHLON".into(),
            active: true,
            created: Some("1977-01-01".into()),
            closed: None,
            naf: Some("68.20B".into()),
        };
        let s = company_signal(&c, &page, today);
        assert_eq!(
            (s.name.as_str(), s.weight),
            ("legal_company_active", ACTIVE_WEIGHT)
        );
        assert!(s.detail.contains("DECATHLON") && s.detail.contains("1977-01-01"));
        c.created = Some("2026-09-01".into());
        let s = company_signal(&c, &page, today);
        assert_eq!(
            (s.name.as_str(), s.weight),
            ("legal_company_recent", RECENT_WEIGHT)
        );
        c.active = false;
        c.closed = Some("2026-10-01".into());
        let s = company_signal(&c, &page, today);
        assert_eq!(
            (s.name.as_str(), s.weight),
            ("legal_company_closed", CLOSED_WEIGHT)
        );
        assert!(s.detail.contains("2026-10-01"));
    }
}
