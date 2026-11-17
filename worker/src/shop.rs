//! Shop heuristics: what the home page of a shop shows that a real shop does not.
//!
//! Runs only when the `page` analyzer saw a shop, on the same home page (from the
//! fetcher's cache). Measured on the home pages of 35 fake shops added to HaGeZi *Fake*
//! in November 2026 and 13 real French shops:
//!
//! - **fake shop kit**: most fakes are built from the same Shopify kit, whose fixed
//!   English phrases ("Free Shipping Secure Checkout Quality Guaranteed", "Fresh
//!   additions to our store"…) stay even on German or French shops: 29 of 35 fakes
//!   show at least two of them, no real shop does;
//! - **uniform discount**: the kit copies the catalogue of a real shop and marks every
//!   product down by about the same ratio (−20 to −30 %): 20 of 35 fakes, no real shop
//!   (sales have tiers, and leave products at full price).

use std::sync::Arc;

use crate::analysis::{Analyzer, BoxFuture, Signal};
use crate::fetch::Fetcher;
use crate::{html, page};

const SOURCE: &str = "shop";

/// Fixed phrases of the fake shop kit, lower case.
const KIT_PHRASES: &[&str] = &[
    "free shipping secure checkout quality guaranteed",
    "fresh additions to our store",
    "top-rated products chosen by shoppers like you",
    "most popular picks this week",
    "handpicked products from trusted brands",
    "highlights from our collection",
    "fresh arrivals and customer favorites",
    "limited time offer",
];
/// One phrase can be a coincidence ("limited time offer").
const KIT_MIN: usize = 2;
const KIT_WEIGHT: i32 = 30;

/// Two prices closer than this (bytes of text) are a sale price and its crossed-out
/// price.
const PAIR_GAP: usize = 40;
const DISCOUNT_MIN_PAIRS: usize = 8;
/// Share of the prices shown that belong to a discounted pair.
const DISCOUNT_MIN_SHARE: f64 = 0.8;
/// Share of the discounts within [`DISCOUNT_SPREAD`] of their median.
const DISCOUNT_MIN_NEAR: f64 = 0.75;
const DISCOUNT_SPREAD: f64 = 0.05;
const DISCOUNT_WEIGHT: i32 = 15;

/// Kit phrases found in `text` (any case).
pub fn kit_phrases(text: &str) -> Vec<&'static str> {
    let t = text.to_lowercase();
    KIT_PHRASES
        .iter()
        .copied()
        .filter(|p| t.contains(p))
        .collect()
}

fn is_space(c: char) -> bool {
    c == ' ' || c == '\u{a0}' || c == '\u{202f}'
}

/// Amount written just before byte `end` of `t` (`12`, `12.99`, `12,99`), with its
/// start, skipping one space.
fn amount_before(t: &str, end: usize) -> Option<(usize, f64)> {
    let s = t[..end].trim_end_matches(is_space);
    let start = s
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_digit() || *c == '.' || *c == ',')
        .last()
        .map(|(i, _)| i)?;
    Some((start, parse_amount(&s[start..])?))
}

/// Amount written just after byte `start` of `t`, skipping one space.
fn amount_after(t: &str, start: usize) -> Option<(usize, f64)> {
    let rest = &t[start..];
    let trimmed = rest.trim_start_matches(is_space);
    let at = start + rest.len() - trimmed.len();
    let len = trimmed
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit() || *c == '.' || *c == ',')
        .last()
        .map(|(i, c)| i + c.len_utf8())?;
    Some((at, parse_amount(&trimmed[..len])?))
}

/// `12`, `12.99`, `12,99`; at most 6 digits before the decimals, no thousands
/// separator (`1.299,00` is not read: rare in the prices that matter here).
fn parse_amount(s: &str) -> Option<f64> {
    let s = s.trim_end_matches(['.', ',']);
    let (int, dec) = match s.find(['.', ',']) {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    };
    let ok = (1..=6).contains(&int.len())
        && int.bytes().all(|b| b.is_ascii_digit())
        && (dec.is_empty() || (dec.len() == 2 && dec.bytes().all(|b| b.is_ascii_digit())));
    if !ok {
        return None;
    }
    format!("{int}.{}", if dec.is_empty() { "0" } else { dec })
        .parse()
        .ok()
        .filter(|v: &f64| *v > 0.0)
}

/// Prices in `text` (`€12.99`, `12,99 €`, `$5`, `£3.50`), with their position, in order.
pub fn prices(text: &str) -> Vec<(usize, f64)> {
    let mut out: Vec<(usize, f64)> = Vec::new();
    for (i, c) in text.char_indices() {
        if !matches!(c, '€' | '$' | '£') {
            continue;
        }
        let found = amount_after(text, i + c.len_utf8()).or_else(|| amount_before(text, i));
        if let Some((at, v)) = found
            && !out.iter().any(|(p, _)| *p == at)
        {
            out.push((at, v));
        }
    }
    out.sort_by_key(|(p, _)| *p);
    out
}

/// Discount of each sale price shown next to its crossed-out price (either order).
fn discounts(prices: &[(usize, f64)]) -> Vec<f64> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < prices.len() {
        let ((a, p), (b, q)) = (prices[i], prices[i + 1]);
        if b - a <= PAIR_GAP && p != q {
            out.push(1.0 - p.min(q) / p.max(q));
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// Every product marked down by about the same ratio: detail of the signal, if so.
pub fn uniform_discount(text: &str) -> Option<String> {
    let all = prices(text);
    let mut d = discounts(&all);
    if d.len() < DISCOUNT_MIN_PAIRS
        || (2 * d.len()) as f64 / (all.len() as f64) < DISCOUNT_MIN_SHARE
    {
        return None;
    }
    d.sort_by(f64::total_cmp);
    let median = d[d.len() / 2];
    let near: Vec<f64> = d
        .iter()
        .copied()
        .filter(|x| (x - median).abs() <= DISCOUNT_SPREAD)
        .collect();
    if (near.len() as f64) / (d.len() as f64) < DISCOUNT_MIN_NEAR {
        return None;
    }
    let pct = |x: f64| (x * 100.0).round() as u32;
    Some(format!(
        "{} of {} products shown are discounted, {} of them by {}–{} % (median {} %)",
        d.len(),
        all.len() - d.len(),
        near.len(),
        pct(near[0]),
        pct(near[near.len() - 1]),
        pct(median)
    ))
}

fn signal(name: &str, weight: i32, detail: String) -> Signal {
    Signal {
        source: SOURCE.into(),
        name: name.into(),
        weight,
        detail,
    }
}

/// Signals for the visible text of a shop's home page.
pub fn signals(text: &str) -> Vec<Signal> {
    let mut out = Vec::new();
    let kit = kit_phrases(text);
    if kit.len() >= KIT_MIN {
        out.push(signal(
            "shop_kit",
            KIT_WEIGHT,
            format!(
                "phrases of a fake shop kit on the home page: \"{}\"",
                kit.join("\", \"")
            ),
        ));
    }
    if let Some(d) = uniform_discount(text) {
        out.push(signal("discount_uniform", DISCOUNT_WEIGHT, d));
    }
    out
}

pub struct Shop {
    fetcher: Arc<Fetcher>,
}

impl Shop {
    pub fn new(fetcher: Arc<Fetcher>) -> Self {
        Self { fetcher }
    }
}

impl Analyzer for Shop {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn analyze<'a>(&'a self, domain: &'a str, earlier: &'a [Signal]) -> BoxFuture<'a, Vec<Signal>> {
        Box::pin(async move {
            if !earlier
                .iter()
                .any(|s| s.source == "page" && s.name == "page_shop")
            {
                return Vec::new();
            }
            // from the fetcher's cache: the page analyzer got it
            let Ok(home) = page::home(&self.fetcher, domain).await else {
                return Vec::new();
            };
            signals(&html::text(&home.html))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kit's home page, as its text comes out of `html::text` (a German fake: the
    /// kit's phrases stay in English).
    fn kit_home(products: &[(&str, &str, &str)]) -> String {
        let mut s = String::from(
            "Diswohngut Kostenloser Versand ab €99.00 Alle ansehen → de 🇪🇺 EUR € New Collection \
             Diswohngut Fresh arrivals and customer favorites, all in one place. Shop Best \
             Sellers Free Shipping Secure Checkout Quality Guaranteed Trending Now Most \
             popular picks this week Alle ansehen → ",
        );
        for (name, sale, was) in products {
            s.push_str(&format!("New Quick Buy €{sale} €{was} {name} "));
        }
        s.push_str(
            "Limited Time Offer Best Sellers Top-rated products chosen by shoppers like you.",
        );
        s
    }

    const PRODUCTS: &[(&str, &str, &str)] = &[
        (
            "Ib Laursen Vase Claire mit breiter Kante, 17cm",
            "8.47",
            "11.50",
        ),
        ("Ib Laursen Topf mit dicker Kante, 7,5cm", "4.90", "6.50"),
        ("Ib Laursen Topf mit Rillen, 11cm", "5.69", "7.90"),
        ("Ib Laursen Vase Clarity, Ø:3 cm", "5.19", "6.90"),
        (
            "Ib Laursen Kerzenhalter schüsselförmig, blau",
            "9.28",
            "12.90",
        ),
        ("Storefactory Vase Fröåsen weiß groß", "31.59", "42.50"),
        ("Hase aus Keramik schwarz", "15.88", "19.90"),
        (
            "Sander Tischläufer Fluffys Gang grau 40x93 cm",
            "23.15",
            "29.95",
        ),
        ("Sander Tischset Novella 35x50", "13.78", "18.95"),
    ];

    #[test]
    fn fake_shop_kit() {
        let t = kit_home(PRODUCTS);
        let s = signals(&t);
        assert_eq!(s[0].name, "shop_kit");
        assert_eq!(s[0].weight, 30);
        assert!(
            s[0].detail
                .contains("fresh arrivals and customer favorites")
        );
        assert_eq!(s[1].name, "discount_uniform");
        assert_eq!(
            s[1].detail,
            "9 of 10 products shown are discounted, 8 of them by 23–28 % (median 26 %)"
        );
        // one phrase is not a kit
        assert!(signals("Black Friday: limited time offer on everything").is_empty());
    }

    #[test]
    fn price_formats() {
        let v = |t: &str| prices(t).into_iter().map(|(_, v)| v).collect::<Vec<_>>();
        assert_eq!(v("€8.31 €10.99"), [8.31, 10.99]);
        assert_eq!(v("Prix 12,99 € au lieu de 15,99\u{a0}€"), [12.99, 15.99]);
        assert_eq!(v("$5 and £3.50"), [5.0, 3.5]);
        // a currency sign alone, a sentence, thousands: no price
        assert!(v("EUR € Livraison").is_empty());
        assert!(v("1.299,00 €").is_empty());
        assert!(v("€").is_empty() && v("€.").is_empty() && v(",,€").is_empty());
    }

    #[test]
    fn real_sales_are_not_uniform() {
        // tiers: -33 % and -50 % (armorlux.com, Black Friday)
        let tiers: Vec<(&str, &str, &str)> = [("40,00", "60,00"), ("30,00", "60,00")]
            .iter()
            .cycle()
            .take(10)
            .map(|(a, b)| ("Marinière homme", *a, *b))
            .collect();
        assert!(uniform_discount(&kit_home(&tiers)).is_none());
        // a few products on sale among full prices
        let mut t = String::new();
        for i in 0..20 {
            t.push_str(&format!("Produit numéro {i} au prix normal 19,90 € "));
            if i % 3 == 0 {
                t.push_str("Promo 15,92 € 19,90 € ");
            }
        }
        assert!(uniform_discount(&t).is_none());
    }

    /// Every cut of messy text goes through without panicking.
    #[test]
    fn hostile_text_does_not_panic() {
        let t = "€€1,2.3€ 9999999€ é€é 1,€ ,5€ €12,999 $ £\u{a0}\u{202f}7 €8.31 €10.99";
        for (i, _) in t.char_indices() {
            signals(&t[..i]);
            signals(&t[i..]);
        }
    }
}
