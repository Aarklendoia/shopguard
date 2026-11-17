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
//!   (sales have tiers, and leave products at full price);
//! - **deep discount everywhere**: every product shown at half price or less (−58 to
//!   −81 %), on WooCommerce or Chinese shop platforms (eclairageoutillage.com,
//!   bamboogohaus.com): no real shop, even on Black Friday (its −60 % stand next to
//!   −10 % and −30 %);
//! - **hotlinked catalogue**: the kit is a Next.js site, not a Shopify store, showing the
//!   product photos of the real store it copies straight from that store's Shopify CDN
//!   (`cdn.shopify.com/s/files/1/<store>/…`): 26 of 35 fakes, no real shop (a Shopify
//!   store serves its own photos from `/cdn/shop/` and declares itself);
//! - **German mobile phone only**: German fake shops outside the kit (firewood, tyres,
//!   containers, heating) give a German mobile number as their only phone, even for a
//!   "GmbH": 5 of 12 in November 2026, none of 29 real German shops (they show a
//!   landline or a service number, or no phone at all).

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
/// Two phrases of the kit word for word are close to proof on their own: no real shop
/// shows one. With the hotlinked catalogue of the same kit, one more sign (a young or
/// unarchived domain, a uniform discount) reaches the threshold, even when crt.sh or the
/// Internet Archive did not answer.
const KIT_WEIGHT: i32 = 45;

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
/// Every discount at least this deep: half price or less on everything shown. Real
/// sales, even on Black Friday, leave products at −10 or −30 % next to the −60 %.
const DEEP_MIN: f64 = 0.5;
const DEEP_WEIGHT: i32 = 25;

/// Product photos served by another Shopify store, at least this many…
const HOTLINK_MIN_IMAGES: usize = 5;
const HOTLINK_WEIGHT: i32 = 20;
/// …on a page without any of these (lower case): the page is not a Shopify store.
const SHOPIFY_STORE: &[&str] = &[
    "shopify.theme",
    "shopify.shop",
    "myshopify.com",
    "/cdn/shop/",
    "cdn.shopify.com/shopifycloud",
];
const SHOPIFY_FILES: &str = "cdn.shopify.com/s/files/1/";

/// A sole trader can answer on a mobile phone: a hint, not a proof.
const MOBILE_ONLY_WEIGHT: i32 = 15;
/// Digits of a German number in national form (with its leading 0).
const PHONE_DIGITS: std::ops::RangeInclusive<usize> = 9..=13;

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

/// A price shown, from its first to its last mention: the same price said again for
/// screen readers ("€109,53 Le prix initial était : €109,53", WooCommerce) is one.
struct Shown {
    first: usize,
    last: usize,
    value: f64,
}

fn shown(prices: &[(usize, f64)]) -> Vec<Shown> {
    let mut out: Vec<Shown> = Vec::with_capacity(prices.len());
    for &(at, value) in prices {
        match out.last_mut() {
            Some(s) if s.value == value && at - s.last <= PAIR_GAP => s.last = at,
            _ => out.push(Shown {
                first: at,
                last: at,
                value,
            }),
        }
    }
    out
}

/// Discount of each sale price shown next to its crossed-out price (either order).
fn discounts(prices: &[Shown]) -> Vec<f64> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < prices.len() {
        let (x, y) = (&prices[i], &prices[i + 1]);
        let (p, q) = (x.value, y.value);
        if y.first - x.last <= PAIR_GAP && p != q {
            out.push(1.0 - p.min(q) / p.max(q));
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// Discounts of the page when most products shown are discounted (sorted), and how many
/// prices it shows.
fn sale_everywhere(text: &str) -> Option<(Vec<f64>, usize)> {
    let all = shown(&prices(text));
    let mut d = discounts(&all);
    if d.len() < DISCOUNT_MIN_PAIRS
        || (2 * d.len()) as f64 / (all.len() as f64) < DISCOUNT_MIN_SHARE
    {
        return None;
    }
    d.sort_by(f64::total_cmp);
    Some((d, all.len()))
}

/// Every product shown at half price or less: detail of the signal, if so.
pub fn deep_discount(text: &str) -> Option<String> {
    let (d, all) = sale_everywhere(text)?;
    let pct = |x: f64| (x * 100.0).round() as u32;
    (d[0] >= DEEP_MIN).then(|| {
        format!(
            "{} of {} products shown are discounted, all by {}–{} % (median {} %)",
            d.len(),
            all - d.len(),
            pct(d[0]),
            pct(d[d.len() - 1]),
            pct(d[d.len() / 2])
        )
    })
}

/// Every product marked down by about the same ratio: detail of the signal, if so.
pub fn uniform_discount(text: &str) -> Option<String> {
    let (d, all) = sale_everywhere(text)?;
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
        all - d.len(),
        near.len(),
        pct(near[0]),
        pct(near[near.len() - 1]),
        pct(median)
    ))
}

/// Shopify store whose product photos `html` shows without being a Shopify store
/// itself: its file id (`0918/0712/1748`) and how many photos, if so.
pub fn hotlinked_store(html: &str) -> Option<(String, usize)> {
    let h = html.to_ascii_lowercase();
    if SHOPIFY_STORE.iter().any(|m| h.contains(m)) {
        return None;
    }
    let mut stores: Vec<(String, usize)> = Vec::new();
    for (i, _) in h.match_indices(SHOPIFY_FILES) {
        let rest = &h[i + SHOPIFY_FILES.len()..];
        // `NNNN/NNNN/NNNN/` then `files/` or `products/`
        let Some(id) = rest.get(..14).filter(|id| {
            id.bytes().enumerate().all(|(j, b)| {
                if j == 4 || j == 9 {
                    b == b'/'
                } else {
                    b.is_ascii_digit()
                }
            })
        }) else {
            continue;
        };
        let after = &rest[14..];
        if !(after.starts_with("/files/") || after.starts_with("/products/")) {
            continue;
        }
        match stores.iter_mut().find(|(s, _)| s == id) {
            Some((_, n)) => *n += 1,
            None => stores.push((id.to_owned(), 1)),
        }
    }
    stores
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .filter(|(_, n)| *n >= HOTLINK_MIN_IMAGES)
}

/// A German phone number read in the text.
#[derive(Debug, PartialEq)]
struct Phone {
    shown: String,
    /// National form, leading 0 included.
    national: String,
    /// Written with +49 or 0049.
    international: bool,
}

fn phone_char(c: char) -> bool {
    c.is_ascii_digit() || "+()/-.".contains(c)
}

/// German phone numbers of the text: `+49 …`, `0049 …`, or `0…` written in groups
/// (`02801 3713`, `030/123456`).
fn german_phones(text: &str) -> Vec<Phone> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        let international = w.starts_with("+49") || w.starts_with("0049");
        let national = !international
            && (w.starts_with('0') || w.starts_with("(0"))
            && !w.starts_with("00")
            && !w.starts_with("(00");
        if !(international || national) || !w.chars().all(phone_char) {
            i += 1;
            continue;
        }
        let mut parts = vec![w];
        let mut digits: String = w.chars().filter(char::is_ascii_digit).collect();
        let mut j = i + 1;
        while let Some(next) = words.get(j) {
            let d: String = next.chars().filter(char::is_ascii_digit).collect();
            if d.is_empty() || !next.chars().all(phone_char) || digits.len() + d.len() > 16 {
                break;
            }
            digits.push_str(&d);
            parts.push(next);
            j += 1;
        }
        let rest = if international {
            let r = digits.strip_prefix("0049").or(digits.strip_prefix("49"));
            r.map(|r| r.strip_prefix('0').unwrap_or(r))
        } else {
            Some(digits.as_str())
        };
        let shown = parts.join(" ");
        // "0123456789" in one piece is more likely a reference than a phone number
        let grouped = parts.len() > 1 || w.contains(['/', '-', '(']);
        if let Some(rest) = rest {
            let nat = if international {
                format!("0{rest}")
            } else {
                rest.to_owned()
            };
            if PHONE_DIGITS.contains(&nat.len()) && (international || grouped) {
                out.push(Phone {
                    shown,
                    national: nat,
                    international,
                });
            }
        }
        i = j;
    }
    out
}

/// The only German phone numbers of the text are mobile numbers: the first one. Mobile
/// numbers count only written +49 (in national form a mobile prefix can be a reference),
/// any other German number (landline, 0800, 0180…) cancels the signal.
pub fn mobile_only(text: &str) -> Option<String> {
    let phones = german_phones(text);
    let mobile = |p: &Phone| {
        ["015", "016", "017"]
            .iter()
            .any(|m| p.national.starts_with(m))
    };
    if phones.iter().any(|p| !mobile(p)) {
        return None;
    }
    phones
        .into_iter()
        .find(|p| p.international && mobile(p))
        .map(|p| p.shown)
}

fn signal(name: &str, weight: i32, detail: String) -> Signal {
    Signal {
        source: SOURCE.into(),
        name: name.into(),
        weight,
        detail,
    }
}

/// Signals for the home page of a shop: its HTML and visible text.
pub fn signals(html: &str, text: &str) -> Vec<Signal> {
    let mut out = Vec::new();
    if let Some((store, n)) = hotlinked_store(html) {
        out.push(signal(
            "catalog_hotlinked",
            HOTLINK_WEIGHT,
            format!(
                "{n} product photos served by another Shopify store (files {store}): \
                 a catalogue copied from that shop"
            ),
        ));
    }
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
    // a deep discount on everything says more than a uniform one: not both
    if let Some(d) = deep_discount(text) {
        out.push(signal("discount_deep", DEEP_WEIGHT, d));
    } else if let Some(d) = uniform_discount(text) {
        out.push(signal("discount_uniform", DISCOUNT_WEIGHT, d));
    }
    if let Some(p) = mobile_only(text) {
        out.push(signal(
            "phone_mobile_only",
            MOBILE_ONLY_WEIGHT,
            format!("the only phone number on the home page, {p}, is a German mobile number"),
        ));
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
            signals(&home.html, &html::text(&home.html))
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
        let s = signals("", &t);
        assert_eq!(s[0].name, "shop_kit");
        assert_eq!(s[0].weight, KIT_WEIGHT);
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
        assert!(signals("", "Black Friday: limited time offer on everything").is_empty());
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

    fn photos(store: &str, n: usize) -> String {
        (0..n)
            .map(|i| {
                format!(
                    r#"<img src="https://cdn.shopify.com/s/files/1/{store}/files/p{i}.jpg?v=1&width=400">"#
                )
            })
            .collect()
    }

    #[test]
    fn hotlinked_catalogue() {
        // the Next.js fake showing the photos of the store it copies
        let fake = format!("<html><body>{}</body></html>", photos("0918/0712/1748", 48));
        assert_eq!(hotlinked_store(&fake), Some(("0918/0712/1748".into(), 48)));
        let s = signals(&fake, "");
        assert_eq!(s[0].name, "catalog_hotlinked");
        assert_eq!(s[0].weight, 20);
        assert_eq!(
            s[0].detail,
            "48 product photos served by another Shopify store (files 0918/0712/1748): \
             a catalogue copied from that shop"
        );
        // a Shopify store showing its own photos from the CDN
        let store = format!(
            r#"<script>Shopify.shop = "b02701-d1.myshopify.com";</script>{}"#,
            photos("0657/1234/5678", 30)
        );
        assert_eq!(hotlinked_store(&store), None);
        // a few photos (a partner's logo, a blog post): not a catalogue
        assert_eq!(hotlinked_store(&photos("0918/0712/1748", 4)), None);
        // not a store's file path
        assert_eq!(
            hotlinked_store(&"cdn.shopify.com/s/files/1/abcd/0712/1748/files/x ".repeat(9)),
            None
        );
    }

    /// Every cut of messy text goes through without panicking.
    #[test]
    fn hostile_text_does_not_panic() {
        let t = "€€1,2.3€ 9999999€ é€é 1,€ ,5€ €12,999 $ £\u{a0}\u{202f}7 €8.31 €10.99";
        let h = format!("{t}{}é", photos("0918/0712/1748", 6));
        for (i, _) in h.char_indices() {
            hotlinked_store(&h[..i]);
            hotlinked_store(&h[i..]);
        }
        for (i, _) in t.char_indices() {
            signals(&t[..i], &t[..i]);
            signals(&t[i..], &t[i..]);
        }
    }

    #[test]
    fn german_mobile_only() {
        // reifenivo.de, derboben-holzimport.de
        let t = "Mobile Montage 0 € bis 30.11.2026 Beratung: +49 163 6574783 Modell suchen";
        assert_eq!(mobile_only(t).as_deref(), Some("+49 163 6574783"));
        let t = "Geöffnet von Montag bis Samstag +49 1523 6935280 Kontakt";
        assert_eq!(mobile_only(t).as_deref(), Some("+49 1523 6935280"));
        assert_eq!(
            mobile_only("Tel. 0049 (0)152 93436230").as_deref(),
            Some("0049 (0)152 93436230")
        );
        // a landline or a service number besides it
        assert!(mobile_only("Hotline +49 (0) 40 22 63 59 0 oder +49 163 6574783").is_none());
        assert!(mobile_only("+49 163 6574783 · Telefon 02801 3713").is_none());
        assert!(mobile_only("0800 5435 111 · +49 151 12345678").is_none());
        // national form only: not counted
        assert!(mobile_only("Tel. 0163 6574783").is_none());
        // no phone, prices and references
        assert!(mobile_only("Art.-Nr. 0157123456 für 0,00 € bis 30.11.2026").is_none());
        assert!(mobile_only("").is_none());
    }

    #[test]
    fn phones_read() {
        let p = german_phones("Tel.: 030/123456 Fax +49 (0)30 1234-57");
        assert_eq!(
            p,
            [
                Phone {
                    shown: "030/123456".into(),
                    national: "030123456".into(),
                    international: false
                },
                Phone {
                    shown: "+49 (0)30 1234-57".into(),
                    national: "030123457".into(),
                    international: true
                }
            ]
        );
    }

    /// Products of a WooCommerce page: crossed-out price, sale price, each said again
    /// for screen readers.
    fn woocommerce(products: &[(&str, &str, &str)]) -> String {
        let mut h = String::from("<html lang=\"fr-FR\"><body><ul>");
        for (name, before, after) in products {
            h.push_str(&format!(
                "<li><span class=\"onsale\">- 70 %</span><h2>{name}</h2><del>&euro;&nbsp;{before}\
                 <span class=\"screen-reader-text\">Le prix initial était : &euro;{before}.</span></del>\
                 <ins>&euro;&nbsp;{after}<span class=\"screen-reader-text\">Le prix actuel est : \
                 &euro;{after}.</span></ins><a>Show more</a></li>"
            ));
        }
        h.push_str("</ul></body></html>");
        crate::html::text(&h)
    }

    #[test]
    fn deep_discount_everywhere() {
        // eclairageoutillage.com: everything at −60 to −80 %
        let t = woocommerce(&[
            ("M0000", "109,53", "27,38"),
            ("LED Strip 5Mt", "7,15", "2,86"),
            ("Pomme de douche", "344,54", "68,91"),
            ("DC Distribution", "79,00", "23,70"),
            ("Pool Gom", "8,65", "3,46"),
            ("Water Lily", "12,80", "5,12"),
            ("Cordon RJ45 0,5 m", "2,70", "1,08"),
            ("Ruban LED RGB", "55,99", "16,80"),
        ]);
        assert_eq!(
            deep_discount(&t).as_deref(),
            Some("8 of 8 products shown are discounted, all by 60–80 % (median 70 %)")
        );
        let s = signals("", &t);
        assert_eq!(
            s.iter()
                .map(|s| (s.name.as_str(), s.weight))
                .collect::<Vec<_>>(),
            [("discount_deep", 25)]
        );
        // Black Friday on a real shop: up to −60 %, but −20 % and −35 % next to it
        let t = woocommerce(&[
            ("Montre A", "200,00", "80,00"),
            ("Montre B", "150,00", "60,00"),
            ("Montre C", "100,00", "80,00"),
            ("Montre D", "90,00", "36,00"),
            ("Montre E", "120,00", "78,00"),
            ("Montre F", "300,00", "120,00"),
            ("Montre G", "80,00", "32,00"),
            ("Montre H", "60,00", "24,00"),
        ]);
        assert!(deep_discount(&t).is_none());
    }
}
