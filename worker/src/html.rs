//! Minimal reading of hostile HTML: visible text and links.
//!
//! No parser, no DOM, nothing executed: a linear scan that tolerates any markup, cannot
//! loop and works in O(n). Good enough to find a legal notice link or a SIRET in a page
//! footer; the analyzers only ever read text.

use reqwest::Url;

/// Text of `html`: tags removed (with the content of `script`, `style`, `noscript`,
/// `template` and `svg`), common entities decoded, whitespace collapsed.
pub fn text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 4);
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    while let Some(off) = html[i..].find('<') {
        out.push_str(&html[i..i + off]);
        out.push(' ');
        let start = i + off;
        let Some(end) = html[start..].find('>').map(|e| start + e + 1) else {
            i = html.len();
            break;
        };
        i = end;
        // skip the content of the elements whose text is not shown
        let tag: String = lower[start + 1..end]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if matches!(
            tag.as_str(),
            "script" | "style" | "noscript" | "template" | "svg"
        ) {
            let close = format!("</{tag}");
            i = lower[end..].find(&close).map_or(html.len(), |c| end + c);
        }
    }
    if i < html.len() {
        out.push_str(&html[i..]);
    }
    collapse(&decode(&out))
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The few entities that matter for text and URLs; numeric ones too.
pub fn decode(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let end = rest.bytes().take(12).position(|b| b == b';');
        let decoded = end.and_then(|e| {
            let name = &rest[1..e];
            let c = match name {
                "amp" => Some('&'),
                "nbsp" => Some('\u{a0}'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "eacute" => Some('é'),
                "egrave" => Some('è'),
                "agrave" => Some('à'),
                "ccedil" => Some('ç'),
                _ => name
                    .strip_prefix("#x")
                    .or_else(|| name.strip_prefix("#X"))
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| name.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            };
            c.map(|c| (c, e + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Value of attribute `name` in the inside of a tag (`a href="…" class=x`).
fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(p) = lower[from..].find(name) {
        let at = from + p;
        from = at + name.len();
        // a whole attribute name: preceded by whitespace, followed by `=`
        if !lower[..at].ends_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let rest = lower[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let value_at = tag.len() - rest.trim_start().len();
        let v = &tag[value_at..];
        let value = match v.chars().next() {
            Some(q @ ('"' | '\'')) => v[1..].split(q).next().unwrap_or(""),
            _ => v
                .split(|c: char| c.is_ascii_whitespace() || c == '>')
                .next()
                .unwrap_or(""),
        };
        return Some(decode(value.trim()));
    }
    None
}

/// `lang` of the `<html>` element, lower case.
pub fn lang(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<html")?;
    let end = start + lower[start..].find('>')?;
    attribute(&html[start + 5..end], "lang").map(|l| l.to_ascii_lowercase())
}

/// A link of a page: absolute address and visible text.
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub url: Url,
    pub text: String,
}

/// The `<a href>` links of `html`, resolved against `base`; at most `max`.
pub fn links(html: &str, base: &Url, max: usize) -> Vec<Link> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < max
        && let Some(p) = lower[i..].find("<a")
    {
        let start = i + p;
        i = start + 2;
        if !lower[i..].starts_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let Some(end) = lower[i..].find('>').map(|e| i + e) else {
            break;
        };
        let href = attribute(&html[i..end], "href");
        i = end + 1;
        let close = lower[i..].find("</a").map_or(html.len(), |c| i + c);
        let text = self::text(&html[i..close.min(i + 2000)]);
        if let Some(url) = href.and_then(|h| base.join(&h).ok())
            && matches!(url.scheme(), "https" | "http")
        {
            out.push(Link { url, text });
        }
    }
    out
}

/// Lower case without the accents of French, to compare words.
pub fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' | 'À' | 'Â' => 'a',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' => 'e',
            'î' | 'ï' | 'Î' => 'i',
            'ô' | 'ö' | 'Ô' => 'o',
            'ù' | 'û' | 'ü' | 'Û' => 'u',
            'ç' | 'Ç' => 'c',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_text() {
        let h = r#"<html><head><style>p{color:red}</style><script>var siret="1";</script></head>
            <body><p>SIRET&nbsp;:&#160;732 829 320 00074</p><SCRIPT type="x">no</SCRIPT>
            <p>R&eacute;sum&#xE9; &amp; fin</p><p>unclosed <b"#;
        let t = text(h);
        assert_eq!(t, "SIRET : 732 829 320 00074 Résumé & fin unclosed");
        assert_eq!(text("a<script>never closed"), "a");
        assert_eq!(decode("&bogus; &#xZZ; &"), "&bogus; &#xZZ; &");
    }

    #[test]
    fn links_and_lang() {
        let base = Url::parse("https://shop.fr/fr/").unwrap();
        let h = r#"<html lang="FR-fr"><a class=x href="/pages/mentions-legales">Mentions <b>légales</b></a>
            <a href='cgv?x=1&amp;y=2'>CGV</a><a href=https://other.com/a>ext</a>
            <abbr>no</abbr><a name="top">anchor</a><a href="javascript:alert(1)">js</a>
            <a data-href="/no" HREF="/yes">ok</a>"#;
        let l = links(h, &base, 10);
        let got: Vec<(&str, &str)> = l
            .iter()
            .map(|l| (l.url.as_str(), l.text.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("https://shop.fr/pages/mentions-legales", "Mentions légales"),
                ("https://shop.fr/fr/cgv?x=1&y=2", "CGV"),
                ("https://other.com/a", "ext"),
                ("https://shop.fr/yes", "ok"),
            ]
        );
        assert_eq!(links(h, &base, 1).len(), 1);
        assert_eq!(lang(h).as_deref(), Some("fr-fr"));
        assert_eq!(lang("<html><body>"), None);
        assert_eq!(fold("Mentions LÉGALES à Évry"), "mentions legales a evry");
    }
}
