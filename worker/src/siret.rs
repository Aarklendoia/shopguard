//! French company identifiers.
//!
//! A SIREN (9 digits) identifies a company, a SIRET (SIREN + 5 digits) one of its
//! establishments. Both carry a Luhn check digit, except SIRETs of La Poste
//! (SIREN 356 000 000), whose digits must add up to a multiple of 5. French online shops
//! must publish theirs in their legal notice: a missing or invalid number is one of the
//! strongest signals of a fake shop. Whether the company exists and is active is checked
//! against the public company directory API, elsewhere.

const LA_POSTE: &str = "356000000";

fn luhn(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            let d = u32::from(d);
            if i % 2 == 1 {
                if d * 2 > 9 { d * 2 - 9 } else { d * 2 }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Digits of `s` when it is exactly `len` digits once spaces, dots and dashes are removed.
fn digits(s: &str, len: usize) -> Option<Vec<u8>> {
    let d: Vec<u8> = s
        .chars()
        .filter(|c| !matches!(c, ' ' | '\u{a0}' | '\u{202f}' | '.' | '-'))
        .map(|c| c.to_digit(10).map(|d| d as u8))
        .collect::<Option<_>>()?;
    (d.len() == len).then_some(d)
}

/// Valid SIREN, as 9 digits.
pub fn siren(s: &str) -> Option<String> {
    let d = digits(s, 9)?;
    luhn(&d).then(|| d.iter().map(|d| char::from(b'0' + d)).collect())
}

/// Valid SIRET, as 14 digits.
pub fn siret(s: &str) -> Option<String> {
    let d = digits(s, 14)?;
    let text: String = d.iter().map(|d| char::from(b'0' + d)).collect();
    let ok = if text.starts_with(LA_POSTE) && text != "35600000000048" {
        d.iter().map(|&d| u32::from(d)).sum::<u32>() % 5 == 0
    } else {
        luhn(&d)
    };
    // an establishment of a company with an invalid SIREN cannot exist
    (ok && siren(&text[..9]).is_some()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::{siren, siret};

    #[test]
    fn valid_numbers() {
        assert_eq!(siren("732 829 320"), Some("732829320".into()));
        assert_eq!(siret("732 829 320 00074"), Some("73282932000074".into()));
        assert_eq!(siret("552.100.554-00005"), Some("55210055400005".into()));
        // La Poste: sum of the digits multiple of 5, not Luhn
        assert_eq!(siret("35600000049837"), Some("35600000049837".into()));
    }

    #[test]
    fn invalid_numbers() {
        for s in [
            "732829321",
            "73282932000075",
            "1234",
            "7328293200007a",
            "732 829 320 0007 4 1",
        ] {
            assert_eq!(siret(s).or(siren(s)), None, "{s}");
        }
    }
}
