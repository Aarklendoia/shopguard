//! `shopguard-worker measure`: scores of the measurement corpus, as Markdown tables for
//! pull requests.
//!
//! The corpus (`worker/corpus/fake.txt`, `legit.txt`) lists known fake and real shops.
//! Verdicts come from `check --json` (network access, run once per version), so that a
//! scoring change is compared on the same answers:
//!
//! ```sh
//! cat corpus/*.txt | shopguard-worker check --json --jobs 16 > before.jsonl  # on main
//! cat corpus/*.txt | shopguard-worker check --json --jobs 16 > after.jsonl   # branch
//! shopguard-worker measure corpus before.jsonl after.jsonl
//! ```

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::ExitCode;

use crate::analysis::Verdict;

const USAGE: &str = "\
usage: shopguard-worker measure [--threshold N] CORPUS_DIR VERDICTS [AFTER]

Compares verdicts (one JSON verdict per line, as printed by `check --json`) with
the corpus (CORPUS_DIR/fake.txt and CORPUS_DIR/legit.txt) and prints Markdown
tables: fakes and real shops above the threshold, means, false positives, misses.
With AFTER: before/after columns and every domain whose score changed.

  --threshold N   blocking threshold (default 70)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Fake,
    Legit,
}

/// Domains of a corpus file: one per line, `#` starts a comment.
pub fn parse_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let d = l
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            (!d.is_empty()).then_some(d)
        })
        .collect()
}

pub fn read_corpus(dir: &Path) -> Result<BTreeMap<String, Kind>, String> {
    let mut out = BTreeMap::new();
    for (file, kind) in [("fake.txt", Kind::Fake), ("legit.txt", Kind::Legit)] {
        let p = dir.join(file);
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        for d in parse_list(&text) {
            if let Some(k) = out.insert(d.clone(), kind)
                && k != kind
            {
                return Err(format!("{d} is both fake and legit"));
            }
        }
    }
    Ok(out)
}

/// Verdicts of a `check --json` output, by domain (the last one wins).
pub fn parse_verdicts(text: &str) -> Result<HashMap<String, Verdict>, String> {
    let mut out = HashMap::new();
    for (i, l) in text.lines().enumerate() {
        if l.trim().is_empty() {
            continue;
        }
        let v: Verdict = serde_json::from_str(l).map_err(|e| format!("line {}: {e}", i + 1))?;
        out.insert(v.domain.clone(), v);
    }
    Ok(out)
}

fn read_verdicts(path: &str) -> Result<HashMap<String, Verdict>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    parse_verdicts(&text).map_err(|e| format!("{path}: {e}"))
}

#[derive(Debug, Default, PartialEq)]
pub struct Stats {
    pub listed: usize,
    pub analyzed: usize,
    /// The site answered with a page (`page_*` signal): fakes die fast.
    pub alive: usize,
    pub blocked: usize,
    pub over_50: usize,
    pub at_0: usize,
    pub mean: u32,
    pub max: u8,
}

fn alive(v: &Verdict) -> bool {
    v.signals.iter().any(|s| s.source == "page")
}

pub fn stats(
    corpus: &BTreeMap<String, Kind>,
    verdicts: &HashMap<String, Verdict>,
    kind: Kind,
    threshold: u8,
) -> Stats {
    let mut s = Stats::default();
    let mut sum = 0u32;
    for (d, k) in corpus {
        if *k != kind {
            continue;
        }
        s.listed += 1;
        let Some(v) = verdicts.get(d) else { continue };
        s.analyzed += 1;
        s.alive += usize::from(alive(v));
        s.blocked += usize::from(v.score >= threshold);
        s.over_50 += usize::from(v.score >= 50);
        s.at_0 += usize::from(v.score == 0);
        s.max = s.max.max(v.score);
        sum += u32::from(v.score);
    }
    if s.analyzed > 0 {
        s.mean = (f64::from(sum) / s.analyzed as f64).round() as u32;
    }
    s
}

/// Names of the signals that raise the score.
fn raising(v: &Verdict) -> String {
    let mut names: Vec<String> = v
        .signals
        .iter()
        .filter(|s| s.weight > 0)
        .map(|s| format!("{} +{}", s.name, s.weight))
        .collect();
    if names.is_empty() {
        names.push("—".into());
    }
    names.join(", ")
}

fn cell(before: impl ToString, after: Option<impl ToString>) -> String {
    match after {
        None => before.to_string(),
        Some(a) => {
            let (b, a) = (before.to_string(), a.to_string());
            if a == b {
                b
            } else {
                format!("{b} → **{a}**")
            }
        }
    }
}

pub fn report(
    corpus: &BTreeMap<String, Kind>,
    before: &HashMap<String, Verdict>,
    after: Option<&HashMap<String, Verdict>>,
    threshold: u8,
) -> String {
    let fb = stats(corpus, before, Kind::Fake, threshold);
    let lb = stats(corpus, before, Kind::Legit, threshold);
    let fa = after.map(|a| stats(corpus, a, Kind::Fake, threshold));
    let la = after.map(|a| stats(corpus, a, Kind::Legit, threshold));
    let mut out = String::new();
    out.push_str("| | fakes | real shops |\n|---|---:|---:|\n");
    let row = |out: &mut String, label: &str, f: &dyn Fn(&Stats) -> String| {
        out.push_str(&format!(
            "| {label} | {} | {} |\n",
            cell(f(&fb), fa.as_ref().map(f)),
            cell(f(&lb), la.as_ref().map(f)),
        ));
    };
    row(&mut out, "analyzed", &|s| {
        format!("{} / {}", s.analyzed, s.listed)
    });
    row(&mut out, "site answering", &|s| s.alive.to_string());
    row(&mut out, &format!("**≥ {threshold}** (blocked)"), &|s| {
        s.blocked.to_string()
    });
    row(&mut out, "≥ 50", &|s| s.over_50.to_string());
    row(&mut out, "at 0", &|s| s.at_0.to_string());
    row(&mut out, "mean score", &|s| s.mean.to_string());
    row(&mut out, "max score", &|s| s.max.to_string());

    let last = after.unwrap_or(before);
    let real_scored: Vec<&Verdict> = corpus
        .iter()
        .filter(|(_, k)| **k == Kind::Legit)
        .filter_map(|(d, _)| last.get(d))
        .filter(|v| v.score > 0)
        .collect();
    out.push_str(&format!(
        "\n**Real shops above 0**: {}\n",
        real_scored.len()
    ));
    if !real_scored.is_empty() {
        out.push_str("\n| domain | score | raised by |\n|---|---:|---|\n");
        for v in real_scored {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                v.domain,
                v.score,
                raising(v)
            ));
        }
    }
    let missed: Vec<&Verdict> = corpus
        .iter()
        .filter(|(_, k)| **k == Kind::Fake)
        .filter_map(|(d, _)| last.get(d))
        .filter(|v| alive(v) && v.score < threshold)
        .collect();
    out.push_str(&format!(
        "\n**Answering fakes under {threshold}**: {}\n",
        missed.len()
    ));
    if !missed.is_empty() {
        out.push_str("\n| domain | score | raised by |\n|---|---:|---|\n");
        for v in missed {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                v.domain,
                v.score,
                raising(v)
            ));
        }
    }

    if let Some(after) = after {
        let mut changed = Vec::new();
        for (d, k) in corpus {
            if let (Some(b), Some(a)) = (before.get(d), after.get(d))
                && a.score != b.score
            {
                changed.push((k, b, a));
            }
        }
        out.push_str(&format!("\n**Scores changed**: {}\n", changed.len()));
        if !changed.is_empty() {
            out.push_str(
                "\n| domain | | before | after | raised by (after) |\n|---|---|---:|---:|---|\n",
            );
            for (k, b, a) in changed {
                let kind = if *k == Kind::Fake { "fake" } else { "real" };
                out.push_str(&format!(
                    "| {} | {kind} | {} | {} | {} |\n",
                    a.domain,
                    b.score,
                    a.score,
                    raising(a)
                ));
            }
        }
    }
    out
}

pub fn measure(args: &[String]) -> ExitCode {
    let mut threshold = 70u8;
    let mut pos = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--threshold" => match it.next().and_then(|t| t.parse().ok()).filter(|t| *t <= 100) {
                Some(t) => threshold = t,
                None => {
                    eprintln!("--threshold: expected 0 to 100\n\n{USAGE}");
                    return ExitCode::from(2);
                }
            },
            s if s.starts_with('-') => {
                eprintln!("unknown option {s}\n\n{USAGE}");
                return ExitCode::from(2);
            }
            s => pos.push(s.to_owned()),
        }
    }
    if !(2..=3).contains(&pos.len()) {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let run = || -> Result<String, String> {
        let corpus = read_corpus(Path::new(&pos[0]))?;
        let before = read_verdicts(&pos[1])?;
        let after = pos.get(2).map(|p| read_verdicts(p)).transpose()?;
        Ok(report(&corpus, &before, after.as_ref(), threshold))
    };
    match run() {
        Ok(r) => {
            print!("{r}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Signal;

    fn v(domain: &str, score: u8, signals: &[(&str, &str, i32)]) -> Verdict {
        Verdict {
            domain: domain.into(),
            score,
            signals: signals
                .iter()
                .map(|(source, name, weight)| Signal {
                    source: (*source).into(),
                    name: (*name).into(),
                    weight: *weight,
                    detail: String::new(),
                })
                .collect(),
            checked_at: 0,
        }
    }

    fn corpus() -> BTreeMap<String, Kind> {
        [
            ("fake1.shop", Kind::Fake),
            ("fake2.shop", Kind::Fake),
            ("dead.shop", Kind::Fake),
            ("real.fr", Kind::Legit),
        ]
        .into_iter()
        .map(|(d, k)| (d.to_owned(), k))
        .collect()
    }

    fn verdicts(list: Vec<Verdict>) -> HashMap<String, Verdict> {
        list.into_iter().map(|v| (v.domain.clone(), v)).collect()
    }

    #[test]
    fn corpus_files() {
        assert_eq!(
            parse_list("# header\n\nShop.fr  # 2026-11-17 hagezi\n  other.de\n#x.com\n"),
            ["shop.fr", "other.de"]
        );
        let dir = std::env::temp_dir().join(format!("shopguard-corpus-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("fake.txt"), "a.shop\nboth.fr\n").unwrap();
        std::fs::write(dir.join("legit.txt"), "b.fr\n").unwrap();
        assert_eq!(read_corpus(&dir).unwrap().len(), 3);
        std::fs::write(dir.join("legit.txt"), "b.fr\nboth.fr\n").unwrap();
        assert!(read_corpus(&dir).unwrap_err().contains("both.fr"));
        std::fs::remove_dir_all(&dir).unwrap();
        // the repository's corpus is well formed
        let repo = read_corpus(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus"))).unwrap();
        assert!(repo.values().filter(|k| **k == Kind::Fake).count() >= 100);
        assert!(repo.values().filter(|k| **k == Kind::Legit).count() >= 40);
        assert!(
            repo.keys()
                .all(|d| crate::domain::registrable(d).as_deref() == Some(d))
        );
    }

    #[test]
    fn verdict_lines() {
        let line = serde_json::to_string(&v("a.fr", 5, &[])).unwrap();
        let got = parse_verdicts(&format!("{line}\n\n{line}\n")).unwrap();
        assert_eq!(got.len(), 1);
        assert!(
            parse_verdicts("{not json")
                .unwrap_err()
                .starts_with("line 1")
        );
    }

    #[test]
    fn statistics_and_report() {
        let page = ("page", "page_shop", 0);
        let before = verdicts(vec![
            v("fake1.shop", 90, &[page, ("shop", "shop_kit", 45)]),
            v("fake2.shop", 40, &[page, ("rdap", "domain_age_days", 40)]),
            v("dead.shop", 0, &[]),
            v("real.fr", 0, &[page]),
        ]);
        let s = stats(&corpus(), &before, Kind::Fake, 70);
        assert_eq!(
            s,
            Stats {
                listed: 3,
                analyzed: 3,
                alive: 2,
                blocked: 1,
                over_50: 1,
                at_0: 1,
                mean: 43,
                max: 90,
            }
        );
        let one = report(&corpus(), &before, None, 70);
        assert!(one.contains("| **≥ 70** (blocked) | 1 | 0 |"), "{one}");
        assert!(one.contains("**Real shops above 0**: 0"));
        // the dead fake is not a miss
        assert!(one.contains("**Answering fakes under 70**: 1"));
        assert!(one.contains("| fake2.shop | 40 | domain_age_days +40 |"));

        let mut after = before.clone();
        after.insert(
            "fake2.shop".into(),
            v(
                "fake2.shop",
                70,
                &[page, ("rdap", "domain_age_days", 40), ("shop", "x", 30)],
            ),
        );
        after.insert(
            "real.fr".into(),
            v("real.fr", 15, &[page, ("legal", "legal_id_missing", 15)]),
        );
        let two = report(&corpus(), &before, Some(&after), 70);
        assert!(
            two.contains("| **≥ 70** (blocked) | 1 → **2** | 0 |"),
            "{two}"
        );
        assert!(two.contains("| real.fr | 15 | legal_id_missing +15 |"));
        assert!(two.contains("**Scores changed**: 2"));
        assert!(two.contains("| fake2.shop | fake | 40 | 70 |"));
    }
}
