//! `shopguard-worker check`: analyzes domains once and prints their verdicts, without
//! the service, the store or the token. For trying the analyzers on known shops, real
//! or fake, before they reach a network.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::sync::Arc;

use crate::analysis::{self, Verdict};

const DEFAULT_JOBS: usize = 8;
const MAX_JOBS: usize = 32;

const USAGE: &str = "\
usage: shopguard-worker check [--json] [--jobs N] [DOMAIN|URL]...

Analyzes each domain (or the domain of each URL) once and prints its verdict.
Without arguments, reads one domain or URL per line from standard input
(empty lines skipped; # starts a comment, as in worker/corpus/*.txt).

  --json     one verdict per line, as returned by GET /v1/verdicts/{domain}
  --jobs N   domains analyzed at the same time (default 8, 1 to 32); the
             verdicts are printed in the order of the input

Logs go to standard error (SHOPGUARD_LOG, default warn).
Exit status: 0; 1 when an argument is not a domain; 2 on a usage error.";

pub async fn check(args: &[String]) -> ExitCode {
    let mut json = false;
    let mut jobs = DEFAULT_JOBS;
    let mut inputs = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--jobs" => match it
                .next()
                .and_then(|n| n.parse().ok())
                .filter(|n| (1..=MAX_JOBS).contains(n))
            {
                Some(n) => jobs = n,
                None => {
                    eprintln!("--jobs: expected 1 to {MAX_JOBS}\n\n{USAGE}");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            s if s.starts_with('-') => {
                eprintln!("unknown option {s}\n\n{USAGE}");
                return ExitCode::from(2);
            }
            s => inputs.push(s.to_owned()),
        }
    }
    if inputs.is_empty() {
        inputs = std::io::stdin()
            .lock()
            .lines()
            .map_while(Result::ok)
            // `domain  # comment`, as in the measurement corpus
            .map(|l| l.split('#').next().unwrap_or("").trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
    }

    let mut ok = true;
    let mut domains: Vec<String> = Vec::new();
    for i in &inputs {
        match domain_of(i) {
            Some(d) if !domains.contains(&d) => domains.push(d),
            Some(_) => {}
            None => {
                eprintln!("not a domain: {i}");
                ok = false;
            }
        }
    }

    let user_agent = match crate::config::user_agent_from_env() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let analyzers = Arc::new(analysis::analyzers(
        crate::http::client(),
        user_agent.as_deref(),
    ));
    // `jobs` analyses at a time (dead fake shops spend most of it in timeouts), printed
    // in the input order as soon as the earlier ones are done
    let mut tasks = tokio::task::JoinSet::new();
    let mut queue = domains.into_iter().enumerate();
    let mut done: BTreeMap<usize, Verdict> = BTreeMap::new();
    let mut next = 0;
    let mut out = std::io::stdout().lock();
    'outer: loop {
        while tasks.len() < jobs
            && let Some((i, d)) = queue.next()
        {
            let analyzers = analyzers.clone();
            tasks.spawn(async move { (i, analysis::verdict(&analyzers, d).await) });
        }
        let Some(res) = tasks.join_next().await else {
            break;
        };
        match res {
            Ok((i, v)) => {
                done.insert(i, v);
            }
            // a verdict cannot panic (analyzers are isolated); a cancelled task
            Err(e) => {
                eprintln!("analysis failed: {e}");
                ok = false;
                // its index is unknown: the later verdicts are printed at the end
                continue;
            }
        }
        while let Some(v) = done.remove(&next) {
            next += 1;
            let text = if json {
                serde_json::to_string(&v).unwrap_or_default()
            } else {
                render(&v)
            };
            // stdout closed (`| head`): nothing left to do
            if writeln!(out, "{text}").and_then(|()| out.flush()).is_err() {
                break 'outer;
            }
        }
    }
    for v in done.into_values() {
        let text = if json {
            serde_json::to_string(&v).unwrap_or_default()
        } else {
            render(&v)
        };
        if writeln!(out, "{text}").is_err() {
            break;
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Registrable domain of a domain name or URL: `https://www.shop.fr:443/p?x` → `shop.fr`.
fn domain_of(input: &str) -> Option<String> {
    let s = input.trim();
    let s = s.split_once("://").map_or(s, |(_, rest)| rest);
    let host = s.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    crate::domain::registrable(host)
}

/// Human-readable verdict: score, then every signal with its weight.
fn render(v: &Verdict) -> String {
    let mut s = format!("{}  score {}\n", v.domain, v.score);
    let name_w = v.signals.iter().map(|g| g.name.len()).max().unwrap_or(0);
    for g in &v.signals {
        s.push_str(&format!(
            "  {:>+4}  {:<8} {:<name_w$}  {}\n",
            g.weight, g.source, g.name, g.detail
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Signal;

    #[test]
    fn domains_and_urls() {
        assert_eq!(domain_of("shop.fr").as_deref(), Some("shop.fr"));
        assert_eq!(domain_of("WWW.Shop.fr.").as_deref(), Some("shop.fr"));
        assert_eq!(
            domain_of("https://www.shop.fr:443/produit?id=1#avis").as_deref(),
            Some("shop.fr")
        );
        assert_eq!(
            domain_of("http://user@boutique.co.uk/").as_deref(),
            Some("boutique.co.uk")
        );
        assert_eq!(domain_of("localhost"), None);
        assert_eq!(domain_of("https:///x"), None);
    }

    #[test]
    fn rendering() {
        let v = Verdict {
            domain: "shop.fr".into(),
            score: 15,
            signals: vec![
                Signal {
                    source: "legal".into(),
                    name: "legal_id_missing".into(),
                    weight: 15,
                    detail: "no company number".into(),
                },
                Signal {
                    source: "rdap".into(),
                    name: "domain_age_days".into(),
                    weight: 0,
                    detail: "registered 400 days ago".into(),
                },
            ],
            checked_at: 0,
        };
        assert_eq!(
            render(&v),
            "shop.fr  score 15\n\
             \x20  +15  legal    legal_id_missing  no company number\n\
             \x20   +0  rdap     domain_age_days   registered 400 days ago\n"
        );
    }
}
