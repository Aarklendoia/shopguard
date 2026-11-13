//! Settings, from environment variables (12-factor: the container has no config file).

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    /// `SHOPGUARD_LISTEN`, default `[::]:8080` (dual-stack where the host allows it).
    pub listen: SocketAddr,
    /// `SHOPGUARD_TOKEN`: bearer token the plugin sends. Required, at least 32 characters.
    pub token: String,
    /// `SHOPGUARD_THRESHOLD`: minimum score of the domains in the blocklist, default 70.
    pub threshold: u8,
    /// `SHOPGUARD_QUEUE`: maximum number of domains waiting for analysis, default 10000.
    pub queue: usize,
    /// `SHOPGUARD_DATA`: directory of the store, default `/data`. Empty: memory only.
    pub data: Option<PathBuf>,
    /// `SHOPGUARD_MAX_DOMAINS`: domains kept, least recently seen evicted, default 100000.
    pub max_domains: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let listen = get("SHOPGUARD_LISTEN").unwrap_or_else(|| "[::]:8080".into());
        let listen = listen
            .parse()
            .map_err(|e| format!("SHOPGUARD_LISTEN={listen}: {e}"))?;
        let token = get("SHOPGUARD_TOKEN").unwrap_or_default();
        if token.chars().count() < 32 {
            return Err(
                "SHOPGUARD_TOKEN must be set to a random string of at least 32 characters \
                        (e.g. openssl rand -hex 32)"
                    .into(),
            );
        }
        let threshold = match get("SHOPGUARD_THRESHOLD") {
            None => 70,
            Some(t) => t
                .parse::<u8>()
                .ok()
                .filter(|t| *t <= 100)
                .ok_or_else(|| format!("SHOPGUARD_THRESHOLD={t}: expected 0 to 100"))?,
        };
        let queue = match get("SHOPGUARD_QUEUE") {
            None => 10_000,
            Some(q) => q
                .parse::<usize>()
                .ok()
                .filter(|q| *q > 0)
                .ok_or_else(|| format!("SHOPGUARD_QUEUE={q}: expected a positive number"))?,
        };
        let data = match get("SHOPGUARD_DATA") {
            None => Some(PathBuf::from("/data")),
            Some(d) if d.trim().is_empty() => None,
            Some(d) => Some(PathBuf::from(d)),
        };
        let max_domains =
            match get("SHOPGUARD_MAX_DOMAINS") {
                None => crate::store::DEFAULT_CAP,
                Some(m) => m.parse::<usize>().ok().filter(|m| *m > 0).ok_or_else(|| {
                    format!("SHOPGUARD_MAX_DOMAINS={m}: expected a positive number")
                })?,
            };
        Ok(Self {
            listen,
            token,
            threshold,
            queue,
            data,
            max_domains,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::collections::HashMap;

    fn cfg(vars: &[(&str, &str)]) -> Result<Config, String> {
        let m: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| m.get(k).cloned())
    }

    const TOKEN: (&str, &str) = ("SHOPGUARD_TOKEN", "0123456789abcdef0123456789abcdef");

    #[test]
    fn defaults() {
        let c = cfg(&[TOKEN]).unwrap();
        assert_eq!(c.listen.to_string(), "[::]:8080");
        assert_eq!((c.threshold, c.queue), (70, 10_000));
        assert_eq!(c.data.as_deref(), Some(std::path::Path::new("/data")));
        assert_eq!(c.max_domains, 100_000);
        assert_eq!(cfg(&[TOKEN, ("SHOPGUARD_DATA", "")]).unwrap().data, None);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(cfg(&[]).is_err());
        assert!(cfg(&[("SHOPGUARD_TOKEN", "short")]).is_err());
        assert!(cfg(&[TOKEN, ("SHOPGUARD_THRESHOLD", "101")]).is_err());
        assert!(cfg(&[TOKEN, ("SHOPGUARD_LISTEN", "nope")]).is_err());
        assert!(cfg(&[TOKEN, ("SHOPGUARD_QUEUE", "0")]).is_err());
        assert!(cfg(&[TOKEN, ("SHOPGUARD_MAX_DOMAINS", "0")]).is_err());
    }
}
