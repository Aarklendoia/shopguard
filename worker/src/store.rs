//! Domains seen and their verdicts, kept across restarts.
//!
//! Persistence is an append-only JSON-lines file (`store.jsonl` in the data directory):
//! every change appends one record, the last record of a domain wins. The file is
//! rewritten from memory (temporary file, then rename) when it opens and when it grows
//! past twice the live data. A torn last line after a crash is skipped.
//!
//! Without a data directory the store lives in memory only.
//!
//! Domains received but not analyzed yet are persisted too: the plugin sends each domain
//! once, a restart must not lose them. Verdicts expire ([`ttl`]) and are analyzed again,
//! since fake shops change fast. Past `cap` domains, the least recently seen are evicted.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::analysis::Verdict;

pub const FILE: &str = "store.jsonl";
pub const DEFAULT_CAP: usize = 100_000;
/// Verdicts scoring at least this are checked again sooner.
const SUSPICIOUS: u8 = 50;
const TTL_SUSPICIOUS: u64 = 24 * 3600;
const TTL_OTHER: u64 = 7 * 24 * 3600;
/// Share of `cap` evicted at once when full, so eviction does not run on every insert.
const EVICT_DIVISOR: usize = 100;

/// How long a verdict stays valid.
pub fn ttl(score: u8) -> u64 {
    if score >= SUSPICIOUS {
        TTL_SUSPICIOUS
    } else {
        TTL_OTHER
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Entry {
    domain: String,
    /// Unix time the plugin last sent the domain.
    last_seen: u64,
    /// `None` until the first analysis.
    verdict: Option<Verdict>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Record {
    Put(Entry),
    Del { domain: String },
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// In the analysis queue or being analyzed: not to be scheduled again.
    queued: HashSet<String>,
}

struct Log {
    dir: PathBuf,
    file: File,
    /// Records in the file, to decide when to compact it.
    lines: usize,
}

pub struct Store {
    inner: RwLock<Inner>,
    log: Option<Mutex<Log>>,
    cap: usize,
}

impl Default for Store {
    fn default() -> Self {
        Self::memory(DEFAULT_CAP)
    }
}

/// Writes `entries` to a new file and puts it in place of `store.jsonl`.
fn rewrite<'a>(dir: &Path, entries: impl Iterator<Item = &'a Entry>) -> io::Result<usize> {
    let tmp = dir.join(format!("{FILE}.tmp"));
    let mut w = BufWriter::new(File::create(&tmp)?);
    let mut n = 0;
    for e in entries {
        serde_json::to_writer(&mut w, &Record::Put(e.clone()))?;
        w.write_all(b"\n")?;
        n += 1;
    }
    w.into_inner()
        .map_err(io::IntoInnerError::into_error)?
        .sync_all()?;
    fs::rename(&tmp, dir.join(FILE))?;
    Ok(n)
}

fn append_handle(dir: &Path) -> io::Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(dir.join(FILE))
}

impl Store {
    pub fn memory(cap: usize) -> Self {
        Self {
            inner: RwLock::default(),
            log: None,
            cap: cap.max(1),
        }
    }

    /// Loads `dir/store.jsonl` (if any), compacts it and appends to it from then on.
    pub fn open(dir: &Path, cap: usize) -> io::Result<Self> {
        let mut entries: HashMap<String, Entry> = HashMap::new();
        let (mut read, mut bad) = (0usize, 0usize);
        match File::open(dir.join(FILE)) {
            Ok(f) => {
                for line in BufReader::new(f).lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    read += 1;
                    match serde_json::from_str::<Record>(&line) {
                        Ok(Record::Put(e)) => {
                            entries.insert(e.domain.clone(), e);
                        }
                        Ok(Record::Del { domain }) => {
                            entries.remove(&domain);
                        }
                        // torn write after a crash, or a format we no longer read
                        Err(_) => bad += 1,
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if bad > 0 {
            warn!(skipped = bad, "unreadable records in {FILE}");
        }
        let store = Self {
            inner: RwLock::new(Inner {
                entries,
                queued: HashSet::new(),
            }),
            log: None,
            cap: cap.max(1),
        };
        // apply the cap of this run, then rewrite the file compactly
        let mut inner = store.inner.try_write().expect("not shared yet");
        store.evict(&mut inner);
        let lines = rewrite(dir, inner.entries.values())?;
        let (domains, pending) = (inner.entries.len(), Self::count_pending(&inner));
        drop(inner);
        info!(path = %dir.join(FILE).display(), records = read, domains, pending, "store loaded");
        Ok(Self {
            log: Some(Mutex::new(Log {
                dir: dir.to_owned(),
                file: append_handle(dir)?,
                lines,
            })),
            ..store
        })
    }

    /// Appends `record`, compacting the file when it holds too many stale records.
    fn persist(&self, inner: &Inner, record: Record) {
        let Some(log) = &self.log else { return };
        let mut log = log.lock().unwrap_or_else(|p| p.into_inner());
        let res = (|| -> io::Result<()> {
            if log.lines > 2 * inner.entries.len() + 10_000 {
                log.lines = rewrite(&log.dir, inner.entries.values())?;
                log.file = append_handle(&log.dir)?;
                // the record is already reflected in `inner`
                return Ok(());
            }
            let mut line = serde_json::to_vec(&record)?;
            line.push(b'\n');
            log.file.write_all(&line)?;
            log.lines += 1;
            Ok(())
        })();
        if let Err(e) = res {
            warn!("cannot write {FILE}: {e}");
        }
    }

    /// Drops the least recently seen domains when over the cap.
    fn evict(&self, inner: &mut Inner) -> Vec<String> {
        if inner.entries.len() <= self.cap {
            return Vec::new();
        }
        let target = self.cap - (self.cap / EVICT_DIVISOR).min(self.cap - 1);
        let mut by_age: Vec<(u64, String)> = inner
            .entries
            .values()
            .filter(|e| !inner.queued.contains(&e.domain))
            .map(|e| (e.last_seen, e.domain.clone()))
            .collect();
        by_age.sort_unstable();
        let n = inner.entries.len().saturating_sub(target).min(by_age.len());
        let gone: Vec<String> = by_age.into_iter().take(n).map(|(_, d)| d).collect();
        for d in &gone {
            inner.entries.remove(d);
        }
        gone
    }

    /// Records `domain` as seen. True if it was not known (and must be analyzed now: the
    /// caller queues it, or calls [`Store::unmark_seen`] if the queue is full).
    pub async fn mark_seen(&self, domain: &str) -> bool {
        let mut inner = self.inner.write().await;
        let now = now();
        if let Some(e) = inner.entries.get_mut(domain) {
            // memory only: saved with the next record or compaction
            e.last_seen = now;
            return false;
        }
        let entry = Entry {
            domain: domain.to_owned(),
            last_seen: now,
            verdict: None,
        };
        inner.entries.insert(domain.to_owned(), entry.clone());
        inner.queued.insert(domain.to_owned());
        for d in self.evict(&mut inner) {
            self.persist(&inner, Record::Del { domain: d });
        }
        self.persist(&inner, Record::Put(entry));
        true
    }

    /// Forgets `domain`, e.g. when the analysis queue is full (the plugin sends it again).
    pub async fn unmark_seen(&self, domain: &str) {
        let mut inner = self.inner.write().await;
        inner.queued.remove(domain);
        if inner.entries.remove(domain).is_some() {
            self.persist(
                &inner,
                Record::Del {
                    domain: domain.to_owned(),
                },
            );
        }
    }

    pub async fn insert(&self, verdict: Verdict) {
        let mut inner = self.inner.write().await;
        inner.queued.remove(&verdict.domain);
        let entry = match inner.entries.get_mut(&verdict.domain) {
            Some(e) => {
                e.verdict = Some(verdict);
                e.clone()
            }
            // evicted while being analyzed: keep the result anyway
            None => {
                let e = Entry {
                    domain: verdict.domain.clone(),
                    last_seen: now(),
                    verdict: Some(verdict),
                };
                inner.entries.insert(e.domain.clone(), e.clone());
                e
            }
        };
        self.persist(&inner, Record::Put(entry));
    }

    /// Up to `limit` domains to analyze now: never analyzed, or with an expired verdict.
    /// They count as queued until [`Store::insert`] or [`Store::release`].
    pub async fn due(&self, now: u64, limit: usize) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let mut inner = self.inner.write().await;
        let mut due: Vec<(u64, String)> = inner
            .entries
            .values()
            .filter(|e| !inner.queued.contains(&e.domain))
            .filter_map(|e| match &e.verdict {
                None => Some((0, e.domain.clone())),
                Some(v) => {
                    let expires = v.checked_at.saturating_add(ttl(v.score));
                    (expires <= now).then(|| (expires, e.domain.clone()))
                }
            })
            .collect();
        // never analyzed first, then the longest expired
        due.sort_unstable();
        due.truncate(limit);
        let due: Vec<String> = due.into_iter().map(|(_, d)| d).collect();
        inner.queued.extend(due.iter().cloned());
        due
    }

    /// `domain` could not be queued after all: schedule it again later.
    pub async fn release(&self, domain: &str) {
        self.inner.write().await.queued.remove(domain);
    }

    pub async fn get(&self, domain: &str) -> Option<Verdict> {
        self.inner
            .read()
            .await
            .entries
            .get(domain)
            .and_then(|e| e.verdict.clone())
    }

    /// Verdicts with a score of at least `min_score`, highest score first.
    pub async fn verdicts(&self, min_score: u8) -> Vec<Verdict> {
        let mut v: Vec<Verdict> = self
            .inner
            .read()
            .await
            .entries
            .values()
            .filter_map(|e| e.verdict.clone())
            .filter(|v| v.score >= min_score)
            .collect();
        v.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.domain.cmp(&b.domain)));
        v
    }

    fn count_pending(inner: &Inner) -> usize {
        inner
            .entries
            .values()
            .filter(|e| e.verdict.is_none())
            .count()
    }

    /// Domains never analyzed yet.
    pub async fn pending(&self) -> usize {
        Self::count_pending(&*self.inner.read().await)
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Signal;

    /// Empty directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "shopguard-test-{name}-{}-{}",
                std::process::id(),
                now()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn verdict(domain: &str, weight: i32, checked_at: u64) -> Verdict {
        Verdict {
            checked_at,
            ..Verdict::new(
                domain.into(),
                vec![Signal {
                    source: "t".into(),
                    name: "t".into(),
                    weight,
                    detail: String::new(),
                }],
            )
        }
    }

    #[tokio::test]
    async fn survives_a_restart() {
        let dir = TempDir::new("restart");
        {
            let s = Store::open(&dir.0, 10).unwrap();
            assert!(s.mark_seen("a.fr").await);
            assert!(s.mark_seen("b.fr").await);
            assert!(s.mark_seen("gone.fr").await);
            assert!(!s.mark_seen("a.fr").await);
            s.unmark_seen("gone.fr").await;
            s.insert(verdict("a.fr", 80, 1000)).await;
        }
        // a torn record at the end, as after a crash
        let mut f = append_handle(&dir.0).unwrap();
        f.write_all(b"{\"op\":\"put\",\"entry\":{\"dom").unwrap();
        drop(f);

        let s = Store::open(&dir.0, 10).unwrap();
        assert_eq!(s.len().await, 2);
        assert_eq!(s.get("a.fr").await.unwrap().score, 80);
        assert_eq!(s.get("b.fr").await, None);
        assert_eq!(s.pending().await, 1);
        assert!(!s.mark_seen("b.fr").await, "still known after the restart");
        // compacted: one record per domain
        let text = fs::read_to_string(dir.0.join(FILE)).unwrap();
        assert_eq!(text.lines().count(), 2);
    }

    #[tokio::test]
    async fn schedules_new_and_expired_domains() {
        let s = Store::memory(10);
        let now = 10 * TTL_OTHER;
        // queued by the API
        assert!(s.mark_seen("new.fr").await);
        // as after a restart: pending but not queued
        s.mark_seen("pending.fr").await;
        s.release("pending.fr").await;
        s.mark_seen("fresh.fr").await;
        s.insert(verdict("fresh.fr", 10, now - 3600)).await;
        s.mark_seen("old.fr").await;
        s.insert(verdict("old.fr", 10, now - TTL_OTHER)).await;
        s.mark_seen("hot.fr").await;
        s.insert(verdict("hot.fr", 90, now - TTL_SUSPICIOUS - 1))
            .await;

        assert_eq!(s.due(now, 10).await, vec!["pending.fr", "hot.fr", "old.fr"]);
        // now queued: not scheduled twice
        assert!(s.due(now, 10).await.is_empty());
        s.release("old.fr").await;
        assert_eq!(s.due(now, 1).await, vec!["old.fr"]);
        assert!(s.due(now, 0).await.is_empty());
    }

    #[tokio::test]
    async fn evicts_least_recently_seen() {
        let s = Store::memory(3);
        for d in ["a.fr", "b.fr", "c.fr"] {
            s.mark_seen(d).await;
            s.insert(verdict(d, 0, now())).await;
        }
        {
            let mut inner = s.inner.write().await;
            for (i, d) in ["a.fr", "b.fr", "c.fr"].iter().enumerate() {
                inner.entries.get_mut(*d).unwrap().last_seen = i as u64;
            }
        }
        // a.fr seen again: b.fr is now the oldest
        s.mark_seen("a.fr").await;
        s.mark_seen("d.fr").await;
        assert_eq!(s.len().await, 3);
        assert_eq!(s.get("b.fr").await, None);
        assert!(s.get("a.fr").await.is_some());
    }

    #[tokio::test]
    async fn compacts_a_growing_file() {
        let dir = TempDir::new("compact");
        let s = Store::open(&dir.0, 10).unwrap();
        s.mark_seen("a.fr").await;
        for i in 0..10_010 {
            s.insert(verdict("a.fr", 0, i)).await;
        }
        let lines = fs::read_to_string(dir.0.join(FILE))
            .unwrap()
            .lines()
            .count();
        assert!(lines < 100, "{lines} lines");
        drop(s);
        let s = Store::open(&dir.0, 10).unwrap();
        assert_eq!(s.get("a.fr").await.unwrap().checked_at, 10_009);
    }
}
