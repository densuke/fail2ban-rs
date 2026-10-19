//! フィルタ、ignoreip、失敗の集計、ブロックの動作をつなぐ。

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::action::{ActionError, BanAction};
use crate::config::{Config, ConfigError};
use crate::filter::{FilterError, SshdFilter};
use crate::ip::{IgnoreList, canonical_ip};
use crate::journal::LogEntry;
use crate::tracker::FailTracker;

/// 1 行を処理した結果。
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// 失敗ではない行 (または数えない行)。
    NoMatch,
    /// ホストが IP アドレスとして解釈できない。
    Unresolvable(String),
    /// ignoreip に入るので数えない。
    Ignored(IpAddr),
    /// 数えたが、まだ上限に達していない。
    Counted(IpAddr),
    /// 上限に達してブロックした。
    Banned(IpAddr),
}

/// Engine を作るときのエラー。
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Filter(#[from] FilterError),
}

/// 行を 1 つずつ受けて、必要ならブロックする。
pub struct Engine<A: BanAction> {
    filter: SshdFilter,
    ignore: IgnoreList,
    tracker: FailTracker,
    bantime: Duration,
    action: A,
}

impl<A: BanAction> Engine<A> {
    pub fn new(config: &Config, action: A) -> Result<Self, EngineError> {
        Ok(Self {
            filter: SshdFilter::new()?,
            ignore: IgnoreList::parse(&config.ignoreip)?,
            tracker: FailTracker::new(config.sshd.findtime, config.sshd.maxretry),
            bantime: config.sshd.bantime,
            action,
        })
    }

    /// 1 行を処理する。ブロックに失敗したら `Err` を返す。
    pub fn handle(&mut self, entry: &LogEntry) -> Result<Outcome, ActionError> {
        let Some(m) = self.filter.check(&entry.message) else {
            return Ok(Outcome::NoMatch);
        };
        if m.nofail {
            return Ok(Outcome::NoMatch);
        }
        let Some(ip) = canonical_ip(&m.host) else {
            return Ok(Outcome::Unresolvable(m.host));
        };
        if self.ignore.contains(ip) {
            return Ok(Outcome::Ignored(ip));
        }
        if self.tracker.record(ip, entry.time) {
            self.action.ban(ip, self.bantime)?;
            return Ok(Outcome::Banned(ip));
        }
        Ok(Outcome::Counted(ip))
    }

    /// 古い記録を捨てる。
    pub fn prune(&mut self, now: SystemTime) {
        self.tracker.prune(now);
    }
}
