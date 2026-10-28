//! フィルタ、ignoreip、失敗の集計、ブロックの動作をつなぐ。

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::action::{ActionError, BanAction};
use crate::config::{Config, ConfigError, RecidiveConfig};
use crate::filter::{FilterError, SshdFilter};
use crate::ip::{IgnoreList, canonical_ip};
use crate::journal::LogEntry;
use crate::ledger::SharedLedger;
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
    /// 常習犯なので、長い期間でブロックした。
    LongBanned(IpAddr),
    /// 上限に達したが、すでにこれより長いブロックが続いているので何もしなかった。
    /// 値は、そのブロックの終わる時刻。
    AlreadyBanned(IpAddr, SystemTime),
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
    /// 常習犯の設定と、ブロックの回数を数える tracker。無効なら `None`。
    recidive: Option<(RecidiveConfig, FailTracker)>,
    /// ブロックの終わる時刻の共有表。`None` なら見ない。
    ledger: Option<SharedLedger>,
    action: A,
}

impl<A: BanAction> Engine<A> {
    pub fn new(
        config: &Config,
        action: A,
        ledger: Option<SharedLedger>,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            filter: SshdFilter::new()?,
            ignore: IgnoreList::parse(&config.ignoreip)?,
            tracker: FailTracker::new(config.sshd.findtime, config.sshd.maxretry),
            bantime: config.sshd.bantime,
            recidive: config
                .sshd
                .recidive
                .clone()
                .map(|r| (r.clone(), FailTracker::new(r.findtime, r.maxbans))),
            ledger,
            action,
        })
    }

    /// ブロックの動作を準備する。設定の検証が済んだ後に呼ぶ。
    pub fn start(&self) -> Result<(), ActionError> {
        self.action.start()
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
        if !self.tracker.record(ip, entry.time) {
            return Ok(Outcome::Counted(ip));
        }
        // maxbans 回目のブロックなら長期ブロックにする (記録は tracker 側で消える)。
        let long = self
            .recidive
            .as_ref()
            .filter(|(_, bans)| bans.would_reach(ip, entry.time))
            .map(|(recidive, _)| recidive.bantime);
        let bantime = long.unwrap_or(self.bantime);
        // 終わりがもっと先のブロックがあれば何もしない。常習犯の回数にも数えない。
        let mut previous_end = None;
        if let Some(ledger) = &self.ledger {
            let mut ledger = ledger.borrow_mut();
            previous_end = ledger.end_of(ip);
            if let Err(ends) = ledger.admit(ip, entry.time, bantime) {
                return Ok(Outcome::AlreadyBanned(ip, ends));
            }
        }
        if let Some((_, bans)) = self.recidive.as_mut() {
            bans.record(ip, entry.time);
        }
        if let Err(e) = self.action.ban(ip, bantime) {
            // ブロックが掛からなかったので、表の終わる時刻も元に戻す。
            if let Some(ledger) = &self.ledger {
                ledger.borrow_mut().restore(ip, previous_end);
            }
            return Err(e);
        }
        Ok(if long.is_some() {
            Outcome::LongBanned(ip)
        } else {
            Outcome::Banned(ip)
        })
    }

    /// ブロックの結果に対応するブロック期間。ブロックではない結果なら `None`。
    pub fn bantime_of(&self, outcome: &Outcome) -> Option<Duration> {
        match (outcome, &self.recidive) {
            (Outcome::Banned(_), _) => Some(self.bantime),
            (Outcome::LongBanned(_), Some((recidive, _))) => Some(recidive.bantime),
            _ => None,
        }
    }

    /// 古い記録を捨てる。
    pub fn prune(&mut self, now: SystemTime) {
        self.tracker.prune(now);
        if let Some((_, bans)) = self.recidive.as_mut() {
            bans.prune(now);
        }
    }
}
