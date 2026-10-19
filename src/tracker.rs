//! IP ごとの失敗回数を、時間窓 (findtime) で数えるスライディングウィンドウ。
//!
//! journal の時刻は多少前後することがあるため、記録は時刻順を前提にしない。
//! 基準時刻より後ろにある記録は「古くない」として残す。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// IP ごとの失敗時刻を保持し、閾値到達を判定する。
#[derive(Debug)]
pub struct FailTracker {
    findtime: Duration,
    maxretry: u32,
    failures: HashMap<IpAddr, VecDeque<SystemTime>>,
}

impl FailTracker {
    /// `findtime` 以内に `maxretry` 回失敗した IP を検出するトラッカーを作る。
    pub fn new(findtime: Duration, maxretry: u32) -> Self {
        Self {
            findtime,
            maxretry,
            failures: HashMap::new(),
        }
    }

    /// `ip` の失敗を `at` で記録する。
    ///
    /// 窓の外に出た古い記録を捨ててから `at` を足し、残りが `maxretry` 以上なら
    /// その IP の記録を消して `true` を返す。
    pub fn record(&mut self, ip: IpAddr, at: SystemTime) -> bool {
        let findtime = self.findtime;
        let times = self.failures.entry(ip).or_default();
        times.retain(|t| is_within(at, *t, findtime));
        times.push_back(at);
        if times.len() >= self.maxretry as usize {
            self.failures.remove(&ip);
            true
        } else {
            false
        }
    }

    /// `now` から見て窓の外に出た記録を捨て、空になった IP を消す。
    pub fn prune(&mut self, now: SystemTime) {
        let findtime = self.findtime;
        self.failures.retain(|_, times| {
            times.retain(|t| is_within(now, *t, findtime));
            !times.is_empty()
        });
    }

    /// 記録を持つ IP の数。
    pub fn len(&self) -> usize {
        self.failures.len()
    }

    /// 記録を持つ IP がなければ `true`。
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }
}

/// `t` が `base` から見て `findtime` 未満の古さならば `true`。
///
/// `t` が `base` より後ろの時刻 (順序の入れ違い) の場合は古くないものとして `true` を返す。
fn is_within(base: SystemTime, t: SystemTime, findtime: Duration) -> bool {
    match base.duration_since(t) {
        Ok(age) => age < findtime,
        Err(_) => true,
    }
}
