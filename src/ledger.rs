//! IP ごとの「ブロックが終わる時刻」の表。
//!
//! nftables の `add element` は、すでにある要素の timeout を上書きする。
//! 短いブロックが長いブロックを縮めないよう、jail 間で共有してここで確かめる。

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

/// 複数の jail が同じ表を使うための共有ハンドル。
pub type SharedLedger = Rc<RefCell<BanLedger>>;

/// IP ごとのブロックの終わる時刻。
#[derive(Debug, Default)]
pub struct BanLedger {
    ends: HashMap<IpAddr, SystemTime>,
}

impl BanLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// `at` から `bantime` のブロックを入れてよいか確かめる。
    ///
    /// 今の終わる時刻が `at + bantime` 以上なら、何も変えずに `Err(今の終わる時刻)`。
    /// そうでなければ終わる時刻を `at + bantime` にして `Ok(())`。
    pub fn admit(
        &mut self,
        ip: IpAddr,
        at: SystemTime,
        bantime: Duration,
    ) -> Result<(), SystemTime> {
        let end = at + bantime;
        match self.ends.get(&ip) {
            Some(current) if *current >= end => Err(*current),
            _ => {
                self.ends.insert(ip, end);
                Ok(())
            }
        }
    }

    /// 終わる時刻が `now` 以前の IP を消す。
    pub fn prune(&mut self, now: SystemTime) {
        self.ends.retain(|_, end| *end > now);
    }
}
