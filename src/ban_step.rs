//! ブロックの手順。sshd と HTTP の両方の engine が使う。

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::action::{ActionError, BanAction};
use crate::config::RecidiveConfig;
use crate::ledger::SharedLedger;
use crate::tracker::FailTracker;

/// 常習犯の設定と、ブロックの回数を数える tracker。
pub type Recidive = (RecidiveConfig, FailTracker);

/// ブロックの手順の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanStep {
    /// すでにこれより長いブロックが続いている。値はその終わる時刻。
    AlreadyBanned(SystemTime),
    /// ブロックした。`long` は常習犯の長期ブロックのとき `true`。
    Banned { bantime: Duration, long: bool },
}

/// 常習犯の判定、表の確認 (続いているブロックがあれば何もしない)、ブロック、常習犯の記録を順に行う。
///
/// 表に載せたあとでブロックに失敗したら表を元に戻して `Err` を返す。
/// 常習犯の回数には、ブロックが掛かったものだけを数える。
pub fn ban_step<A: BanAction>(
    action: &A,
    ledger: Option<&SharedLedger>,
    recidive: Option<&mut Recidive>,
    ip: IpAddr,
    at: SystemTime,
    base: Duration,
) -> Result<BanStep, ActionError> {
    // maxbans 回目のブロックなら長期ブロックにする (記録は tracker 側で消える)。
    let long = recidive
        .as_deref()
        .filter(|(_, bans)| bans.would_reach(ip, at))
        .map(|(config, _)| config.bantime);
    let bantime = long.unwrap_or(base);
    // まだ続いているブロックがあれば何もしない。延ばさず、常習犯の回数にも数えない。
    let mut previous_end = None;
    if let Some(ledger) = ledger {
        let mut ledger = ledger.borrow_mut();
        previous_end = ledger.end_of(ip);
        if let Some(end) = previous_end.filter(|end| *end > at) {
            return Ok(BanStep::AlreadyBanned(end));
        }
        if let Err(until) = ledger.admit(ip, at, bantime) {
            return Ok(BanStep::AlreadyBanned(until));
        }
    }
    if let Err(e) = action.ban(ip, bantime) {
        // ブロックが掛からなかったので、表の終わる時刻も元に戻す。
        if let Some(ledger) = ledger {
            ledger.borrow_mut().restore(ip, previous_end);
        }
        return Err(e);
    }
    // 掛かったブロックだけを常習犯の回数に数える。
    if let Some((_, bans)) = recidive {
        bans.record(ip, at);
    }
    Ok(BanStep::Banned {
        bantime,
        long: long.is_some(),
    })
}
