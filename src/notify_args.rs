//! 結果から、通知コマンドに渡す値を決める。通知を出すかどうかの判断はここに寄せる。

use std::net::IpAddr;
use std::time::Duration;

use crate::engine::Outcome;
use crate::http_engine::HttpOutcome;

/// 通知コマンドに渡す値。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyArgs {
    pub ip: IpAddr,
    pub bantime: Duration,
    /// "通常" または "長期"。
    pub kind: &'static str,
    pub jail: &'static str,
    pub rule: &'static str,
}

fn kind_of(long: bool) -> &'static str {
    if long { "長期" } else { "通常" }
}

/// sshd の結果に対する通知。`bantime` は、その結果に対応するブロック期間
/// (`Engine::bantime_of`)。ブロックしていない結果では通知しない。
pub fn sshd_notify(outcome: &Outcome, bantime: Duration) -> Option<NotifyArgs> {
    let (ip, long) = match outcome {
        Outcome::Banned(ip) => (*ip, false),
        Outcome::LongBanned(ip) => (*ip, true),
        _ => return None,
    };
    Some(NotifyArgs {
        ip,
        bantime,
        kind: kind_of(long),
        jail: "sshd",
        rule: "sshd",
    })
}

/// HTTP の結果に対する通知。log モードの `WouldBan` も通知する (動作の確認用)。
pub fn http_notify(outcome: &HttpOutcome) -> Option<NotifyArgs> {
    let (ip, rule, bantime, long) = match outcome {
        HttpOutcome::Banned {
            ip,
            rule,
            bantime,
            long,
            ..
        } => (*ip, *rule, *bantime, *long),
        HttpOutcome::WouldBan {
            ip, rule, bantime, ..
        } => (*ip, *rule, *bantime, false),
        _ => return None,
    };
    Some(NotifyArgs {
        ip,
        bantime,
        kind: kind_of(long),
        jail: "http",
        rule: rule.as_str(),
    })
}
