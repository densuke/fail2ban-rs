//! Caddy のアクセスログの 1 行を判定し、必要ならブロックする。

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::action::{ActionError, BanAction};
use crate::config::{HttpConfig, Mode, RecidiveConfig};
use crate::engine::EngineError;
use crate::filter::{AccessEntry, BadPaths, parse_access};
use crate::ip::IgnoreList;
use crate::journal::LogEntry;
use crate::ledger::SharedLedger;
use crate::tracker::FailTracker;

/// ブロックの理由になったルール。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRule {
    /// 既知の危険なパスへのアクセス。
    Badpath,
    /// 404 の連続。
    Notfound,
}

impl HttpRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Badpath => "badpath",
            Self::Notfound => "notfound",
        }
    }
}

/// 1 行を処理した結果。
#[derive(Debug, Clone, PartialEq)]
pub enum HttpOutcome {
    /// アクセスログでない行、またはどのルールにも関わらない行。
    NoMatch,
    /// ignoreip に入るので何も記録しない。
    Ignored(IpAddr),
    /// 404 として数えたが、まだ上限に達していない。
    Counted(IpAddr),
    /// ブロックした。`uri` は badpath のときだけ、当たった URI。
    Banned {
        ip: IpAddr,
        rule: HttpRule,
        bantime: Duration,
        long: bool,
        uri: Option<String>,
    },
    /// 上限に達したが、mode が log なのでブロックしなかった。
    WouldBan {
        ip: IpAddr,
        rule: HttpRule,
        bantime: Duration,
        uri: Option<String>,
    },
    /// すでにこれより長いブロックが続いているので何もしなかった。`until` はその終わる時刻。
    AlreadyBanned {
        ip: IpAddr,
        rule: HttpRule,
        until: SystemTime,
    },
}

/// 閾値に達した行。どのルールで、どの mode かを持つ。
struct Hit {
    rule: HttpRule,
    mode: Mode,
    uri: Option<String>,
}

/// アクセスログを 1 行ずつ受けて、必要ならブロックする。
pub struct HttpEngine<A: BanAction> {
    badpaths: BadPaths,
    badpath_enabled: bool,
    badpath_mode: Mode,
    notfound_enabled: bool,
    notfound_mode: Mode,
    ignore: IgnoreList,
    notfound: FailTracker,
    bantime: Duration,
    /// 常習犯の設定と、ブロックの回数を数える tracker。無効なら `None`。
    recidive: Option<(RecidiveConfig, FailTracker)>,
    ledger: SharedLedger,
    action: A,
}

impl<A: BanAction> HttpEngine<A> {
    pub fn new(
        http: &HttpConfig,
        ignoreip: &[String],
        action: A,
        ledger: SharedLedger,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            badpaths: BadPaths::new(&http.badpath.extra)?,
            badpath_enabled: http.badpath.enabled,
            badpath_mode: http.badpath.mode,
            notfound_enabled: http.notfound.enabled,
            notfound_mode: http.notfound.mode,
            ignore: IgnoreList::parse(ignoreip)?,
            notfound: FailTracker::new(http.notfound.findtime, http.notfound.maxretry),
            bantime: http.bantime,
            recidive: http
                .recidive
                .clone()
                .map(|r| (r.clone(), FailTracker::new(r.findtime, r.maxbans))),
            ledger,
            action,
        })
    }

    /// 1 行を処理する。ブロックに失敗したら `Err` を返す。
    pub fn handle(&mut self, entry: &LogEntry) -> Result<HttpOutcome, ActionError> {
        let Some(access) = parse_access(&entry.message) else {
            return Ok(HttpOutcome::NoMatch);
        };
        let is_badpath = self.badpath_enabled && self.badpaths.matches(&access.uri);
        let is_notfound = self.notfound_enabled && access.status == 404;
        if !is_badpath && !is_notfound {
            return Ok(HttpOutcome::NoMatch);
        }
        if self.ignore.contains(access.ip) {
            return Ok(HttpOutcome::Ignored(access.ip));
        }
        let Some(hit) = self.judge(&access, entry.time, is_badpath) else {
            return Ok(HttpOutcome::Counted(access.ip));
        };
        match hit.mode {
            Mode::Log => Ok(HttpOutcome::WouldBan {
                ip: access.ip,
                rule: hit.rule,
                bantime: self.bantime,
                uri: hit.uri,
            }),
            Mode::Nft => self.ban(access.ip, entry.time, hit),
        }
    }

    /// 閾値に達したルールを返す。badpath は即達し、404 の tracker には足さない。
    fn judge(&mut self, access: &AccessEntry, at: SystemTime, is_badpath: bool) -> Option<Hit> {
        if is_badpath {
            return Some(Hit {
                rule: HttpRule::Badpath,
                mode: self.badpath_mode,
                uri: Some(access.uri.clone()),
            });
        }
        self.notfound.record(access.ip, at).then_some(Hit {
            rule: HttpRule::Notfound,
            mode: self.notfound_mode,
            uri: None,
        })
    }

    /// ledger の確認、ブロック、recidive の記録を順に行う。
    fn ban(&mut self, ip: IpAddr, at: SystemTime, hit: Hit) -> Result<HttpOutcome, ActionError> {
        // maxbans 回目のブロックなら長期ブロックにする (記録は tracker 側で消える)。
        let long = self
            .recidive
            .as_ref()
            .filter(|(_, bans)| bans.would_reach(ip, at))
            .map(|(recidive, _)| recidive.bantime);
        let bantime = long.unwrap_or(self.bantime);
        // 終わりがもっと先のブロックがあれば何もしない。常習犯の回数にも数えない。
        let previous_end = {
            let mut ledger = self.ledger.borrow_mut();
            let previous_end = ledger.end_of(ip);
            if let Err(until) = ledger.admit(ip, at, bantime) {
                return Ok(HttpOutcome::AlreadyBanned {
                    ip,
                    rule: hit.rule,
                    until,
                });
            }
            previous_end
        };
        if let Err(e) = self.action.ban(ip, bantime) {
            // ブロックが掛からなかったので、表の終わる時刻も元に戻す。
            self.ledger.borrow_mut().restore(ip, previous_end);
            return Err(e);
        }
        // 掛かったブロックだけを常習犯の回数に数える。
        if let Some((_, bans)) = self.recidive.as_mut() {
            bans.record(ip, at);
        }
        Ok(HttpOutcome::Banned {
            ip,
            rule: hit.rule,
            bantime,
            long: long.is_some(),
            uri: hit.uri,
        })
    }

    /// 古い記録を捨てる。
    pub fn prune(&mut self, now: SystemTime) {
        self.notfound.prune(now);
        if let Some((_, bans)) = self.recidive.as_mut() {
            bans.prune(now);
        }
    }
}
