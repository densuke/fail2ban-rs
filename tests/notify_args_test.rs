//! 通知の振り分け (どの結果で、何を渡すか) のテスト。

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use fail2ban_rs::engine::Outcome;
use fail2ban_rs::http_engine::{HttpOutcome, HttpRule};
use fail2ban_rs::notify_args::{NotifyArgs, http_notify, sshd_notify};

fn ip() -> IpAddr {
    "192.0.2.9".parse().unwrap()
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn args(bantime: u64, kind: &'static str, jail: &'static str, rule: &'static str) -> NotifyArgs {
    NotifyArgs {
        ip: ip(),
        bantime: secs(bantime),
        kind,
        jail,
        rule,
    }
}

#[test]
fn sshd_ban_notifies_with_the_given_bantime() {
    assert_eq!(
        sshd_notify(&Outcome::Banned(ip()), secs(300)),
        Some(args(300, "通常", "sshd", "sshd"))
    );
    assert_eq!(
        sshd_notify(&Outcome::LongBanned(ip()), secs(86400)),
        Some(args(86400, "長期", "sshd", "sshd"))
    );
}

#[test]
fn sshd_other_outcomes_do_not_notify() {
    let until = SystemTime::UNIX_EPOCH;
    for o in [
        Outcome::AlreadyBanned(ip(), until),
        Outcome::Ignored(ip()),
        Outcome::Counted(ip()),
        Outcome::NoMatch,
        Outcome::Unresolvable("host".into()),
    ] {
        assert_eq!(sshd_notify(&o, secs(300)), None, "{o:?}");
    }
}

fn banned(rule: HttpRule, long: bool, bantime: u64) -> HttpOutcome {
    HttpOutcome::Banned {
        ip: ip(),
        rule,
        bantime: secs(bantime),
        long,
        uri: None,
    }
}

#[test]
fn http_ban_notifies_with_rule_and_kind() {
    assert_eq!(
        http_notify(&banned(HttpRule::Badpath, false, 300)),
        Some(args(300, "通常", "http", "badpath"))
    );
    assert_eq!(
        http_notify(&banned(HttpRule::Notfound, true, 86400)),
        Some(args(86400, "長期", "http", "notfound"))
    );
}

#[test]
fn http_would_ban_notifies_as_normal() {
    let o = HttpOutcome::WouldBan {
        ip: ip(),
        rule: HttpRule::Notfound,
        bantime: secs(300),
        uri: None,
    };
    assert_eq!(http_notify(&o), Some(args(300, "通常", "http", "notfound")));
}

#[test]
fn http_other_outcomes_do_not_notify() {
    for o in [
        HttpOutcome::AlreadyBanned {
            ip: ip(),
            rule: HttpRule::Badpath,
            until: SystemTime::UNIX_EPOCH,
        },
        HttpOutcome::Ignored(ip()),
        HttpOutcome::Counted(ip()),
        HttpOutcome::NoMatch,
    ] {
        assert_eq!(http_notify(&o), None, "{o:?}");
    }
}
