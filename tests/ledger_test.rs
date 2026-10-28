//! ブロックの終わる時刻の表 (BanLedger) のテスト。

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fail2ban_rs::ledger::BanLedger;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_000_000 + secs)
}

fn s(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

#[test]
fn empty_ledger_admits_and_later_ban_extends() {
    let mut l = BanLedger::new();
    let a = ip("192.0.2.1");
    assert_eq!(l.admit(a, at(0), s(300)), Ok(()));
    assert_eq!(l.admit(a, at(60), s(300)), Ok(()));
    // 終わりは at(360) に延びている。
    assert_eq!(l.admit(a, at(0), s(360)), Err(at(360)));
}

#[test]
fn shorter_ban_does_not_override_longer_one() {
    let mut l = BanLedger::new();
    let a = ip("192.0.2.1");
    assert_eq!(l.admit(a, at(0), s(86400)), Ok(()));
    assert_eq!(l.admit(a, at(60), s(300)), Err(at(86400)));
    // 失敗した admit は何も変えない。
    assert_eq!(l.admit(a, at(60), s(300)), Err(at(86400)));
}

#[test]
fn prune_drops_ended_bans() {
    let mut l = BanLedger::new();
    let a = ip("192.0.2.1");
    l.admit(a, at(0), s(86400)).unwrap();
    l.prune(at(86400));
    assert_eq!(l.admit(a, at(86401), s(300)), Ok(()));
    // 残っていれば at(86400) 以前に終わる短いブロックは断られるはず。
    let mut l = BanLedger::new();
    l.admit(a, at(0), s(86400)).unwrap();
    l.prune(at(86400));
    assert_eq!(l.admit(a, at(0), s(86400)), Ok(()));
}

#[test]
fn prune_keeps_running_bans() {
    let mut l = BanLedger::new();
    let a = ip("192.0.2.1");
    l.admit(a, at(0), s(86400)).unwrap();
    l.prune(at(86399));
    assert_eq!(l.admit(a, at(86399), s(1)), Err(at(86400)));
}

#[test]
fn ips_are_independent() {
    let mut l = BanLedger::new();
    l.admit(ip("192.0.2.1"), at(0), s(86400)).unwrap();
    assert_eq!(l.admit(ip("198.51.100.1"), at(0), s(300)), Ok(()));
    assert_eq!(l.admit(ip("2001:db8::1"), at(0), s(300)), Ok(()));
}
