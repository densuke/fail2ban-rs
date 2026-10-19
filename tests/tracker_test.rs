//! 失敗回数のスライディングウィンドウ (FailTracker) のテスト。

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fail2ban_rs::tracker::FailTracker;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// 基準時刻 t0 から `secs` 秒後の時刻。
fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_000_000 + secs)
}

fn tracker() -> FailTracker {
    FailTracker::new(Duration::from_secs(10), 5)
}

#[test]
fn reaches_threshold_within_window_then_clears_record() {
    let mut t = tracker();
    let a = ip("192.0.2.1");

    assert!(!t.record(a, at(0)));
    assert!(!t.record(a, at(1)));
    assert!(!t.record(a, at(2)));
    assert!(!t.record(a, at(3)));
    assert!(t.record(a, at(4)));
    // 閾値到達で記録が消えているので、次の 1 回は数え直しになる
    assert!(!t.record(a, at(5)));
}

#[test]
fn failure_exactly_findtime_old_is_not_counted() {
    let mut t = tracker();
    let a = ip("192.0.2.1");

    assert!(!t.record(a, at(0)));
    assert!(!t.record(a, at(1)));
    assert!(!t.record(a, at(2)));
    assert!(!t.record(a, at(3)));
    // t=0 はちょうど 10 秒前なので数えない。残りは 4 件で閾値未満
    assert!(!t.record(a, at(10)));
}

#[test]
fn ips_are_counted_independently() {
    let mut t = tracker();
    let a = ip("192.0.2.1");
    let b = ip("192.0.2.2");

    for s in 0..4 {
        assert!(!t.record(a, at(s)));
        assert!(!t.record(b, at(s)));
    }
}

#[test]
fn out_of_order_record_does_not_panic_and_counts_sensibly() {
    let mut t = tracker();
    let a = ip("192.0.2.1");

    // 後から届いた古い時刻は、保存済みの時刻より前でも落とさず数える
    assert!(!t.record(a, at(5)));
    assert!(!t.record(a, at(3)));
    assert!(!t.record(a, at(4)));
    assert!(!t.record(a, at(1)));
    assert!(t.record(a, at(2)));
}

#[test]
fn prune_removes_expired_entries_and_empty_ips() {
    let mut t = tracker();
    let a = ip("192.0.2.1");

    assert!(!t.record(a, at(0)));
    assert_eq!(t.len(), 1);

    t.prune(at(20));
    assert_eq!(t.len(), 0);
    assert!(t.is_empty());
}

#[test]
fn prune_keeps_recent_entries() {
    let mut t = tracker();
    let a = ip("192.0.2.1");

    assert!(!t.record(a, at(0)));
    assert!(!t.record(a, at(5)));

    // now=t+12 では t=0 (12 秒前) は消え、t=5 (7 秒前) は残る
    t.prune(at(12));
    assert_eq!(t.len(), 1);
}

#[test]
fn prune_with_earlier_now_keeps_entries() {
    let mut t = tracker();
    let a = ip("192.0.2.1");

    assert!(!t.record(a, at(10)));
    // now が記録より前でも panic せず、記録を保持する
    t.prune(at(0));
    assert_eq!(t.len(), 1);
}
