//! HttpEngine の振る舞いのテスト。ban は記録用の BanAction で受ける。

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use fail2ban_rs::action::{ActionError, BanAction};
use fail2ban_rs::config::parse_config;
use fail2ban_rs::http_engine::{HttpEngine, HttpOutcome, HttpRule};
use fail2ban_rs::journal::LogEntry;
use fail2ban_rs::ledger::{BanLedger, SharedLedger};

type Bans = Rc<RefCell<Vec<(IpAddr, Duration)>>>;

struct Recorder {
    bans: Bans,
    fail_ban: Rc<Cell<bool>>,
}

impl BanAction for Recorder {
    fn start(&self) -> Result<(), ActionError> {
        Ok(())
    }
    fn ban(&self, ip: IpAddr, bantime: Duration) -> Result<(), ActionError> {
        if self.fail_ban.get() {
            return Err(ActionError::NftFailed {
                status: "exit 1".into(),
                stderr: "boom".into(),
            });
        }
        self.bans.borrow_mut().push((ip, bantime));
        Ok(())
    }
}

struct Rig {
    engine: HttpEngine<Recorder>,
    bans: Bans,
    ledger: SharedLedger,
    fail_ban: Rc<Cell<bool>>,
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// 全体は nft。`extra` は `[http]` 以下に足す設定。
fn rig(extra: &str, ignoreip: &str) -> Rig {
    let config = parse_config(&format!("mode = \"nft\"\n{ignoreip}\n[http]\n{extra}")).unwrap();
    let bans: Bans = Rc::default();
    let fail_ban = Rc::new(Cell::new(false));
    let ledger: SharedLedger = Rc::new(RefCell::new(BanLedger::new()));
    let action = Recorder {
        bans: bans.clone(),
        fail_ban: fail_ban.clone(),
    };
    let engine = HttpEngine::new(
        config.http.as_ref().unwrap(),
        &config.ignoreip,
        action,
        ledger.clone(),
    )
    .unwrap();
    Rig {
        engine,
        bans,
        ledger,
        fail_ban,
    }
}

fn access(logger: &str, client: &str, uri: &str, status: u16) -> String {
    serde_json::json!({
        "logger": logger,
        "status": status,
        "request": {"client_ip": client, "uri": uri},
    })
    .to_string()
}

fn entry(message: String, offset: u64) -> LogEntry {
    LogEntry {
        time: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + offset),
        message,
        cursor: None,
    }
}

fn hit(rig: &mut Rig, client: &str, uri: &str, status: u16, at: u64) -> HttpOutcome {
    let msg = access("http.log.access.log0", client, uri, status);
    rig.engine.handle(&entry(msg, at)).unwrap()
}

const RECIDIVE: &str = "[http.recidive]\nmaxbans = 3\n";

#[test]
fn badpath_bans_at_once() {
    let mut r = rig("", "");
    let out = hit(&mut r, "192.0.2.1", "/.env", 404, 0);
    assert_eq!(
        out,
        HttpOutcome::Banned {
            ip: ip("192.0.2.1"),
            rule: HttpRule::Badpath,
            bantime: secs(300),
            long: false,
            uri: Some("/.env".into()),
        }
    );
    assert_eq!(*r.bans.borrow(), vec![(ip("192.0.2.1"), secs(300))]);
}

#[test]
fn badpath_bans_regardless_of_status() {
    for status in [502, 303, 200] {
        let mut r = rig("", "");
        let out = hit(&mut r, "192.0.2.2", "/.env", status, 0);
        assert!(
            matches!(
                out,
                HttpOutcome::Banned {
                    rule: HttpRule::Badpath,
                    ..
                }
            ),
            "status {status}: {out:?}"
        );
    }
}

#[test]
fn notfound_bans_on_twentieth_within_window() {
    let mut r = rig("", "");
    for i in 1..20 {
        let out = hit(&mut r, "192.0.2.3", &format!("/x{i}"), 404, i);
        assert_eq!(out, HttpOutcome::Counted(ip("192.0.2.3")));
    }
    let out = hit(&mut r, "192.0.2.3", "/x20", 404, 20);
    assert_eq!(
        out,
        HttpOutcome::Banned {
            ip: ip("192.0.2.3"),
            rule: HttpRule::Notfound,
            bantime: secs(300),
            long: false,
            uri: None,
        }
    );
}

#[test]
fn notfound_window_restarts_after_gap() {
    let mut r = rig("", "");
    for i in 0..19 {
        hit(&mut r, "192.0.2.4", &format!("/x{i}"), 404, i);
    }
    // 窓 (600 秒) を超えて間が空いたので、数え直しになる。
    let out = hit(&mut r, "192.0.2.4", "/x19", 404, 19 + 601);
    assert_eq!(out, HttpOutcome::Counted(ip("192.0.2.4")));
    assert!(r.bans.borrow().is_empty());
}

const LOG_BADPATH: &str = "[http.badpath]\nmode = \"log\"\n";

#[test]
fn log_badpath_404_still_counts_toward_notfound() {
    let mut r = rig(LOG_BADPATH, "");
    for i in 1..20 {
        hit(&mut r, "192.0.2.14", &format!("/x{i}"), 404, i);
    }
    let out = hit(&mut r, "192.0.2.14", "/.env", 404, 20);
    assert!(
        matches!(
            out,
            HttpOutcome::Banned {
                rule: HttpRule::Notfound,
                uri: None,
                ..
            }
        ),
        "{out:?}"
    );
    assert_eq!(r.bans.borrow().len(), 1);
}

#[test]
fn log_badpath_alone_would_ban_and_advances_notfound() {
    let mut r = rig(LOG_BADPATH, "");
    let out = hit(&mut r, "192.0.2.15", "/.env", 404, 0);
    assert!(matches!(
        out,
        HttpOutcome::WouldBan {
            rule: HttpRule::Badpath,
            ..
        }
    ));
    // /.env の分が 1 本として数えられているので、あと 18 本で 19 本目に達する。
    for i in 1..19 {
        let out = hit(&mut r, "192.0.2.15", &format!("/x{i}"), 404, i);
        assert_eq!(out, HttpOutcome::Counted(ip("192.0.2.15")));
    }
    let out = hit(&mut r, "192.0.2.15", "/x19", 404, 19);
    assert!(matches!(
        out,
        HttpOutcome::Banned {
            rule: HttpRule::Notfound,
            ..
        }
    ));
}

#[test]
fn ok_page_and_disabled_notfound_are_no_match() {
    let mut r = rig("", "");
    assert_eq!(hit(&mut r, "192.0.2.5", "/", 200, 0), HttpOutcome::NoMatch);
    let mut r = rig("[http.notfound]\nenabled = false\n", "");
    assert_eq!(hit(&mut r, "192.0.2.5", "/x", 404, 0), HttpOutcome::NoMatch);
}

#[test]
fn badpath_line_is_one_ban_even_if_both_reach_threshold() {
    let mut r = rig("[http.notfound]\nmaxretry = 2\n", "");
    // notfound は 1 本目 (Counted)。次の /.env は badpath で 1 回だけブロック。
    hit(&mut r, "192.0.2.6", "/a", 404, 0);
    let out = hit(&mut r, "192.0.2.6", "/.env", 404, 1);
    assert!(matches!(
        out,
        HttpOutcome::Banned {
            rule: HttpRule::Badpath,
            ..
        }
    ));
    assert_eq!(r.bans.borrow().len(), 1);
}

#[test]
fn ignored_ip_is_not_banned() {
    let mut r = rig("", "ignoreip = [\"192.0.2.7\"]");
    let out = hit(&mut r, "192.0.2.7", "/.env", 404, 0);
    assert_eq!(out, HttpOutcome::Ignored(ip("192.0.2.7")));
    assert!(r.bans.borrow().is_empty());
}

#[test]
fn log_mode_rule_would_ban_and_leaves_no_trace() {
    // 200 で返る /.env にして、notfound に数えられないようにする。
    let mut r = rig(
        &format!("{RECIDIVE}[http.badpath]\nmode = \"log\"\n[http.notfound]\nmaxretry = 2\n"),
        "",
    );
    for i in 0..3 {
        let out = hit(&mut r, "192.0.2.8", "/.env", 200, i * 400);
        assert_eq!(
            out,
            HttpOutcome::WouldBan {
                ip: ip("192.0.2.8"),
                rule: HttpRule::Badpath,
                bantime: secs(300),
                uri: Some("/.env".into()),
            }
        );
    }
    assert!(r.bans.borrow().is_empty());
    assert_eq!(r.ledger.borrow().end_of(ip("192.0.2.8")), None);
    // WouldBan は recidive に数えないので、nft のルールの 1 回目は長期にならない。
    hit(&mut r, "192.0.2.8", "/a", 404, 2000);
    let out = hit(&mut r, "192.0.2.8", "/b", 404, 2001);
    assert!(matches!(
        out,
        HttpOutcome::Banned {
            rule: HttpRule::Notfound,
            long: false,
            ..
        }
    ));
}

#[test]
fn recidive_makes_third_ban_long() {
    let mut r = rig(&format!("{RECIDIVE}[http.notfound]\nmaxretry = 2\n"), "");
    let c = "192.0.2.9";
    let first = hit(&mut r, c, "/.env", 404, 0);
    assert!(matches!(first, HttpOutcome::Banned { long: false, .. }));
    hit(&mut r, c, "/a", 404, 400);
    let second = hit(&mut r, c, "/b", 404, 401);
    assert!(matches!(
        second,
        HttpOutcome::Banned {
            rule: HttpRule::Notfound,
            long: false,
            ..
        }
    ));
    let third = hit(&mut r, c, "/.env", 404, 800);
    assert!(matches!(
        third,
        HttpOutcome::Banned {
            rule: HttpRule::Badpath,
            long: true,
            bantime,
            ..
        } if bantime == secs(86400)
    ));
}

#[test]
fn longer_existing_ban_gives_already_banned() {
    let mut r = rig("", "");
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + 86_400);
    r.ledger.borrow_mut().restore(ip("192.0.2.10"), Some(until));
    let out = hit(&mut r, "192.0.2.10", "/.env", 404, 0);
    assert_eq!(
        out,
        HttpOutcome::AlreadyBanned {
            ip: ip("192.0.2.10"),
            rule: HttpRule::Badpath,
            until,
        }
    );
    assert!(r.bans.borrow().is_empty());
}

#[test]
fn non_access_logger_is_no_match() {
    let mut r = rig("", "");
    let msg = access("tls.handshake", "192.0.2.11", "/.env", 404);
    assert_eq!(
        r.engine.handle(&entry(msg, 0)).unwrap(),
        HttpOutcome::NoMatch
    );
}

#[test]
fn failed_ban_restores_ledger() {
    let mut r = rig("", "");
    r.fail_ban.set(true);
    let msg = access("http.log.access.log0", "192.0.2.12", "/.env", 404);
    assert!(r.engine.handle(&entry(msg, 0)).is_err());
    assert_eq!(r.ledger.borrow().end_of(ip("192.0.2.12")), None);
    // 戻っているので、次は AlreadyBanned にならずブロックできる。
    r.fail_ban.set(false);
    let out = hit(&mut r, "192.0.2.12", "/.env", 404, 1);
    assert!(matches!(out, HttpOutcome::Banned { .. }));
}

#[test]
fn failed_ban_is_not_counted_toward_recidive() {
    let mut r = rig("[http.recidive]\nmaxbans = 2\n", "");
    r.fail_ban.set(true);
    let msg = access("http.log.access.log0", "192.0.2.13", "/.env", 404);
    assert!(r.engine.handle(&entry(msg, 0)).is_err());
    r.fail_ban.set(false);
    // 失敗を数えていれば、これが 2 回目として長期になってしまう。
    let ok = hit(&mut r, "192.0.2.13", "/.env", 404, 400);
    assert!(matches!(ok, HttpOutcome::Banned { long: false, .. }));
    let again = hit(&mut r, "192.0.2.13", "/.env", 404, 800);
    assert!(matches!(again, HttpOutcome::Banned { long: true, .. }));
}

fn is_already(out: &HttpOutcome) -> bool {
    matches!(out, HttpOutcome::AlreadyBanned { .. })
}

#[test]
fn badpath_scan_during_a_ban_is_one_ban() {
    let mut r = rig(RECIDIVE, "");
    let a = "192.0.2.50";
    let first = hit(&mut r, a, "/.env", 404, 0);
    assert!(matches!(first, HttpOutcome::Banned { long: false, .. }));
    // 掛かったブロックが続いている間の行は、延ばさず、nft にも送らず、常習犯にも数えない。
    for t in [1, 2] {
        let out = hit(&mut r, a, "/.git/config", 404, t);
        assert!(is_already(&out), "t+{t}: {out:?}");
    }
    assert_eq!(r.bans.borrow().len(), 1);
    // 終わりは最初のブロックのまま (延びていない)。
    assert_eq!(
        r.ledger.borrow().end_of(ip(a)),
        Some(entry(String::new(), 0).time + secs(300))
    );
}

#[test]
fn bans_after_the_end_count_toward_recidive() {
    let mut r = rig(RECIDIVE, "");
    let a = "192.0.2.51";
    for t in [0, 1, 2] {
        hit(&mut r, a, "/.env", 404, t);
    }
    let second = hit(&mut r, a, "/.env", 404, 301);
    assert!(matches!(second, HttpOutcome::Banned { long: false, .. }));
    assert!(is_already(&hit(&mut r, a, "/.env", 404, 302)));
    let third = hit(&mut r, a, "/.env", 404, 602);
    assert!(matches!(third, HttpOutcome::Banned { long: true, .. }));
    let times: Vec<_> = r.bans.borrow().iter().map(|(_, d)| *d).collect();
    assert_eq!(times, vec![secs(300), secs(300), secs(86400)]);
}
