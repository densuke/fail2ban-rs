//! Engine の振る舞いのテスト。ban は記録用の BanAction で受ける。

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use fail2ban_rs::action::{ActionError, BanAction};
use fail2ban_rs::config::{Config, parse_config};
use fail2ban_rs::engine::{Engine, Outcome};
use fail2ban_rs::journal::LogEntry;

type Bans = Rc<RefCell<Vec<(IpAddr, Duration)>>>;

struct Recorder {
    bans: Bans,
    starts: Rc<Cell<u32>>,
    fail_ban: bool,
}

impl Recorder {
    fn new(bans: Bans) -> Self {
        Self {
            bans,
            starts: Rc::default(),
            fail_ban: false,
        }
    }
}

impl BanAction for Recorder {
    fn start(&self) -> Result<(), ActionError> {
        self.starts.set(self.starts.get() + 1);
        Ok(())
    }
    fn ban(&self, ip: IpAddr, bantime: Duration) -> Result<(), ActionError> {
        if self.fail_ban {
            return Err(ActionError::NftFailed {
                status: "exit 1".into(),
                stderr: "boom".into(),
            });
        }
        self.bans.borrow_mut().push((ip, bantime));
        Ok(())
    }
}

fn engine(config: &Config) -> (Engine<Recorder>, Bans) {
    let bans: Bans = Rc::default();
    let e = Engine::new(config, Recorder::new(bans.clone())).unwrap();
    (e, bans)
}

fn entry(message: &str, secs: u64) -> LogEntry {
    LogEntry {
        time: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs),
        message: message.to_string(),
        cursor: None,
    }
}

fn failed(host: &str) -> String {
    format!("Failed password for root from {host} port 1 ssh2")
}

#[test]
fn bans_on_fifth_failure() {
    let (mut e, bans) = engine(&parse_config("").unwrap());
    let msg = failed("192.0.2.20");
    let outcomes: Vec<_> = (0..5).map(|i| e.handle(&entry(&msg, i)).unwrap()).collect();
    let ip: IpAddr = "192.0.2.20".parse().unwrap();
    assert!(outcomes[..4].iter().all(|o| *o == Outcome::Counted(ip)));
    assert_eq!(outcomes[4], Outcome::Banned(ip));
    assert_eq!(*bans.borrow(), vec![(ip, Duration::from_secs(600))]);
}

#[test]
fn ignored_ip_is_never_counted_or_banned() {
    let (mut e, bans) = engine(&parse_config("").unwrap());
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    for i in 0..10 {
        assert_eq!(
            e.handle(&entry(&failed("127.0.0.1"), i)).unwrap(),
            Outcome::Ignored(ip)
        );
    }
    assert!(bans.borrow().is_empty());
}

#[test]
fn mapped_ipv4_is_matched_against_ignoreip() {
    let config = parse_config("ignoreip = [\"192.168.11.0/24\"]").unwrap();
    let (mut e, bans) = engine(&config);
    let ip: IpAddr = "192.168.11.5".parse().unwrap();
    for i in 0..10 {
        let o = e.handle(&entry(&failed("::ffff:192.168.11.5"), i)).unwrap();
        assert_eq!(o, Outcome::Ignored(ip));
    }
    assert!(bans.borrow().is_empty());
}

#[test]
fn hostname_is_unresolvable() {
    let (mut e, _) = engine(&parse_config("").unwrap());
    let o = e.handle(&entry(&failed("example.com"), 0)).unwrap();
    assert_eq!(o, Outcome::Unresolvable("example.com".to_string()));
}

#[test]
fn success_line_is_no_match() {
    let (mut e, _) = engine(&parse_config("").unwrap());
    let msg = "Accepted publickey for densuke from 192.0.2.21 port 1 ssh2: RSA SHA256:x";
    assert_eq!(e.handle(&entry(msg, 0)).unwrap(), Outcome::NoMatch);
}

#[test]
fn slow_failures_outside_findtime_never_ban() {
    let (mut e, bans) = engine(&parse_config("").unwrap());
    let msg = failed("192.0.2.22");
    for i in 0..5 {
        let o = e.handle(&entry(&msg, i * 360)).unwrap();
        assert!(!matches!(o, Outcome::Banned(_)));
    }
    assert!(bans.borrow().is_empty());
}

#[test]
fn invalid_ignoreip_fails_before_action_start() {
    let config = parse_config("ignoreip = [\"not-an-ip\"]").unwrap();
    let rec = Recorder::new(Rc::default());
    let starts = rec.starts.clone();
    assert!(Engine::new(&config, rec).is_err());
    assert_eq!(starts.get(), 0);
}

#[test]
fn engine_start_calls_action_start() {
    let rec = Recorder::new(Rc::default());
    let starts = rec.starts.clone();
    let e = Engine::new(&parse_config("").unwrap(), rec).unwrap();
    assert_eq!(starts.get(), 0);
    e.start().unwrap();
    assert_eq!(starts.get(), 1);
}

#[test]
fn ban_failure_is_returned() {
    let mut rec = Recorder::new(Rc::default());
    rec.fail_ban = true;
    let mut e = Engine::new(&parse_config("").unwrap(), rec).unwrap();
    let msg = failed("192.0.2.40");
    for i in 0..4 {
        assert!(e.handle(&entry(&msg, i)).is_ok());
    }
    assert!(e.handle(&entry(&msg, 4)).is_err());
}

#[test]
fn nofail_line_is_no_match() {
    let (mut e, _) = engine(&parse_config("").unwrap());
    let msg = "Failed publickey for alice from 192.0.2.30 port 1 ssh2";
    assert_eq!(e.handle(&entry(msg, 0)).unwrap(), Outcome::NoMatch);
}
