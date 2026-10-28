//! Engine の振る舞いのテスト。ban は記録用の BanAction で受ける。

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use fail2ban_rs::action::{ActionError, BanAction};
use fail2ban_rs::config::{Config, parse_config};
use fail2ban_rs::engine::{Engine, Outcome};
use fail2ban_rs::journal::LogEntry;
use fail2ban_rs::ledger::SharedLedger;

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
    let e = Engine::new(config, Recorder::new(bans.clone()), None).unwrap();
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
    assert!(Engine::new(&config, rec, None).is_err());
    assert_eq!(starts.get(), 0);
}

#[test]
fn engine_start_calls_action_start() {
    let rec = Recorder::new(Rc::default());
    let starts = rec.starts.clone();
    let e = Engine::new(&parse_config("").unwrap(), rec, None).unwrap();
    assert_eq!(starts.get(), 0);
    e.start().unwrap();
    assert_eq!(starts.get(), 1);
}

#[test]
fn ban_failure_is_returned() {
    let mut rec = Recorder::new(Rc::default());
    rec.fail_ban = true;
    let mut e = Engine::new(&parse_config("").unwrap(), rec, None).unwrap();
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

const RECIDIVE_CONFIG: &str = "[sshd]\nmaxretry = 3\nbantime = \"300s\"\n[sshd.recidive]";
const IP: &str = "192.0.2.50";
const MIN: u64 = 60;
const HOUR: u64 = 3600;

/// start 秒から 3 回失敗させ、最後の結果を返す。
fn burst<A: BanAction>(e: &mut Engine<A>, host: &str, start: u64) -> Outcome {
    let msg = failed(host);
    let mut last = Outcome::NoMatch;
    for i in 0..3 {
        last = e.handle(&entry(&msg, start + i)).unwrap();
    }
    last
}

fn secs(items: &[u64]) -> Vec<Duration> {
    items.iter().map(|s| Duration::from_secs(*s)).collect()
}

fn ban_times(bans: &Bans) -> Vec<Duration> {
    bans.borrow().iter().map(|(_, t)| *t).collect()
}

#[test]
fn third_ban_within_findtime_is_long() {
    let (mut e, bans) = engine(&parse_config(RECIDIVE_CONFIG).unwrap());
    let ip: IpAddr = IP.parse().unwrap();
    assert_eq!(burst(&mut e, IP, 0), Outcome::Banned(ip));
    assert_eq!(burst(&mut e, IP, 20 * MIN), Outcome::Banned(ip));
    assert_eq!(burst(&mut e, IP, 40 * MIN), Outcome::LongBanned(ip));
    assert_eq!(ban_times(&bans), secs(&[300, 300, 86400]));
}

#[test]
fn count_restarts_after_a_long_ban() {
    let (mut e, bans) = engine(&parse_config(RECIDIVE_CONFIG).unwrap());
    let ip: IpAddr = IP.parse().unwrap();
    for i in 0..3 {
        burst(&mut e, IP, i * 20 * MIN);
    }
    assert_eq!(burst(&mut e, IP, 3 * HOUR), Outcome::Banned(ip));
    assert_eq!(ban_times(&bans), secs(&[300, 300, 86400, 300]));
}

#[test]
fn bans_spread_beyond_findtime_stay_short() {
    let (mut e, bans) = engine(&parse_config(RECIDIVE_CONFIG).unwrap());
    let ip: IpAddr = IP.parse().unwrap();
    assert_eq!(burst(&mut e, IP, 0), Outcome::Banned(ip));
    assert_eq!(burst(&mut e, IP, 20 * MIN), Outcome::Banned(ip));
    // 1 つめのブロックから 1 日より後。
    assert_eq!(burst(&mut e, IP, 24 * HOUR + 30 * MIN), Outcome::Banned(ip));
    assert_eq!(ban_times(&bans), secs(&[300, 300, 300]));
}

#[test]
fn without_recidive_every_ban_is_short() {
    let config = parse_config("[sshd]\nmaxretry = 3\nbantime = \"300s\"").unwrap();
    let (mut e, bans) = engine(&config);
    let ip: IpAddr = IP.parse().unwrap();
    for i in 0..5 {
        assert_eq!(burst(&mut e, IP, i * 20 * MIN), Outcome::Banned(ip));
    }
    assert_eq!(ban_times(&bans), secs(&[300; 5]));
}

#[test]
fn recidive_counts_each_ip_separately() {
    let (mut e, _) = engine(&parse_config(RECIDIVE_CONFIG).unwrap());
    let a: IpAddr = IP.parse().unwrap();
    let b: IpAddr = "192.0.2.51".parse().unwrap();
    burst(&mut e, IP, 0);
    burst(&mut e, "192.0.2.51", 10 * MIN);
    burst(&mut e, IP, 20 * MIN);
    assert_eq!(burst(&mut e, "192.0.2.51", 30 * MIN), Outcome::Banned(b));
    assert_eq!(burst(&mut e, IP, 40 * MIN), Outcome::LongBanned(a));
}

#[test]
fn ignored_ip_never_gets_a_long_ban() {
    let (mut e, bans) = engine(&parse_config(RECIDIVE_CONFIG).unwrap());
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    for i in 0..5 {
        let o = burst(&mut e, "127.0.0.1", i * 20 * MIN);
        assert_eq!(o, Outcome::Ignored(ip));
    }
    assert!(bans.borrow().is_empty());
}

#[test]
fn bantime_of_matches_the_outcome() {
    let (e, _) = engine(&parse_config(RECIDIVE_CONFIG).unwrap());
    let ip: IpAddr = IP.parse().unwrap();
    let short = Some(Duration::from_secs(300));
    let long = Some(Duration::from_secs(86400));
    assert_eq!(e.bantime_of(&Outcome::Banned(ip)), short);
    assert_eq!(e.bantime_of(&Outcome::LongBanned(ip)), long);
    assert_eq!(e.bantime_of(&Outcome::Counted(ip)), None);
}

#[test]
fn prune_forgets_old_bans() {
    let (mut e, bans) = engine(&parse_config(RECIDIVE_CONFIG).unwrap());
    let ip: IpAddr = IP.parse().unwrap();
    burst(&mut e, IP, 0);
    burst(&mut e, IP, 20 * MIN);
    e.prune(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + 3 * 86400));
    assert_eq!(burst(&mut e, IP, 40 * MIN), Outcome::Banned(ip));
    assert_eq!(ban_times(&bans), secs(&[300, 300, 300]));
}

fn ledger_engine() -> (Engine<Recorder>, Bans, SharedLedger) {
    let bans: Bans = Rc::default();
    let ledger: SharedLedger = Rc::default();
    let config = parse_config(RECIDIVE_CONFIG).unwrap();
    let e = Engine::new(&config, Recorder::new(bans.clone()), Some(ledger.clone())).unwrap();
    (e, bans, ledger)
}

fn at(secs: u64) -> SystemTime {
    entry("", secs).time
}

#[test]
fn ban_is_skipped_while_a_longer_ban_is_running() {
    let (mut e, bans, ledger) = ledger_engine();
    let ip: IpAddr = IP.parse().unwrap();
    let day = Duration::from_secs(24 * HOUR);
    ledger.borrow_mut().admit(ip, at(0), day).unwrap();
    assert_eq!(
        burst(&mut e, IP, 0),
        Outcome::AlreadyBanned(ip, at(0) + day)
    );
    assert!(bans.borrow().is_empty());
}

#[test]
fn already_banned_is_not_counted_toward_recidive() {
    let (mut e, bans, ledger) = ledger_engine();
    let ip: IpAddr = IP.parse().unwrap();
    // 1 時間で終わるブロックが先にあるので、t=2 秒の閾値到達は AlreadyBanned になる。
    ledger
        .borrow_mut()
        .admit(ip, at(0), Duration::from_secs(HOUR))
        .unwrap();
    assert!(matches!(burst(&mut e, IP, 0), Outcome::AlreadyBanned(..)));
    // ブロックが終わった後に 3 回 (すべて 24 時間以内)。数えられていたら 2 回目で長期になる。
    let base = 2 * HOUR;
    assert_eq!(burst(&mut e, IP, base), Outcome::Banned(ip));
    assert_eq!(burst(&mut e, IP, base + 20 * MIN), Outcome::Banned(ip));
    assert_eq!(burst(&mut e, IP, base + 40 * MIN), Outcome::LongBanned(ip));
    assert_eq!(ban_times(&bans), secs(&[300, 300, 86400]));
}

#[test]
fn failed_ban_leaves_no_ledger_entry() {
    let ledger: SharedLedger = Rc::default();
    let config = parse_config(RECIDIVE_CONFIG).unwrap();
    let mut rec = Recorder::new(Rc::default());
    rec.fail_ban = true;
    let mut failing = Engine::new(&config, rec, Some(ledger.clone())).unwrap();
    let ip: IpAddr = IP.parse().unwrap();
    let msg = failed(IP);
    for i in 0..2 {
        failing.handle(&entry(&msg, i)).unwrap();
    }
    assert!(failing.handle(&entry(&msg, 2)).is_err());
    // 同じ表を使う、ブロックに成功する Engine。0 秒から始めると終わりは失敗時と同じ 302 秒で、
    // 表が戻っていなければ AlreadyBanned になる。
    let bans: Bans = Rc::default();
    let mut working =
        Engine::new(&config, Recorder::new(bans.clone()), Some(ledger.clone())).unwrap();
    assert_eq!(burst(&mut working, IP, 0), Outcome::Banned(ip));
    assert_eq!(ban_times(&bans), secs(&[300]));
}

#[test]
fn ledger_records_the_end_of_each_ban() {
    let (mut e, _, ledger) = ledger_engine();
    let ip: IpAddr = IP.parse().unwrap();
    burst(&mut e, IP, 0);
    // 表には 3 回目の失敗 (2 秒後) + 300 秒が入る。これより短く終わるブロックは断られる。
    let ends = at(2) + Duration::from_secs(300);
    assert_eq!(
        ledger
            .borrow_mut()
            .admit(ip, at(2), Duration::from_secs(299)),
        Err(ends)
    );
}

/// 最初の `failures` 回の ban だけ失敗する BanAction。
struct Flaky {
    failures: Cell<u32>,
    bans: Bans,
}

impl BanAction for Flaky {
    fn start(&self) -> Result<(), ActionError> {
        Ok(())
    }
    fn ban(&self, ip: IpAddr, bantime: Duration) -> Result<(), ActionError> {
        if self.failures.get() > 0 {
            self.failures.set(self.failures.get() - 1);
            return Err(ActionError::NftFailed {
                status: "exit 1".into(),
                stderr: "boom".into(),
            });
        }
        self.bans.borrow_mut().push((ip, bantime));
        Ok(())
    }
}

#[test]
fn failed_ban_is_not_counted_toward_recidive() {
    let bans: Bans = Rc::default();
    let action = Flaky {
        failures: Cell::new(1),
        bans: bans.clone(),
    };
    let config = parse_config(RECIDIVE_CONFIG).unwrap();
    let mut e = Engine::new(&config, action, None).unwrap();
    let ip: IpAddr = IP.parse().unwrap();
    let msg = failed(IP);
    for i in 0..2 {
        e.handle(&entry(&msg, i)).unwrap();
    }
    assert!(e.handle(&entry(&msg, 2)).is_err());
    // 失敗した分が数えられていたら、2 回目の成功で長期になる。
    assert_eq!(burst(&mut e, IP, 20 * MIN), Outcome::Banned(ip));
    assert_eq!(burst(&mut e, IP, 40 * MIN), Outcome::Banned(ip));
    assert_eq!(burst(&mut e, IP, 60 * MIN), Outcome::LongBanned(ip));
    assert_eq!(ban_times(&bans), secs(&[300, 300, 86400]));
}

#[test]
fn threshold_during_a_running_ban_does_not_extend_it() {
    let (mut e, bans, ledger) = ledger_engine();
    let ip: IpAddr = IP.parse().unwrap();
    assert_eq!(burst(&mut e, IP, 0), Outcome::Banned(ip));
    let end = ledger.borrow().end_of(ip).unwrap();
    // ブロックの途中で再び閾値に達しても、延ばさず、送らない。
    assert_eq!(burst(&mut e, IP, 60), Outcome::AlreadyBanned(ip, end));
    assert_eq!(ledger.borrow().end_of(ip), Some(end));
    assert_eq!(ban_times(&bans), secs(&[300]));
}
