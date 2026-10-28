//! 有効な jail を動かし、journal の行を受けて処理するメインのループ。

use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, SystemTime};

use crate::action::{BanAction, LogAction, NftAction};
use crate::config::{Config, Mode};
use crate::engine::{Engine, Outcome};
use crate::http_engine::HttpEngine;
use crate::journal::{LogEntry, spawn_reader};
use crate::ledger::{BanLedger, SharedLedger};
use crate::notify::{render_command, spawn_notify};
use crate::notify_args::{NotifyArgs, http_notify, sshd_notify};
use crate::report::{http_outcome_line, http_start_line, sshd_already_banned_line};

use std::cell::RefCell;
use std::rc::Rc;

/// 受信を待つ最長時間。超えるたびに古い記録を捨てる。
const RECV_TIMEOUT: Duration = Duration::from_secs(60);
/// この件数ごとに古い記録を捨てる。
const PRUNE_EVERY: u64 = 1000;

/// 行がどの jail の journal から来たか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JailId {
    Sshd,
    Http,
}

/// 有効な jail が 1 つも無いときは何もせず正常終了する。
pub fn run(config: &Config) -> Result<(), String> {
    let http_enabled = config.http.as_ref().is_some_and(|h| h.enabled);
    if !config.sshd.enabled && !http_enabled {
        println!("no jail is enabled; exiting");
        return Ok(());
    }
    match config.mode {
        Mode::Log => run_with(config, LogAction, LogAction),
        Mode::Nft => run_with(
            config,
            NftAction {
                config: config.nft.clone(),
            },
            NftAction {
                config: config.nft.clone(),
            },
        ),
    }
}

/// 起動時の 1 行に出す recidive の設定。無効なら `off`。
fn recidive_summary(config: &Config) -> String {
    match &config.sshd.recidive {
        None => "off".to_string(),
        Some(r) => format!(
            "{}/{}s/{}s",
            r.maxbans,
            r.findtime.as_secs(),
            r.bantime.as_secs()
        ),
    }
}

fn sshd_start_line(config: &Config) -> String {
    format!(
        "start mode={:?} maxretry={} findtime={}s bantime={}s recidive={} ignoreip={:?}",
        config.mode,
        config.sshd.maxretry,
        config.sshd.findtime.as_secs(),
        config.sshd.bantime.as_secs(),
        recidive_summary(config),
        config.ignoreip
    )
}

/// 通知コマンドを起動する。`on_ban` が空なら何もしない。
fn notify_ban(config: &Config, args: &NotifyArgs) {
    if config.notify.on_ban.is_empty() {
        return;
    }
    let argv = render_command(
        &config.notify.on_ban,
        args.ip,
        args.bantime,
        args.kind,
        args.jail,
        args.rule,
    );
    spawn_notify(&argv);
}

/// 2 つの engine は同じ型の action を 1 つずつ受け取る (nft の表の準備は 1 回だけ行う)。
fn run_with<A: BanAction>(config: &Config, sshd_action: A, http_action: A) -> Result<(), String> {
    // 設定の検証を先に済ませ、通ってから nft などを触る。
    if config.ignoreip.is_empty() {
        eprintln!("警告: ignoreip が空です。自分の接続元もブロックされる可能性があります");
    }
    let ledger: SharedLedger = Rc::new(RefCell::new(BanLedger::new()));
    // log モードの sshd は表を見ない (ブロックしないので)。
    let sshd_ledger = (config.mode == Mode::Nft).then(|| Rc::clone(&ledger));
    let mut sshd = if config.sshd.enabled {
        Some(Engine::new(config, sshd_action, sshd_ledger).map_err(|e| e.to_string())?)
    } else {
        None
    };
    let http_config = config.http.as_ref().filter(|h| h.enabled);
    let mut http = match http_config {
        Some(h) => Some(
            HttpEngine::new(h, &config.ignoreip, http_action, Rc::clone(&ledger))
                .map_err(|e| e.to_string())?,
        ),
        None => None,
    };
    // nft の表の準備は、どちらの action でも同じなので 1 回だけ。
    match (&sshd, &http) {
        (Some(e), _) => e.start(),
        (None, Some(h)) => h.start(),
        (None, None) => Ok(()),
    }
    .map_err(|e| e.to_string())?;
    if sshd.is_some() {
        println!("{}", sshd_start_line(config));
    }
    if let Some(h) = http_config {
        println!("{}", http_start_line(h));
    }

    let (tx, rx) = mpsc::channel();
    // スレッドは終了まで走り続けるので JoinHandle は使わない。
    if sshd.is_some() {
        spawn_jail_reader(
            config,
            config.sshd.journalmatch.clone(),
            config.sshd.findtime,
            JailId::Sshd,
            &tx,
        );
    }
    if let Some(h) = http_config {
        spawn_jail_reader(
            config,
            h.journalmatch.clone(),
            h.notfound.findtime,
            JailId::Http,
            &tx,
        );
    }
    drop(tx);

    let mut count = 0u64;
    loop {
        match rx.recv_timeout(RECV_TIMEOUT) {
            Ok((jail, entry)) => {
                match jail {
                    JailId::Sshd => {
                        if let Some(engine) = sshd.as_mut() {
                            handle_sshd(config, engine, &entry);
                        }
                    }
                    JailId::Http => {
                        if let Some(engine) = http.as_mut() {
                            handle_http(config, engine, &entry);
                        }
                    }
                }
                count += 1;
                if count.is_multiple_of(PRUNE_EVERY) {
                    prune_all(sshd.as_mut(), http.as_mut(), &ledger);
                }
            }
            Err(RecvTimeoutError::Timeout) => prune_all(sshd.as_mut(), http.as_mut(), &ledger),
            Err(RecvTimeoutError::Disconnected) => {
                return Err("journal の読み取りスレッドが終了した".to_string());
            }
        }
    }
}

fn spawn_jail_reader(
    config: &Config,
    matches: Vec<String>,
    findtime: Duration,
    jail: JailId,
    tx: &Sender<(JailId, LogEntry)>,
) {
    let _reader = spawn_reader(
        config.nft.journalctl_path.clone(),
        matches,
        findtime,
        jail,
        tx.clone(),
    );
}

fn prune_all<A: BanAction>(
    sshd: Option<&mut Engine<A>>,
    http: Option<&mut HttpEngine<A>>,
    ledger: &SharedLedger,
) {
    let now = SystemTime::now();
    if let Some(e) = sshd {
        e.prune(now);
    }
    if let Some(e) = http {
        e.prune(now);
    }
    ledger.borrow_mut().prune(now);
}

fn handle_sshd<A: BanAction>(config: &Config, engine: &mut Engine<A>, entry: &LogEntry) {
    match engine.handle(entry) {
        Ok(outcome @ (Outcome::Banned(ip) | Outcome::LongBanned(ip))) => {
            let long = matches!(outcome, Outcome::LongBanned(_));
            let bantime = engine.bantime_of(&outcome).unwrap_or(config.sshd.bantime);
            // log モードでは LogAction が `would ban` を出すので、二重に出さない。
            if config.mode == Mode::Nft {
                let note = if long { " (recidive)" } else { "" };
                println!("ban {ip} for {}s{note}", bantime.as_secs());
            }
            // 通知は mode に関係なく行う (log モードでも動作を確かめられる)。
            if let Some(args) = sshd_notify(&outcome, bantime) {
                notify_ban(config, &args);
            }
        }
        Ok(Outcome::AlreadyBanned(ip, until)) => {
            println!("{}", sshd_already_banned_line(ip, until));
        }
        Ok(Outcome::Ignored(ip)) => println!("ignored {ip}"),
        Ok(_) => {}
        Err(e) => eprintln!("ブロックに失敗: {e}"),
    }
}

fn handle_http<A: BanAction>(config: &Config, engine: &mut HttpEngine<A>, entry: &LogEntry) {
    let outcome = match engine.handle(entry) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ブロックに失敗: {e}");
            return;
        }
    };
    if let Some(line) = http_outcome_line(&outcome) {
        println!("{line}");
    }
    // 通知は mode に関係なく行う。
    if let Some(args) = http_notify(&outcome) {
        notify_ban(config, &args);
    }
}
