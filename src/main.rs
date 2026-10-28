//! fail2ban-rs のバイナリ。サブコマンド: run / test-filter / check-config。

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, SystemTime};

use clap::{Parser, Subcommand};
use fail2ban_rs::action::{BanAction, LogAction, NftAction};
use fail2ban_rs::config::{Config, Mode, load_config};
use fail2ban_rs::engine::{Engine, Outcome};
use fail2ban_rs::filter::SshdFilter;
use fail2ban_rs::journal::spawn_reader;
use fail2ban_rs::notify::{render_command, spawn_notify};

const DEFAULT_CONFIG: &str = "/etc/fail2ban-rs/config.toml";
/// 受信を待つ最長時間。超えるたびに古い記録を捨てる。
const RECV_TIMEOUT: Duration = Duration::from_secs(60);
/// この件数ごとに古い記録を捨てる。
const PRUNE_EVERY: u64 = 1000;

#[derive(Parser)]
#[command(version, about = "sshd の認証失敗を journal から読んでブロックする")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// journal を監視してブロックする
    Run {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// ログの行をフィルタに通して結果を表示する
    TestFilter {
        /// 読むファイル (省略時は標準入力)
        file: Option<PathBuf>,
    },
    /// 設定を検証して実際に使う値を表示する
    CheckConfig {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Run { config } => run(&config),
        Command::TestFilter { file } => test_filter(file),
        Command::CheckConfig { config } => check_config(&config),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn check_config(path: &Path) -> Result<(), String> {
    let config = load_config(path).map_err(|e| e.to_string())?;
    println!("{config:#?}");
    Ok(())
}

fn test_filter(file: Option<PathBuf>) -> Result<(), String> {
    let filter = SshdFilter::new().map_err(|e| e.to_string())?;
    let reader: Box<dyn BufRead> = match file {
        Some(p) if p != Path::new("-") => Box::new(BufReader::new(
            File::open(&p).map_err(|e| format!("{} を開けません: {e}", p.display()))?,
        )),
        _ => Box::new(io::stdin().lock()),
    };
    let (mut total, mut matched) = (0u64, 0u64);
    for line in reader.lines() {
        let line = line.map_err(|e| format!("読み込みに失敗: {e}"))?;
        total += 1;
        let Some(m) = filter.check(&line) else {
            continue;
        };
        matched += 1;
        if m.nofail {
            println!("nofail {}", m.host);
        } else {
            println!("fail {} user={}", m.host, m.user.as_deref().unwrap_or(""));
        }
    }
    println!("matched {matched}/{total} lines");
    Ok(())
}

fn run(path: &Path) -> Result<(), String> {
    let config = load_config(path).map_err(|e| e.to_string())?;
    if !config.sshd.enabled {
        println!("sshd jail is disabled; exiting");
        return Ok(());
    }
    match config.mode {
        Mode::Log => run_with(&config, LogAction),
        Mode::Nft => run_with(
            &config,
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

fn run_with<A: BanAction>(config: &Config, action: A) -> Result<(), String> {
    // 設定の検証を先に済ませ、通ってから nft などを触る。
    if config.ignoreip.is_empty() {
        eprintln!("警告: ignoreip が空です。自分の接続元もブロックされる可能性があります");
    }
    let mut engine = Engine::new(config, action, None).map_err(|e| e.to_string())?;
    engine.start().map_err(|e| e.to_string())?;
    println!(
        "start mode={:?} maxretry={} findtime={}s bantime={}s recidive={} ignoreip={:?}",
        config.mode,
        config.sshd.maxretry,
        config.sshd.findtime.as_secs(),
        config.sshd.bantime.as_secs(),
        recidive_summary(config),
        config.ignoreip
    );
    let (tx, rx) = mpsc::channel();
    // スレッドは終了まで走り続けるので JoinHandle は使わない。
    let _reader = spawn_reader(
        config.nft.journalctl_path.clone(),
        config.sshd.journalmatch.clone(),
        config.sshd.findtime,
        tx,
    );
    let mut count = 0u64;
    loop {
        match rx.recv_timeout(RECV_TIMEOUT) {
            Ok(entry) => {
                match engine.handle(&entry) {
                    Ok(outcome @ (Outcome::Banned(ip) | Outcome::LongBanned(ip))) => {
                        let long = matches!(outcome, Outcome::LongBanned(_));
                        let bantime = engine.bantime_of(&outcome).unwrap_or(config.sshd.bantime);
                        // log モードでは LogAction が `would ban` を出すので、二重に出さない。
                        if config.mode == Mode::Nft {
                            let note = if long { " (recidive)" } else { "" };
                            println!("ban {ip} for {}s{note}", bantime.as_secs());
                        }
                        // 通知は mode に関係なく行う (log モードでも動作を確かめられる)。
                        if !config.notify.on_ban.is_empty() {
                            let kind = if long { "長期" } else { "通常" };
                            let argv = render_command(&config.notify.on_ban, ip, bantime, kind);
                            spawn_notify(&argv);
                        }
                    }
                    Ok(Outcome::Ignored(ip)) => println!("ignored {ip}"),
                    Ok(_) => {}
                    Err(e) => eprintln!("ブロックに失敗: {e}"),
                }
                count += 1;
                if count.is_multiple_of(PRUNE_EVERY) {
                    engine.prune(SystemTime::now());
                }
            }
            Err(RecvTimeoutError::Timeout) => engine.prune(SystemTime::now()),
            Err(RecvTimeoutError::Disconnected) => {
                return Err("journal の読み取りスレッドが終了した".to_string());
            }
        }
    }
}
