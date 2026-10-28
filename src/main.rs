//! fail2ban-rs のバイナリ。サブコマンド: run / test-filter / check-config。

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use fail2ban_rs::config::load_config;
use fail2ban_rs::daemon;
use fail2ban_rs::filter::{BadPaths, SshdFilter, parse_access};
use fail2ban_rs::report::sanitize_uri;

const DEFAULT_CONFIG: &str = "/etc/fail2ban-rs/config.toml";

#[derive(Parser)]
#[command(version, about = "sshd の認証失敗を journal から読んでブロックする")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// test-filter で試す jail の種類。
#[derive(Clone, Copy, ValueEnum)]
enum JailKind {
    Sshd,
    Http,
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
        /// 試す jail (sshd は journal の行、http は Caddy の JSON)
        #[arg(long, value_enum, default_value = "sshd")]
        jail: JailKind,
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
        Command::TestFilter { jail, file } => test_filter(jail, file),
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

fn test_filter(jail: JailKind, file: Option<PathBuf>) -> Result<(), String> {
    let reader: Box<dyn BufRead> = match file {
        Some(p) if p != Path::new("-") => Box::new(BufReader::new(
            File::open(&p).map_err(|e| format!("{} を開けません: {e}", p.display()))?,
        )),
        _ => Box::new(io::stdin().lock()),
    };
    match jail {
        JailKind::Sshd => test_sshd(reader),
        JailKind::Http => test_http(reader),
    }
}

fn test_sshd(reader: Box<dyn BufRead>) -> Result<(), String> {
    let filter = SshdFilter::new().map_err(|e| e.to_string())?;
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

/// Caddy の JSON を 1 行ずつ、既知のパス / 404 / それ以外に分けて数える。
fn test_http(reader: Box<dyn BufRead>) -> Result<(), String> {
    let bad_paths = BadPaths::new(&[]).map_err(|e| e.to_string())?;
    let (mut total, mut badpath, mut notfound, mut other) = (0u64, 0u64, 0u64, 0u64);
    for line in reader.lines() {
        let line = line.map_err(|e| format!("読み込みに失敗: {e}"))?;
        total += 1;
        match parse_access(&line) {
            Some(e) if bad_paths.matches(&e.uri) => {
                badpath += 1;
                println!("badpath {} {}", e.ip, sanitize_uri(&e.uri));
            }
            Some(e) if e.status == 404 => {
                notfound += 1;
                println!("notfound {}", e.ip);
            }
            _ => {
                other += 1;
                println!("other");
            }
        }
    }
    println!("badpath {badpath} notfound {notfound} other {other} / {total} lines");
    Ok(())
}

fn run(path: &Path) -> Result<(), String> {
    let config = load_config(path).map_err(|e| e.to_string())?;
    daemon::run(&config)
}
