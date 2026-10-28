//! fail2ban-rs のバイナリ。サブコマンド: run / test-filter / check-config。

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use fail2ban_rs::config::load_config;
use fail2ban_rs::daemon;
use fail2ban_rs::filter::SshdFilter;

const DEFAULT_CONFIG: &str = "/etc/fail2ban-rs/config.toml";

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
    daemon::run(&config)
}
