//! journalctl の JSON 出力から sshd のログ行を読む。

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// journalctl が終わった (または起動できなかった) あと、起動し直すまでの待ち時間。
const RESTART_DELAY: Duration = Duration::from_secs(5);

/// journal の 1 行分。
#[derive(Debug, Clone, PartialEq)]
pub struct LogEntry {
    pub time: SystemTime,
    pub message: String,
    pub cursor: Option<String>,
}

/// `journalctl -o json` の 1 行を読む。壊れた行や、時刻か本文が無い行は `None`。
pub fn parse_journal_json(line: &str) -> Option<LogEntry> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let micros_text = value.get("__REALTIME_TIMESTAMP")?.as_str()?;
    if micros_text.is_empty() || !micros_text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let micros: u64 = micros_text.parse().ok()?;
    let message = match value.get("MESSAGE")? {
        serde_json::Value::String(s) => s.clone(),
        // journald は本文が UTF-8 でないとき、バイト値の配列で出す
        serde_json::Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            String::from_utf8_lossy(&bytes?).into_owned()
        }
        _ => return None,
    };
    let cursor = value
        .get("__CURSOR")
        .and_then(|c| c.as_str())
        .map(str::to_owned);
    Some(LogEntry {
        time: UNIX_EPOCH.checked_add(Duration::from_micros(micros))?,
        message,
        cursor,
    })
}

/// journalctl に渡す引数を組み立てる。カーソルがあれば続きから、無ければ findtime 分さかのぼる。
pub fn journalctl_args(
    matches: &[String],
    findtime: Duration,
    after_cursor: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = ["-f", "-o", "json", "--no-pager"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.push(match after_cursor {
        Some(c) => format!("--after-cursor={c}"),
        None => format!("--since=-{}s", findtime.as_secs()),
    });
    args.extend(matches.iter().cloned());
    args
}

/// journalctl を起動して 1 行ずつ `tx` に送るスレッドを始める。
///
/// journalctl が終わったら理由を stderr に出し、5 秒待って最後のカーソルから起動し直す。
/// `tx` の送信に失敗したら (受け手が終わったら) スレッドを終える。
///
/// 送る行には `tag` を添える。複数の jail が 1 つのチャネルを共有するとき、どの jail の行かを区別する。
pub fn spawn_reader<T: Copy + Send + 'static>(
    journalctl: PathBuf,
    matches: Vec<String>,
    findtime: Duration,
    tag: T,
    tx: Sender<(T, LogEntry)>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut cursor: Option<String> = None;
        let mut first = true;
        loop {
            let args = journalctl_args(&matches, findtime, cursor.as_deref());
            match Command::new(&journalctl)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
            {
                Err(e) => {
                    eprintln!("journalctl ({}) を起動できない: {e}", journalctl.display());
                    // 最初の起動に失敗したら設定の誤りなので、tx を落として呼び出し側に知らせる。
                    if first {
                        return;
                    }
                }
                Ok(mut child) => {
                    first = false;
                    let Some(stdout) = child.stdout.take() else {
                        eprintln!("journalctl の標準出力を取れない");
                        let _ = child.kill();
                        let _ = child.wait();
                        thread::sleep(RESTART_DELAY);
                        continue;
                    };
                    let receiver_alive =
                        forward_lines(BufReader::new(stdout), tag, &tx, &mut cursor);
                    // 読み取りエラーで抜けた場合も、子が生きたままだと wait が戻らない。
                    let _ = child.kill();
                    if !receiver_alive {
                        let _ = child.wait();
                        return;
                    }
                    match child.wait() {
                        Ok(status) => eprintln!("journalctl が終了した ({status})。再起動する"),
                        Err(e) => eprintln!("journalctl の終了を待てない: {e}"),
                    }
                }
            }
            thread::sleep(RESTART_DELAY);
        }
    })
}

/// 行を読み切るまで `tx` に送る。送信に失敗したら `false`。
fn forward_lines<T: Copy>(
    mut reader: impl BufRead,
    tag: T,
    tx: &Sender<(T, LogEntry)>,
    cursor: &mut Option<String>,
) -> bool {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e) => {
                eprintln!("journalctl の出力を読めない: {e}");
                return true;
            }
        }
        let line = String::from_utf8_lossy(&buf);
        let Some(entry) = parse_journal_json(line.trim_end()) else {
            continue;
        };
        let seen = entry.cursor.clone();
        if tx.send((tag, entry)).is_err() {
            return false;
        }
        if seen.is_some() {
            *cursor = seen;
        }
    }
}
