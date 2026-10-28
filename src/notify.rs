//! ブロック時の通知コマンドの組み立てと起動。

use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 雛形の各要素の `{ip}`、`{bantime}` (秒の整数)、`{kind}` (ブロックの種類)、
/// `{jail}` (ブロックした jail 名)、`{rule}` (ブロックの理由になった規則) を置き換える。
/// 他の `{...}` はそのまま。
pub fn render_command(
    template: &[String],
    ip: IpAddr,
    bantime: Duration,
    kind: &str,
    jail: &str,
    rule: &str,
) -> Vec<String> {
    let ip = ip.to_canonical().to_string();
    let secs = bantime.as_secs().to_string();
    template
        .iter()
        .map(|arg| {
            arg.replace("{ip}", &ip)
                .replace("{bantime}", &secs)
                .replace("{kind}", kind)
                .replace("{jail}", jail)
                .replace("{rule}", rule)
        })
        .collect()
}

/// 通知コマンドを待つ最長時間。超えたら強制終了する。
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(60);
/// 終了を確かめる間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// argv[0] をシェルを通さずに起動する。完了は待たない。
///
/// ゾンビを残さないよう別スレッドで待ち、`NOTIFY_TIMEOUT` を過ぎたら kill する。
/// 起動に失敗しても stderr に 1 行出すだけで、ブロック自体は妨げない。
/// argv が空なら何もしない。
pub fn spawn_notify(argv: &[String]) {
    spawn_notify_with_timeout(argv, NOTIFY_TIMEOUT);
}

/// `spawn_notify` の待ち時間を指定できる版 (テスト用)。
#[doc(hidden)]
pub fn spawn_notify_with_timeout(argv: &[String], timeout: Duration) {
    let Some((program, args)) = argv.split_first() else {
        return;
    };
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(e) => {
            eprintln!("通知コマンドを起動できません: {program}: {e}");
            return;
        }
    };
    // スレッドの作成に失敗したら子を失うので、共有して取り戻せるようにする。
    let shared = Arc::new(Mutex::new(Some(child)));
    let for_thread = Arc::clone(&shared);
    let name = program.clone();
    let waiter = std::thread::Builder::new()
        .name("notify-wait".to_string())
        .spawn(move || {
            let child = for_thread.lock().ok().and_then(|mut slot| slot.take());
            if let Some(child) = child {
                wait_or_kill(child, &name, timeout);
            }
        });
    if let Err(e) = waiter {
        eprintln!("通知コマンドの待機スレッドを作れません: {e}");
        let child = shared.lock().ok().and_then(|mut slot| slot.take());
        if let Some(child) = child {
            kill_and_reap(child, program);
        }
    }
}

fn wait_or_kill(mut child: Child, program: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    eprintln!("通知コマンドが失敗しました: {program}: {status}");
                }
                return;
            }
            Ok(None) if Instant::now() >= deadline => {
                eprintln!(
                    "通知コマンドが {}s で終わらないため止めます: {program}",
                    timeout.as_secs()
                );
                kill_and_reap(child, program);
                return;
            }
            Ok(None) => std::thread::sleep(POLL_INTERVAL.min(timeout)),
            Err(e) => {
                eprintln!("通知コマンドの終了を待てません: {program}: {e}");
                kill_and_reap(child, program);
                return;
            }
        }
    }
}

fn kill_and_reap(mut child: Child, program: &str) {
    if let Err(e) = child.kill() {
        eprintln!("通知コマンドを止められません: {program}: {e}");
    }
    if let Err(e) = child.wait() {
        eprintln!("通知コマンドの終了を待てません: {program}: {e}");
    }
}
