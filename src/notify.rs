//! ブロック時の通知コマンドの組み立てと起動。

use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

/// 雛形の各要素の `{ip}` と `{bantime}` (秒の整数) を置き換える。他の `{...}` はそのまま。
pub fn render_command(template: &[String], ip: IpAddr, bantime: Duration) -> Vec<String> {
    let ip = ip.to_canonical().to_string();
    let secs = bantime.as_secs().to_string();
    template
        .iter()
        .map(|arg| arg.replace("{ip}", &ip).replace("{bantime}", &secs))
        .collect()
}

/// argv[0] をシェルを通さずに起動する。完了は待たない。
///
/// ゾンビを残さないよう別スレッドで `wait()` する。起動に失敗しても
/// stderr に 1 行出すだけで、ブロック自体は妨げない。argv が空なら何もしない。
pub fn spawn_notify(argv: &[String]) {
    let Some((program, args)) = argv.split_first() else {
        return;
    };
    let spawned = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .spawn();
    match spawned {
        Ok(mut child) => {
            let program = program.clone();
            let waiter = std::thread::Builder::new()
                .name("notify-wait".to_string())
                .spawn(move || match child.wait() {
                    Ok(status) if !status.success() => {
                        eprintln!("通知コマンドが失敗しました: {program}: {status}");
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("通知コマンドの終了を待てません: {program}: {e}"),
                });
            if let Err(e) = waiter {
                eprintln!("通知コマンドの待機スレッドを作れません: {e}");
            }
        }
        Err(e) => eprintln!("通知コマンドを起動できません: {program}: {e}"),
    }
}
