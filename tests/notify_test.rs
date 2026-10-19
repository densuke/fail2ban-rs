//! 通知コマンドの組み立てと起動のテスト。

use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use fail2ban_rs::notify::{render_command, spawn_notify, spawn_notify_with_timeout};

/// 偽の実行ファイルを書いてから起動するテストを直列にする (ETXTBSY の競合を防ぐ)。
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn render_replaces_every_placeholder() {
    let ip: IpAddr = "192.0.2.5".parse().unwrap();
    let template = strings(&[
        "/bin/x",
        "--t",
        "ban {ip} for {bantime}s",
        "[{kind}]",
        "{ip}{ip}",
        "{other}",
    ]);
    assert_eq!(
        render_command(&template, ip, Duration::from_secs(300), "長期"),
        strings(&[
            "/bin/x",
            "--t",
            "ban 192.0.2.5 for 300s",
            "[長期]",
            "192.0.2.5192.0.2.5",
            "{other}",
        ])
    );
}

#[test]
fn render_uses_canonical_ip() {
    let mapped: IpAddr = "::ffff:192.0.2.6".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let template = strings(&["{ip}"]);
    let secs = Duration::from_secs(1);
    assert_eq!(
        render_command(&template, mapped, secs, "通常"),
        strings(&["192.0.2.6"])
    );
    assert_eq!(
        render_command(&template, v6, secs, "通常"),
        strings(&["2001:db8::1"])
    );
}

#[test]
fn spawn_passes_arguments_without_a_shell() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.txt");
    let script = dir.path().join("fake.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > {}\n",
            out.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    spawn_notify(&[
        script.display().to_string(),
        "a b".to_string(),
        "c".to_string(),
    ]);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::fs::read_to_string(&out).is_ok_and(|s| s == "a b\nc\n") {
            return;
        }
        assert!(Instant::now() < deadline, "引数がファイルに書かれなかった");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn spawn_of_missing_program_does_not_panic() {
    spawn_notify(&["/nonexistent/fail2ban-rs-notify".to_string()]);
    spawn_notify(&[]);
}

#[test]
fn hung_command_is_killed_after_timeout() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid.txt");
    let script = dir.path().join("hang.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho $$ > {}\nexec sleep 30\n",
            pid_file.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    spawn_notify_with_timeout(&[script.display().to_string()], Duration::from_secs(1));

    let deadline = Instant::now() + Duration::from_secs(10);
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "PID が書かれなかった");
        std::thread::sleep(Duration::from_millis(50));
    };
    let proc_dir = std::path::PathBuf::from(format!("/proc/{pid}"));
    loop {
        if !proc_dir.exists() {
            return;
        }
        assert!(Instant::now() < deadline, "止まったコマンドが残っている");
        std::thread::sleep(Duration::from_millis(50));
    }
}
