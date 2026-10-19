use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};

use fail2ban_rs::journal::{LogEntry, journalctl_args, parse_journal_json, spawn_reader};

#[test]
fn 文字列のmessageを読む() {
    let line = r#"{"__REALTIME_TIMESTAMP":"1792304167216173","MESSAGE":"Failed password for root from 192.0.2.1 port 1 ssh2","__CURSOR":"s=abc"}"#;
    assert_eq!(
        parse_journal_json(line),
        Some(LogEntry {
            time: UNIX_EPOCH + Duration::from_micros(1_792_304_167_216_173),
            message: "Failed password for root from 192.0.2.1 port 1 ssh2".into(),
            cursor: Some("s=abc".into()),
        })
    );
}

#[test]
fn バイト配列のmessageをutf8として読む() {
    let ok = r#"{"__REALTIME_TIMESTAMP":"1","MESSAGE":[70,97,105,108,101,100]}"#;
    let e = parse_journal_json(ok).unwrap();
    assert_eq!(e.message, "Failed");
    assert_eq!(e.cursor, None);
    let bad = r#"{"__REALTIME_TIMESTAMP":"1","MESSAGE":[70,255]}"#;
    assert_eq!(parse_journal_json(bad).unwrap().message, "F\u{FFFD}");
}

#[test]
fn 壊れた行はnone() {
    assert_eq!(parse_journal_json(r#"{"__REALTIME_TIMESTAMP":"1"}"#), None);
    assert_eq!(
        parse_journal_json(r#"{"__REALTIME_TIMESTAMP":"abc","MESSAGE":"x"}"#),
        None
    );
    assert_eq!(parse_journal_json(r#"{"MESSAGE":"x"}"#), None);
    assert_eq!(
        parse_journal_json(r#"{"__REALTIME_TIMESTAMP":"1","MESSAGE":[300]}"#),
        None
    );
    assert_eq!(parse_journal_json("not json"), None);
}

fn matches() -> Vec<String> {
    vec!["_COMM=sshd".into(), "+".into(), "_COMM=sshd-session".into()]
}

#[test]
fn 引数はsinceで組み立てる() {
    assert_eq!(
        journalctl_args(&matches(), Duration::from_secs(600), None),
        [
            "-f",
            "-o",
            "json",
            "--no-pager",
            "--since=-600s",
            "_COMM=sshd",
            "+",
            "_COMM=sshd-session"
        ]
    );
}

#[test]
fn カーソルがあればafter_cursorを使う() {
    assert_eq!(
        journalctl_args(&matches(), Duration::from_secs(600), Some("s=abc")),
        [
            "-f",
            "-o",
            "json",
            "--no-pager",
            "--after-cursor=s=abc",
            "_COMM=sshd",
            "+",
            "_COMM=sshd-session"
        ]
    );
}

#[test]
fn journalctlが終わったら最後のカーソルで再開する() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-journalctl");
    std::fs::write(
        &script,
        r#"#!/bin/sh
for a in "$@"; do
  case "$a" in
    --after-cursor=*)
      printf "{\"__REALTIME_TIMESTAMP\":\"2\",\"MESSAGE\":\"%s\",\"__CURSOR\":\"c2\"}\n" "$a"
      sleep 30
      exit 0;;
  esac
done
printf "{\"__REALTIME_TIMESTAMP\":\"1\",\"MESSAGE\":\"first\",\"__CURSOR\":\"c1\"}\n"
exit 0
"#,
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let (tx, rx) = mpsc::channel();
    let _h = spawn_reader(script, matches(), Duration::from_secs(600), tx);
    let first = rx.recv_timeout(Duration::from_secs(15)).unwrap();
    assert_eq!(first.cursor.as_deref(), Some("c1"));
    let second = rx.recv_timeout(Duration::from_secs(15)).unwrap();
    assert!(second.message.contains("--after-cursor=c1"), "{second:?}");
}
