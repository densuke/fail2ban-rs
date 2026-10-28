//! `test-filter` サブコマンドを実バイナリで動かして出力を確かめる。

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], input: &str) -> (bool, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fail2ban-rs"))
        .arg("test-filter")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap())
}

fn access(uri: &str, status: u16) -> String {
    serde_json::json!({
        "logger": "http.log.access.log0",
        "status": status,
        "request": {"client_ip": "203.0.113.7", "uri": uri},
    })
    .to_string()
}

#[test]
fn http_jail_classifies_each_line() {
    let input = format!(
        "{}\n{}\n{}\n",
        access("/.env", 404),
        access("/x", 404),
        access("/", 200)
    );
    let (ok, out) = run(&["--jail", "http"], &input);
    assert!(ok);
    assert_eq!(
        out,
        "badpath 203.0.113.7 /.env\nnotfound 203.0.113.7\nother\nbadpath 1 notfound 1 other 1 / 3 lines\n"
    );
}

#[test]
fn default_jail_is_sshd() {
    let line = "Failed password for invalid user admin from 192.0.2.7 port 4242 ssh2\n";
    let (ok, out) = run(&[], line);
    assert!(ok);
    assert_eq!(out, "fail 192.0.2.7 user=admin\nmatched 1/1 lines\n");
}

#[test]
fn unknown_jail_is_rejected() {
    let (ok, _) = run(&["--jail", "ftp"], "");
    assert!(!ok);
}
