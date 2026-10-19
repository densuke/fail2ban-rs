//! sshd フィルタ (normal モード) と式の展開のテスト。

use fail2ban_rs::filter::{SshdFilter, expand};

fn check(msg: &str) -> Option<fail2ban_rs::filter::FilterMatch> {
    SshdFilter::new().unwrap().check(msg)
}

#[test]
fn failed_password_invalid_user() {
    let m = check("Failed password for invalid user admin from 192.0.2.7 port 4242 ssh2").unwrap();
    assert_eq!(m.host, "192.0.2.7");
    assert_eq!(m.user.as_deref(), Some("admin"));
    assert!(!m.nofail);
}

#[test]
fn failed_password_ipv6() {
    let m = check("Failed password for root from 2001:db8::5 port 22 ssh2").unwrap();
    assert_eq!(m.host, "2001:db8::5");
    assert_eq!(m.user.as_deref(), Some("root"));
}

#[test]
fn pam_error_prefix_is_stripped() {
    let m = check("error: PAM: Authentication failure for bob from 192.0.2.8").unwrap();
    assert_eq!(m.host, "192.0.2.8");
    assert!(!m.nofail);
}

#[test]
fn invalid_user_line() {
    let m = check("Invalid user test from 192.0.2.9 port 5555").unwrap();
    assert_eq!(m.host, "192.0.2.9");
    assert_eq!(m.user.as_deref(), Some("test"));
}

#[test]
fn failed_publickey_invalid_user_is_failure() {
    let m = check("Failed publickey for invalid user x from 192.0.2.10 port 1 ssh2").unwrap();
    assert!(!m.nofail);
}

#[test]
fn failed_publickey_valid_user_is_nofail() {
    let m = check("Failed publickey for alice from 192.0.2.11 port 1 ssh2").unwrap();
    assert!(m.nofail);
}

#[test]
fn accepted_publickey_is_never_a_failure() {
    let m = check("Accepted publickey for densuke from 192.168.11.5 port 52759 ssh2: RSA SHA256:x");
    assert!(m.is_none_or(|m| m.nofail));
}

#[test]
fn connection_closed_is_never_a_failure() {
    let m =
        check("Connection closed by authenticating user densuke 192.168.11.5 port 52755 [preauth]");
    assert!(m.is_none_or(|m| m.nofail));
}

#[test]
fn unrelated_line_does_not_match() {
    assert_eq!(
        check(
            "pam_unix(sshd:session): session opened for user densuke(uid=1000) by densuke(uid=0)"
        ),
        None
    );
}

#[test]
fn very_long_attacker_line_returns() {
    let msg = format!(
        "Failed password for invalid user {} from 192.0.2.12 port 1 ssh2",
        "a ".repeat(5000)
    );
    let _ = check(&msg);
}

#[test]
fn expand_resolves_nested_references() {
    assert_eq!(expand("<a>-%(b)s", &[("a", "<b>"), ("b", "x")]), "x-x");
}
