//! 出力の行を作る関数のテスト。

use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use fail2ban_rs::config::parse_config;
use fail2ban_rs::http_engine::{HttpOutcome, HttpRule};
use fail2ban_rs::report::{
    http_outcome_line, http_start_line, sanitize_uri, sshd_already_banned_line,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn 制御文字と空白をパーセントエンコードする() {
    assert_eq!(sanitize_uri("/a b\n\x1b[31m"), "/a%20b%0A%1B[31m");
}

#[test]
fn 長い_uri_は_200_文字で切る() {
    let long = format!("/{}", "a".repeat(299));
    let got = sanitize_uri(&long);
    assert_eq!(got, format!("{}...", &long[..200]));
}

#[test]
fn 日本語はそのまま() {
    assert_eq!(sanitize_uri("/日本語"), "/日本語");
}

#[test]
fn 全角空白はバイトごとにエンコードする() {
    assert_eq!(sanitize_uri("/a\u{3000}b"), "/a%E3%80%80b");
}

#[test]
fn 既定の起動の行() {
    let config = parse_config("mode = \"nft\"\n[http]\n[http.recidive]\n").unwrap();
    let http = config.http.unwrap();
    assert_eq!(
        http_start_line(&http),
        "start http bantime=300s badpath=nft(+0 extra) notfound=nft/20/600s recidive=3/86400s/86400s"
    );
}

#[test]
fn 無効なルールと_recidive_なしは_off() {
    let config =
        parse_config("mode = \"nft\"\n[http]\n[http.notfound]\nenabled = false\n").unwrap();
    let http = config.http.unwrap();
    assert_eq!(
        http_start_line(&http),
        "start http bantime=300s badpath=nft(+0 extra) notfound=off recidive=off"
    );
}

#[test]
fn badpath_が無効なら_off_で_log_は小文字() {
    let config = parse_config(
        "mode = \"log\"\n[http]\n[http.badpath]\nenabled = false\n[http.notfound]\nmaxretry = 5\n",
    )
    .unwrap();
    let http = config.http.unwrap();
    assert_eq!(
        http_start_line(&http),
        "start http bantime=300s badpath=off notfound=log/5/600s recidive=off"
    );
}

#[test]
fn ban_の行() {
    let o = HttpOutcome::Banned {
        ip: ip("203.0.113.7"),
        rule: HttpRule::Badpath,
        bantime: Duration::from_secs(300),
        long: false,
        uri: Some("/.env".into()),
    };
    assert_eq!(
        http_outcome_line(&o).unwrap(),
        "ban 203.0.113.7 for 300s jail=http rule=badpath uri=/.env"
    );
}

#[test]
fn 長期_ban_の行() {
    let o = HttpOutcome::Banned {
        ip: ip("203.0.113.7"),
        rule: HttpRule::Notfound,
        bantime: Duration::from_secs(86400),
        long: true,
        uri: None,
    };
    assert_eq!(
        http_outcome_line(&o).unwrap(),
        "ban 203.0.113.7 for 86400s (recidive) jail=http rule=notfound"
    );
}

#[test]
fn would_ban_の行() {
    let o = HttpOutcome::WouldBan {
        ip: ip("203.0.113.8"),
        rule: HttpRule::Notfound,
        bantime: Duration::from_secs(300),
        uri: None,
    };
    assert_eq!(
        http_outcome_line(&o).unwrap(),
        "would ban 203.0.113.8 for 300s jail=http rule=notfound"
    );
}

#[test]
fn already_banned_の行() {
    let o = HttpOutcome::AlreadyBanned {
        ip: ip("203.0.113.7"),
        rule: HttpRule::Badpath,
        until: UNIX_EPOCH + Duration::from_secs(1_700_086_400),
    };
    assert_eq!(
        http_outcome_line(&o).unwrap(),
        "already banned 203.0.113.7 until 1700086400 jail=http rule=badpath"
    );
}

#[test]
fn ignored_の行と出さない結果() {
    assert_eq!(
        http_outcome_line(&HttpOutcome::Ignored(ip("198.51.100.1"))).unwrap(),
        "ignored 198.51.100.1 jail=http"
    );
    assert_eq!(http_outcome_line(&HttpOutcome::NoMatch), None);
    assert_eq!(
        http_outcome_line(&HttpOutcome::Counted(ip("198.51.100.1"))),
        None
    );
}

#[test]
fn 改行入りの_uri_でも_1_行() {
    let o = HttpOutcome::Banned {
        ip: ip("203.0.113.7"),
        rule: HttpRule::Badpath,
        bantime: Duration::from_secs(300),
        long: false,
        uri: Some("/a\nforged line".into()),
    };
    let line = http_outcome_line(&o).unwrap();
    assert!(!line.contains('\n'));
    assert!(line.ends_with("uri=/a%0Aforged%20line"));
}

#[test]
fn sshd_の_already_banned_の行() {
    let until = UNIX_EPOCH + Duration::from_secs(1_700_086_400);
    assert_eq!(
        sshd_already_banned_line(ip("2001:db8::1"), until),
        "already banned 2001:db8::1 until 1700086400 jail=sshd rule=sshd"
    );
}
