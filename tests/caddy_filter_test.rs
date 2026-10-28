//! Caddy のアクセスログの読み取りと、既知のパスの判定。

use std::net::IpAddr;

use fail2ban_rs::filter::{AccessEntry, BadPaths, parse_access};

fn line(
    logger: &str,
    client: Option<&str>,
    remote: Option<&str>,
    uri: &str,
    status: Option<u16>,
) -> String {
    let mut request = serde_json::json!({
        "host": "fuga.jp",
        "uri": uri,
        "headers": {"X-Forwarded-For": ["198.51.100.9"]},
    });
    if let Some(c) = client {
        request["client_ip"] = c.into();
    }
    if let Some(r) = remote {
        request["remote_ip"] = r.into();
    }
    let mut v = serde_json::json!({"level": "info", "logger": logger, "request": request});
    if let Some(s) = status {
        v["status"] = s.into();
    }
    v.to_string()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

const ACCESS: &str = "http.log.access.log0";

#[test]
fn peer_is_client_ip_and_headers_are_ignored() {
    let l = line(
        ACCESS,
        Some("203.0.113.7"),
        Some("203.0.113.7"),
        "/.env",
        Some(404),
    );
    assert_eq!(
        parse_access(&l),
        Some(AccessEntry {
            ip: ip("203.0.113.7"),
            uri: "/.env".into(),
            status: 404
        })
    );
}

#[test]
fn falls_back_to_remote_ip() {
    let l = line(ACCESS, None, Some("192.0.2.5"), "/", Some(200));
    assert_eq!(parse_access(&l).map(|e| e.ip), Some(ip("192.0.2.5")));
}

#[test]
fn canonicalizes_mapped_ipv4_keeps_ipv6() {
    let l = line(ACCESS, Some("::ffff:192.0.2.1"), None, "/", Some(200));
    assert_eq!(parse_access(&l).map(|e| e.ip), Some(ip("192.0.2.1")));
    let l = line(ACCESS, Some("2001:db8::1"), None, "/", Some(200));
    assert_eq!(parse_access(&l).map(|e| e.ip), Some(ip("2001:db8::1")));
}

#[test]
fn drops_unreadable_lines() {
    let bad = [
        line("http.log.error", Some("203.0.113.7"), None, "/", Some(404)),
        "not json".to_string(),
        line(ACCESS, Some("203.0.113.7"), None, "/", None),
        line(
            ACCESS,
            Some("example.com"),
            Some("203.0.113.7"),
            "/",
            Some(404),
        ),
        line(ACCESS, None, None, "/", Some(404)),
    ];
    for l in bad {
        assert_eq!(parse_access(&l), None, "{l}");
    }
}

#[test]
fn builtin_list_matches() {
    let b = BadPaths::new(&[]).unwrap();
    for uri in [
        "/.env",
        "/app/.env.local",
        "/.env-example",
        "/.envoy",
        "/.git/config",
        "/.aws/credentials",
        "/.ssh/id_rsa",
        "/.claude/settings.json",
        "/wp-login.php",
        "/blog/wp-json/",
        "/BLOG/WP-JSON/",
        "/xmlrpc.php",
        "/phpmyadmin/",
        "/cgi-bin/x",
        "/phpinfo.php",
        "/_profiler/phpinfo",
        "/backup.zip",
        "/b45d3cda3836.tar.gz",
        "/dump.sql",
        "/db.bak",
        "/?rest_route=/",
        "/?rest%5Froute=/",
        "/?phpinfo=1",
        "/%2E%65nv",
        "/a.php?x=1&REST_ROUTE=/",
    ] {
        assert!(b.matches(uri), "{uri}");
    }
}

#[test]
fn legitimate_urls_do_not_match() {
    let b = BadPaths::new(&[]).unwrap();
    for uri in [
        "/",
        "/login",
        "/feed?url=https://example.com/.env/a.zip",
        "/feed?url=http://example.com/?rest_route=/",
        "/posts/phpinfo-tips",
        "/environment",
        "/a%zz",
        "/a%",
        "/a.zip.html",
    ] {
        assert!(!b.matches(uri), "{uri}");
    }
}

#[test]
fn extra_matches_decoded_lowercased_path() {
    let b = BadPaths::new(&["^/\\.svn/".into()]).unwrap();
    assert!(b.matches("/.svn/entries"));
    assert!(b.matches("/%2ESVN/entries"));
    assert!(!BadPaths::new(&[]).unwrap().matches("/.svn/entries"));
}

#[test]
fn invalid_extra_is_error() {
    assert!(BadPaths::new(&["(".into()]).is_err());
}
