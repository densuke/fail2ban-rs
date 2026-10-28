use std::time::Duration;

use fail2ban_rs::config::{BadpathConfig, Mode, NotfoundConfig, RecidiveConfig, parse_config};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn http_is_none_without_section() {
    assert_eq!(parse_config("").unwrap().http, None);
}

#[test]
fn empty_http_section_gets_defaults() {
    let http = parse_config("mode = \"nft\"\n[http]")
        .unwrap()
        .http
        .unwrap();
    assert!(http.enabled);
    assert_eq!(http.bantime, secs(300));
    assert_eq!(http.journalmatch, vec!["_SYSTEMD_UNIT=caddy.service"]);
    assert_eq!(
        http.badpath,
        BadpathConfig {
            enabled: true,
            mode: Mode::Nft,
            bantime: secs(300),
            extra: vec![]
        }
    );
    assert_eq!(
        http.notfound,
        NotfoundConfig {
            enabled: true,
            mode: Mode::Nft,
            bantime: secs(300),
            maxretry: 20,
            findtime: secs(600)
        }
    );
    assert_eq!(http.recidive, None);
}

#[test]
fn rule_mode_overrides_global_mode() {
    let text = "mode = \"nft\"\n[http.notfound]\nmode = \"log\"";
    let http = parse_config(text).unwrap().http.unwrap();
    assert_eq!(http.notfound.mode, Mode::Log);
    assert_eq!(http.badpath.mode, Mode::Nft);
}

#[test]
fn rule_nft_is_rejected_unless_global_mode_is_nft() {
    for text in [
        "[http.badpath]\nmode = \"nft\"",
        "mode = \"log\"\n[http.badpath]\nmode = \"nft\"",
        "[http.notfound]\nmode = \"nft\"",
    ] {
        assert!(parse_config(text).is_err(), "{text}");
    }
}

#[test]
fn http_recidive_defaults() {
    let http = parse_config("[http.recidive]").unwrap().http.unwrap();
    assert_eq!(
        http.recidive,
        Some(RecidiveConfig {
            maxbans: 3,
            findtime: secs(86400),
            bantime: secs(86400)
        })
    );
}

#[test]
fn http_recidive_bantime_must_exceed_bantime() {
    let err = parse_config("[http]\nbantime = \"1d\"\n[http.recidive]")
        .unwrap_err()
        .to_string();
    assert!(err.contains("http.recidive.bantime"), "{err}");
}

#[test]
fn invalid_extra_regex_is_rejected() {
    let err = parse_config("[http.badpath]\nextra = [\"(\"]")
        .unwrap_err()
        .to_string();
    assert!(err.contains("http.badpath.extra"), "{err}");
}

#[test]
fn valid_extra_regex_is_kept() {
    let http = parse_config("[http.badpath]\nextra = [\"^/secret\"]")
        .unwrap()
        .http
        .unwrap();
    assert_eq!(http.badpath.extra, vec!["^/secret"]);
}

#[test]
fn notfound_maxretry_zero_is_rejected() {
    assert!(parse_config("[http.notfound]\nmaxretry = 0").is_err());
}

#[test]
fn bad_journalmatch_is_rejected() {
    let err = parse_config("[http]\njournalmatch = [\"-f\"]")
        .unwrap_err()
        .to_string();
    assert!(err.contains("http.journalmatch"), "{err}");
}

#[test]
fn badpath_can_be_disabled() {
    let http = parse_config("[http.badpath]\nenabled = false")
        .unwrap()
        .http
        .unwrap();
    assert!(!http.badpath.enabled);
}

#[test]
fn unknown_http_keys_are_rejected() {
    assert!(parse_config("[http]\nfoo = 1").is_err());
    assert!(parse_config("[http.badpath]\nfoo = 1").is_err());
}

#[test]
fn rule_bantime_defaults_to_http_bantime() {
    let http = parse_config("[http]\nbantime = \"10m\"")
        .unwrap()
        .http
        .unwrap();
    assert_eq!(http.badpath.bantime, secs(600));
    assert_eq!(http.notfound.bantime, secs(600));
}

#[test]
fn rule_bantime_overrides_http_bantime() {
    let text = "[http.badpath]\nbantime = \"1d\"\n[http.notfound]\nbantime = \"1h\"";
    let http = parse_config(text).unwrap().http.unwrap();
    assert_eq!(http.badpath.bantime, secs(86400));
    assert_eq!(http.notfound.bantime, secs(3600));
    assert_eq!(http.bantime, secs(300));
}

#[test]
fn rule_bantime_longer_than_recidive_is_rejected() {
    for (text, key) in [
        (
            "[http.badpath]\nbantime = \"2d\"\n[http.recidive]",
            "http.badpath.bantime",
        ),
        (
            "[http.notfound]\nbantime = \"2d\"\n[http.recidive]",
            "http.notfound.bantime",
        ),
    ] {
        let err = parse_config(text).unwrap_err().to_string();
        assert!(err.contains(key), "{err}");
    }
    let ok = "[http.badpath]\nbantime = \"1d\"\n[http.recidive]";
    assert!(parse_config(ok).is_ok());
}
