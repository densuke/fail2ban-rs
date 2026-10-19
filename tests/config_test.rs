use std::path::PathBuf;
use std::time::Duration;

use fail2ban_rs::config::{Config, JailConfig, Mode, NftConfig, NotifyConfig, parse_config};
use fail2ban_rs::duration::parse_duration;

fn default_config() -> Config {
    Config {
        mode: Mode::Log,
        ignoreip: vec!["127.0.0.0/8".to_string(), "::1".to_string()],
        sshd: JailConfig {
            enabled: true,
            maxretry: 5,
            findtime: Duration::from_secs(600),
            bantime: Duration::from_secs(600),
            journalmatch: vec![
                "_COMM=sshd".to_string(),
                "_UID=0".to_string(),
                "+".to_string(),
                "_COMM=sshd-session".to_string(),
                "_UID=0".to_string(),
            ],
        },
        nft: NftConfig {
            table: "fail2ban_rs".to_string(),
            priority: -10,
            nft_path: PathBuf::from("/usr/sbin/nft"),
            journalctl_path: PathBuf::from("/usr/bin/journalctl"),
        },
        notify: NotifyConfig::default(),
    }
}

#[test]
fn parse_duration_accepts_plain_seconds() {
    assert_eq!(parse_duration("600").unwrap(), Duration::from_secs(600));
}

#[test]
fn parse_duration_accepts_units() {
    assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
}

#[test]
fn parse_duration_rejects_empty_negative_unknown_unit_and_zero() {
    for input in ["", "-5m", "10x", "0", "0s", "10 m", " 10m", "m"] {
        assert!(
            parse_duration(input).is_err(),
            "{input:?} should be rejected"
        );
    }
}

#[test]
fn parse_duration_rejects_overflowing_values() {
    assert!(parse_duration("18446744073709551615d").is_err());
}

#[test]
fn parse_duration_error_message_contains_the_input() {
    let err = parse_duration("10x").unwrap_err();
    assert!(err.to_string().contains("10x"), "message was: {err}");
}

#[test]
fn empty_config_yields_global_defaults() {
    assert_eq!(parse_config("").unwrap(), default_config());
}

#[test]
fn partial_sshd_section_overrides_only_given_keys() {
    let text = "mode = \"nft\"\n[sshd]\nmaxretry = 3\nbantime = \"1h\"\n";
    let config = parse_config(text).unwrap();
    assert_eq!(config.mode, Mode::Nft);
    assert_eq!(config.sshd.maxretry, 3);
    assert_eq!(config.sshd.bantime, Duration::from_secs(3600));
    assert_eq!(config.sshd.findtime, Duration::from_secs(600));
}

#[test]
fn integer_durations_are_seconds() {
    let config = parse_config("[sshd]\nfindtime = 120\nbantime = 90\n").unwrap();
    assert_eq!(config.sshd.findtime, Duration::from_secs(120));
    assert_eq!(config.sshd.bantime, Duration::from_secs(90));
}

#[test]
fn zero_maxretry_is_rejected() {
    assert!(parse_config("[sshd]\nmaxretry = 0\n").is_err());
}

#[test]
fn invalid_duration_in_config_is_rejected() {
    assert!(parse_config("[sshd]\nbantime = \"-1h\"\n").is_err());
    assert!(parse_config("[sshd]\nfindtime = -1\n").is_err());
}

#[test]
fn nft_table_with_injection_characters_is_rejected() {
    assert!(parse_config("[nft]\ntable = \"x; flush ruleset\"\n").is_err());
}

#[test]
fn nft_table_name_rules_are_enforced() {
    assert!(parse_config("[nft]\ntable = \"\"\n").is_err());
    assert!(parse_config("[nft]\ntable = \"1abc\"\n").is_err());
    assert!(parse_config("[nft]\ntable = \"a-b\"\n").is_err());
    let too_long = format!("[nft]\ntable = \"a{}\"\n", "b".repeat(32));
    assert!(parse_config(&too_long).is_err());
    let config = parse_config("[nft]\ntable = \"My_table1\"\n").unwrap();
    assert_eq!(config.nft.table, "My_table1");
}

#[test]
fn unknown_key_is_rejected() {
    assert!(parse_config("mod = \"nft\"\n").is_err());
    assert!(parse_config("[sshd]\nmaxretires = 3\n").is_err());
    assert!(parse_config("[nft]\ntabel = \"x\"\n").is_err());
}

#[test]
fn unknown_mode_is_rejected() {
    assert!(parse_config("mode = \"drop\"\n").is_err());
}

#[test]
fn empty_journalmatch_is_rejected() {
    assert!(parse_config("[sshd]\njournalmatch = []\n").is_err());
}

#[test]
fn journalmatch_without_a_real_term_is_rejected() {
    assert!(parse_config("[sshd]\njournalmatch = [\"+\"]\n").is_err());
    assert!(parse_config("[sshd]\njournalmatch = [\"+\", \"+\"]\n").is_err());
}

#[test]
fn journalmatch_option_like_entry_is_rejected() {
    assert!(parse_config("[sshd]\njournalmatch = [\"--file=/tmp/x\"]\n").is_err());
    assert!(parse_config("[sshd]\njournalmatch = [\"-x=1\"]\n").is_err());
    assert!(parse_config("[sshd]\njournalmatch = [\"_comm=sshd\"]\n").is_err());
    assert!(parse_config("[sshd]\njournalmatch = [\"_COMM\"]\n").is_err());
}

#[test]
fn valid_journalmatch_is_accepted() {
    let config =
        parse_config("[sshd]\njournalmatch = [\"_COMM=sshd\", \"+\", \"_COMM=sshd-session\"]\n")
            .unwrap();
    assert_eq!(config.sshd.journalmatch.len(), 3);
    assert!(parse_config("[sshd]\njournalmatch = [\"SYSLOG_IDENTIFIER=f2b-e2e\"]\n").is_ok());
}

#[test]
fn bantimeとfindtimeは365日まで() {
    assert!(parse_config("[sshd]\nbantime = \"365d\"\n").is_ok());
    assert!(parse_config("[sshd]\nbantime = \"366d\"\n").is_err());
    assert!(parse_config("[sshd]\nfindtime = \"365d\"\n").is_ok());
    assert!(parse_config("[sshd]\nfindtime = \"366d\"\n").is_err());
}

#[test]
fn notify_defaults_to_empty() {
    assert!(parse_config("").unwrap().notify.on_ban.is_empty());
}

#[test]
fn notify_on_ban_is_read() {
    let config = parse_config("[notify]\non_ban = [\"/bin/echo\", \"{ip}\"]").unwrap();
    assert_eq!(config.notify.on_ban, vec!["/bin/echo", "{ip}"]);
}

#[test]
fn notify_on_ban_requires_absolute_program_path() {
    assert!(parse_config("[notify]\non_ban = [\"echo\", \"{ip}\"]").is_err());
}

#[test]
fn notify_rejects_unknown_key() {
    assert!(parse_config("[notify]\nfoo = 1").is_err());
}
