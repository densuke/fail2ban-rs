//! ブロックの動作のテスト。nft のスクリプトは完全一致で確かめる。

use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use fail2ban_rs::action::{BanAction, NftAction, nft_ban_script, nft_setup_script};
use fail2ban_rs::config::NftConfig;

fn nft_config(nft_path: PathBuf) -> NftConfig {
    NftConfig {
        table: "fail2ban_rs".to_string(),
        priority: -10,
        nft_path,
        journalctl_path: PathBuf::from("/usr/bin/journalctl"),
    }
}

#[test]
fn setup_script_is_exact() {
    let expected = "\
add table inet fail2ban_rs
add set inet fail2ban_rs addr4 { type ipv4_addr; flags timeout; }
add set inet fail2ban_rs addr6 { type ipv6_addr; flags timeout; }
add chain inet fail2ban_rs input { type filter hook input priority -10; policy accept; }
flush chain inet fail2ban_rs input
add rule inet fail2ban_rs input ip saddr @addr4 drop
add rule inet fail2ban_rs input ip6 saddr @addr6 drop
";
    assert_eq!(nft_setup_script("fail2ban_rs", -10), expected);
}

#[test]
fn ban_script_ipv4_uses_addr4() {
    let ip: IpAddr = "192.0.2.10".parse().unwrap();
    assert_eq!(
        nft_ban_script("fail2ban_rs", ip, Duration::from_secs(600)),
        "add element inet fail2ban_rs addr4 { 192.0.2.10 timeout 600s }\n"
    );
}

#[test]
fn ban_script_ipv6_uses_addr6() {
    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(
        nft_ban_script("fail2ban_rs", ip, Duration::from_secs(600)),
        "add element inet fail2ban_rs addr6 { 2001:db8::1 timeout 600s }\n"
    );
}

#[test]
fn start_fails_when_nft_is_missing() {
    let action = NftAction {
        config: nft_config(PathBuf::from("/nonexistent/nft")),
    };
    assert!(action.start().is_err());
}

#[test]
fn start_error_includes_nft_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fake-nft");
    std::fs::write(
        &path,
        "#!/bin/sh\ncat >/dev/null\necho \"Error: syntax error\" >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let action = NftAction {
        config: nft_config(path),
    };
    let err = action.start().unwrap_err();
    assert!(err.to_string().contains("syntax error"), "{err}");
}
