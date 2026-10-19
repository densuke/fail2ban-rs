//! 実際の nft を使うテスト。ホストの規則を触らないよう、必ず
//! 使い捨てのネットワーク名前空間の中で動かす。
//!
//! 実行方法:
//!   cargo test --test nft_netns_test --no-run
//!   sudo -n unshare -n <上で作られたテストのバイナリ> --ignored

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use fail2ban_rs::action::{BanAction, NftAction};
use fail2ban_rs::config::NftConfig;

#[test]
#[ignore = "unshare -n の中で root として実行すること"]
fn ban_is_visible_in_set_and_survives_restart() {
    let nft_path = PathBuf::from("/usr/sbin/nft");
    let action = NftAction {
        config: NftConfig {
            table: "fail2ban_rs".to_string(),
            priority: -10,
            nft_path: nft_path.clone(),
            journalctl_path: PathBuf::from("/usr/bin/journalctl"),
        },
    };
    let ip: IpAddr = "192.0.2.10".parse().unwrap();

    action.start().unwrap();
    action.start().unwrap();
    action.ban(ip, Duration::from_secs(600)).unwrap();
    action.start().unwrap();

    let out = Command::new(&nft_path)
        .args(["list", "set", "inet", "fail2ban_rs", "addr4"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("192.0.2.10"), "{text}");
    assert!(text.contains("timeout 10m"), "{text}");
}
