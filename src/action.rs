//! ブロックの動作。`log` モードは記録だけ、`nft` モードは nftables の set に追加する。

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::config::NftConfig;

/// ブロックの動作で起きるエラー。
#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    #[error("nft を起動できません ({path}): {source}")]
    Spawn {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("nft が失敗しました ({status}): {stderr}")]
    NftFailed { status: String, stderr: String },
}

/// IP アドレスをブロックする動作。
pub trait BanAction {
    /// 起動時に 1 回呼ぶ。何度呼んでも安全であること。
    fn start(&self) -> Result<(), ActionError>;
    /// `ip` を `bantime` の間ブロックする。
    fn ban(&self, ip: IpAddr, bantime: Duration) -> Result<(), ActionError>;
}

/// 実際にはブロックせず、標準出力に書くだけの動作。
pub struct LogAction;

impl BanAction for LogAction {
    fn start(&self) -> Result<(), ActionError> {
        Ok(())
    }

    fn ban(&self, ip: IpAddr, bantime: Duration) -> Result<(), ActionError> {
        println!("would ban {ip} for {}s", bantime.as_secs());
        Ok(())
    }
}

/// nftables の set に追加する動作。
pub struct NftAction {
    pub config: NftConfig,
}

impl BanAction for NftAction {
    fn start(&self) -> Result<(), ActionError> {
        let script = nft_setup_script(&self.config.table, self.config.priority);
        self.run_script(&script)
    }

    fn ban(&self, ip: IpAddr, bantime: Duration) -> Result<(), ActionError> {
        let script = nft_ban_script(&self.config.table, ip, bantime);
        self.run_script(&script)
    }
}

impl NftAction {
    /// スクリプトを `nft -f -` の標準入力に渡す。
    fn run_script(&self, script: &str) -> Result<(), ActionError> {
        let path = &self.config.nft_path;
        let spawn_err = |source| ActionError::Spawn {
            path: path.display().to_string(),
            source,
        };
        let mut child = Command::new(path)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(spawn_err)?;
        if let Some(mut stdin) = child.stdin.take() {
            // nft が先に終わると書き込みが失敗するが、原因は終了状態と stderr で分かる
            let _ = stdin.write_all(script.as_bytes());
        }
        let output = child.wait_with_output().map_err(spawn_err)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ActionError::NftFailed {
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
    }
}

/// 表・set・規則を作るスクリプト。何度流しても set の要素は消えない。
pub fn nft_setup_script(table: &str, priority: i32) -> String {
    format!(
        "add table inet {table}\n\
         add set inet {table} addr4 {{ type ipv4_addr; flags timeout; }}\n\
         add set inet {table} addr6 {{ type ipv6_addr; flags timeout; }}\n\
         add chain inet {table} input {{ type filter hook input priority {priority}; policy accept; }}\n\
         flush chain inet {table} input\n\
         add rule inet {table} input ip saddr @addr4 drop\n\
         add rule inet {table} input ip6 saddr @addr6 drop\n"
    )
}

/// 1 つの IP を `bantime` 秒の期限付きで set に加えるスクリプト。
pub fn nft_ban_script(table: &str, ip: IpAddr, bantime: Duration) -> String {
    let set = match ip {
        IpAddr::V4(_) => "addr4",
        IpAddr::V6(_) => "addr6",
    };
    format!(
        "add element inet {table} {set} {{ {ip} timeout {}s }}\n",
        bantime.as_secs()
    )
}
