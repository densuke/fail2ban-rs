//! 設定ファイル (TOML) の読み込みと検証。
//!
//! TOML はまず `Option` の多い生の構造体で受け、既定値を埋めてから検証して
//! `Config` に変換する。ignoreip の各要素の IP/CIDR 検証は `IgnoreList::parse` の仕事。

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::duration::parse_duration;

const DEFAULT_MAXRETRY: u32 = 5;
const DEFAULT_FINDTIME: Duration = Duration::from_secs(600);
const DEFAULT_BANTIME: Duration = Duration::from_secs(600);
const DEFAULT_TABLE: &str = "fail2ban_rs";
const DEFAULT_PRIORITY: i32 = -10;
const DEFAULT_NFT_PATH: &str = "/usr/sbin/nft";
const DEFAULT_JOURNALCTL_PATH: &str = "/usr/bin/journalctl";
const MAX_TABLE_NAME_LEN: usize = 32;

/// 設定の読み込み・検証で起きるエラー。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("設定ファイルを読めません: {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("設定ファイルの書式が不正です: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("時間の書式が不正です: {0:?} (例: 600, 30s, 10m, 1h, 1d)")]
    InvalidDuration(String),
    #[error("値が不正です: {key} = {value:?}")]
    InvalidValue { key: &'static str, value: String },
    #[error("ignoreip の値が IP アドレスまたは CIDR ではありません: {0:?}")]
    InvalidIgnoreIp(String),
}

/// 動作モード。`log` はログに出すだけ、`nft` は nftables で実際に遮断する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Log,
    Nft,
}

/// sshd ジェイルの設定。
#[derive(Debug, Clone, PartialEq)]
pub struct JailConfig {
    pub enabled: bool,
    pub maxretry: u32,
    pub findtime: Duration,
    pub bantime: Duration,
    pub journalmatch: Vec<String>,
}

/// nftables 関連の設定。
#[derive(Debug, Clone, PartialEq)]
pub struct NftConfig {
    pub table: String,
    pub priority: i32,
    pub nft_path: PathBuf,
    pub journalctl_path: PathBuf,
}

/// 検証済みの設定全体。
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub mode: Mode,
    pub ignoreip: Vec<String>,
    pub sshd: JailConfig,
    pub nft: NftConfig,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    mode: Option<Mode>,
    ignoreip: Option<Vec<String>>,
    sshd: Option<RawJail>,
    nft: Option<RawNft>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawJail {
    enabled: Option<bool>,
    maxretry: Option<u32>,
    findtime: Option<RawDuration>,
    bantime: Option<RawDuration>,
    journalmatch: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawNft {
    table: Option<String>,
    priority: Option<i32>,
    nft_path: Option<PathBuf>,
    journalctl_path: Option<PathBuf>,
}

/// 時間は整数 (秒) でも `"1h"` のような文字列でも書ける。
#[derive(Deserialize)]
#[serde(untagged)]
enum RawDuration {
    Seconds(i64),
    Text(String),
}

impl RawDuration {
    fn to_duration(&self) -> Result<Duration, ConfigError> {
        match self {
            Self::Seconds(secs) => parse_duration(&secs.to_string()),
            Self::Text(text) => parse_duration(text),
        }
    }
}

/// TOML 文字列から検証済みの設定を作る。空文字なら既定値だけの設定になる。
pub fn parse_config(text: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(text)?;
    Ok(Config {
        mode: raw.mode.unwrap_or(Mode::Log),
        ignoreip: raw
            .ignoreip
            .unwrap_or_else(|| vec!["127.0.0.0/8".to_string(), "::1".to_string()]),
        sshd: jail_from_raw(raw.sshd.unwrap_or_default())?,
        nft: nft_from_raw(raw.nft.unwrap_or_default())?,
    })
}

/// ファイルから設定を読み込む。
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_config(&text)
}

fn jail_from_raw(raw: RawJail) -> Result<JailConfig, ConfigError> {
    let maxretry = raw.maxretry.unwrap_or(DEFAULT_MAXRETRY);
    if maxretry == 0 {
        return Err(ConfigError::InvalidValue {
            key: "sshd.maxretry",
            value: maxretry.to_string(),
        });
    }
    Ok(JailConfig {
        enabled: raw.enabled.unwrap_or(true),
        maxretry,
        findtime: duration_or(raw.findtime, DEFAULT_FINDTIME)?,
        bantime: duration_or(raw.bantime, DEFAULT_BANTIME)?,
        journalmatch: raw.journalmatch.unwrap_or_else(|| {
            vec![
                "_COMM=sshd".to_string(),
                "+".to_string(),
                "_COMM=sshd-session".to_string(),
            ]
        }),
    })
}

fn nft_from_raw(raw: RawNft) -> Result<NftConfig, ConfigError> {
    let table = raw.table.unwrap_or_else(|| DEFAULT_TABLE.to_string());
    validate_table_name(&table)?;
    Ok(NftConfig {
        table,
        priority: raw.priority.unwrap_or(DEFAULT_PRIORITY),
        nft_path: raw
            .nft_path
            .unwrap_or_else(|| PathBuf::from(DEFAULT_NFT_PATH)),
        journalctl_path: raw
            .journalctl_path
            .unwrap_or_else(|| PathBuf::from(DEFAULT_JOURNALCTL_PATH)),
    })
}

/// 表の名前は nft のスクリプトに埋め込むため、英字始まりの英数字と `_` だけを許す。
fn validate_table_name(name: &str) -> Result<(), ConfigError> {
    let mut chars = name.chars();
    let valid = name.len() <= MAX_TABLE_NAME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid {
        Ok(())
    } else {
        Err(ConfigError::InvalidValue {
            key: "nft.table",
            value: name.to_string(),
        })
    }
}

fn duration_or(raw: Option<RawDuration>, default: Duration) -> Result<Duration, ConfigError> {
    raw.map_or(Ok(default), |value| value.to_duration())
}
