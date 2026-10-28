//! `[http]` (Caddy ジェイル) の設定。

use std::time::Duration;

use serde::Deserialize;

use super::{
    ConfigError, HTTP_RECIDIVE_KEYS, Mode, RawDuration, RawRecidive, RecidiveConfig, duration_or,
    recidive_from_raw, validate_journalmatch,
};
use crate::filter::build;

const DEFAULT_BANTIME: Duration = Duration::from_secs(300);
const DEFAULT_NOTFOUND_MAXRETRY: u32 = 20;
const DEFAULT_NOTFOUND_FINDTIME: Duration = Duration::from_secs(600);
const DEFAULT_JOURNALMATCH: &str = "_SYSTEMD_UNIT=caddy.service";

/// HTTP ジェイルの設定。
#[derive(Debug, Clone, PartialEq)]
pub struct HttpConfig {
    pub enabled: bool,
    pub bantime: Duration,
    pub journalmatch: Vec<String>,
    pub badpath: BadpathConfig,
    pub notfound: NotfoundConfig,
    /// 常習犯を長くブロックする設定。`None` なら無効。
    pub recidive: Option<RecidiveConfig>,
}

/// 危険なパスへのアクセスを即ブロックするルール。
#[derive(Debug, Clone, PartialEq)]
pub struct BadpathConfig {
    pub enabled: bool,
    /// 省略時は全体の `mode` を解決した値。
    pub mode: Mode,
    /// 省略時は `[http]` の `bantime`。
    pub bantime: Duration,
    /// 組み込みに足す正規表現。
    pub extra: Vec<String>,
}

/// 404 が続く IP をブロックするルール。
#[derive(Debug, Clone, PartialEq)]
pub struct NotfoundConfig {
    pub enabled: bool,
    pub mode: Mode,
    /// 省略時は `[http]` の `bantime`。
    pub bantime: Duration,
    pub maxretry: u32,
    pub findtime: Duration,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct RawHttp {
    enabled: Option<bool>,
    bantime: Option<RawDuration>,
    journalmatch: Option<Vec<String>>,
    badpath: Option<RawBadpath>,
    notfound: Option<RawNotfound>,
    recidive: Option<RawRecidive>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawBadpath {
    enabled: Option<bool>,
    mode: Option<Mode>,
    bantime: Option<RawDuration>,
    extra: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawNotfound {
    enabled: Option<bool>,
    mode: Option<Mode>,
    bantime: Option<RawDuration>,
    maxretry: Option<u32>,
    findtime: Option<RawDuration>,
}

pub(super) fn http_from_raw(raw: RawHttp, global: Mode) -> Result<HttpConfig, ConfigError> {
    let journalmatch = raw
        .journalmatch
        .unwrap_or_else(|| vec![DEFAULT_JOURNALMATCH.to_string()]);
    validate_journalmatch("http.journalmatch", &journalmatch)?;
    let bantime = duration_or("http.bantime", raw.bantime, DEFAULT_BANTIME)?;
    let recidive = raw
        .recidive
        .map(|r| recidive_from_raw(&HTTP_RECIDIVE_KEYS, r, bantime))
        .transpose()?;
    let badpath = badpath_from_raw(raw.badpath.unwrap_or_default(), global, bantime)?;
    let notfound = notfound_from_raw(raw.notfound.unwrap_or_default(), global, bantime)?;
    if let Some(r) = &recidive {
        check_rule_bantime("http.badpath.bantime", badpath.bantime, r)?;
        check_rule_bantime("http.notfound.bantime", notfound.bantime, r)?;
    }
    Ok(HttpConfig {
        enabled: raw.enabled.unwrap_or(true),
        bantime,
        journalmatch,
        badpath,
        notfound,
        recidive,
    })
}

/// ルールの bantime が常習犯の bantime より長いと、常習犯のほうが短くなってしまう。
fn check_rule_bantime(
    key: &'static str,
    bantime: Duration,
    recidive: &RecidiveConfig,
) -> Result<(), ConfigError> {
    if bantime > recidive.bantime {
        return Err(ConfigError::InvalidValue {
            key,
            value: format!(
                "{}s (http.recidive.bantime の {}s 以下にする)",
                bantime.as_secs(),
                recidive.bantime.as_secs()
            ),
        });
    }
    Ok(())
}

/// ルールの mode を解決する。全体が nft でなければルールだけ nft にはできない。
fn resolve_mode(key: &'static str, rule: Option<Mode>, global: Mode) -> Result<Mode, ConfigError> {
    match (rule, global) {
        (Some(Mode::Nft), Mode::Log) => Err(ConfigError::InvalidValue {
            key,
            value: "nft (全体の mode が nft のときだけ指定できる)".to_string(),
        }),
        (Some(mode), _) => Ok(mode),
        (None, global) => Ok(global),
    }
}

fn badpath_from_raw(
    raw: RawBadpath,
    global: Mode,
    jail_bantime: Duration,
) -> Result<BadpathConfig, ConfigError> {
    let extra = raw.extra.unwrap_or_default();
    for pattern in &extra {
        build(pattern).map_err(|_| ConfigError::InvalidValue {
            key: "http.badpath.extra",
            value: pattern.clone(),
        })?;
    }
    Ok(BadpathConfig {
        enabled: raw.enabled.unwrap_or(true),
        mode: resolve_mode("http.badpath.mode", raw.mode, global)?,
        bantime: duration_or("http.badpath.bantime", raw.bantime, jail_bantime)?,
        extra,
    })
}

fn notfound_from_raw(
    raw: RawNotfound,
    global: Mode,
    jail_bantime: Duration,
) -> Result<NotfoundConfig, ConfigError> {
    let maxretry = raw.maxretry.unwrap_or(DEFAULT_NOTFOUND_MAXRETRY);
    if maxretry == 0 {
        return Err(ConfigError::InvalidValue {
            key: "http.notfound.maxretry",
            value: maxretry.to_string(),
        });
    }
    Ok(NotfoundConfig {
        enabled: raw.enabled.unwrap_or(true),
        mode: resolve_mode("http.notfound.mode", raw.mode, global)?,
        bantime: duration_or("http.notfound.bantime", raw.bantime, jail_bantime)?,
        maxretry,
        findtime: duration_or(
            "http.notfound.findtime",
            raw.findtime,
            DEFAULT_NOTFOUND_FINDTIME,
        )?,
    })
}
