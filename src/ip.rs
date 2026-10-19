//! IP アドレスの正規化と ignoreip リスト。

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

use crate::config::ConfigError;

/// 文字列を IP アドレスとして解釈する。
///
/// 前後の `[` `]` は外し、IPv4 射影の IPv6 (`::ffff:a.b.c.d`) は IPv4 に変換する。
/// 解釈できなければ `None`。
pub fn canonical_ip(s: &str) -> Option<IpAddr> {
    let trimmed = s.strip_prefix('[').unwrap_or(s);
    let trimmed = trimmed.strip_suffix(']').unwrap_or(trimmed);
    IpAddr::from_str(trimmed).ok().map(|ip| ip.to_canonical())
}

/// 無視する IP / CIDR の集合。
pub struct IgnoreList {
    nets: Vec<IpNet>,
}

impl IgnoreList {
    /// 各要素を単独の IP または CIDR として解釈する。不正な要素があれば `Err`。
    pub fn parse(entries: &[String]) -> Result<Self, ConfigError> {
        let nets = entries
            .iter()
            .map(|entry| parse_entry(entry))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { nets })
    }

    /// `ip` がいずれかの要素に含まれるかを返す。`ip` は `canonical_ip` で正規化済みであること。
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(&ip))
    }
}

fn parse_entry(entry: &str) -> Result<IpNet, ConfigError> {
    let invalid = || ConfigError::InvalidIgnoreIp(entry.to_string());
    if entry.contains('/') {
        IpNet::from_str(entry).map_err(|_| invalid())
    } else {
        canonical_ip(entry).map(IpNet::from).ok_or_else(invalid)
    }
}
