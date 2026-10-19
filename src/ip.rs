//! IP アドレスの正規化と ignoreip リスト。

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net};

use crate::config::ConfigError;

/// 文字列を IP アドレスとして解釈する。
///
/// 角括弧 `[` `]` は両方そろっている場合だけ外す。IPv4 射影の IPv6 (`::ffff:a.b.c.d`)
/// は IPv4 に変換する。解釈できなければ `None`。
pub fn canonical_ip(s: &str) -> Option<IpAddr> {
    let trimmed = match s.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        Some(inner) => inner,
        None if s.contains(['[', ']']) => return None,
        None => s,
    };
    IpAddr::from_str(trimmed).ok().map(|ip| ip.to_canonical())
}

/// 無視する IP / CIDR の集合。
#[derive(Debug, Clone)]
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

    /// `ip` がいずれかの要素に含まれるかを返す。
    /// IPv4 射影の IPv6 は内部で IPv4 に変換してから判定する。
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets.iter().any(|net| net.contains(&ip))
    }
}

fn parse_entry(entry: &str) -> Result<IpNet, ConfigError> {
    let invalid = || ConfigError::InvalidIgnoreIp(entry.to_string());
    if entry.contains('/') {
        let net = IpNet::from_str(entry).map_err(|_| invalid())?;
        canonical_net(net).ok_or_else(invalid)
    } else {
        canonical_ip(entry).map(IpNet::from).ok_or_else(invalid)
    }
}

/// IPv4 射影の IPv6 CIDR を対応する IPv4 CIDR に変換する。
/// 例: `::ffff:10.0.0.0/104` は `10.0.0.0/8`。射影の範囲 (prefix < 96) を含む場合は `None`。
/// 射影でない IPv6 CIDR はそのまま返す。
fn canonical_net(net: IpNet) -> Option<IpNet> {
    let IpNet::V6(v6) = net else {
        return Some(net);
    };
    let Some(v4) = v6.addr().to_ipv4_mapped() else {
        return Some(net);
    };
    let prefix = v6.prefix_len().checked_sub(96)?;
    Ipv4Net::new(v4, prefix).ok().map(IpNet::V4)
}
