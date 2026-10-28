//! Caddy の JSON アクセスログの読み取りと、既知のパスの判定。
//!
//! 攻撃者が書ける値 (Host、X-Forwarded-For、User-Agent、URI の中身) で、接続元以外の
//! IP を数えさせてはならない。接続元は Caddy が TCP の接続から作る `client_ip` /
//! `remote_ip` だけを見て、ヘッダは見ない。

use std::net::IpAddr;

use fancy_regex::Regex;
use serde_json::Value;

use super::{FilterError, build};
use crate::ip::canonical_ip;

/// アクセスログの 1 行から取り出した値。
#[derive(Debug, Clone, PartialEq)]
pub struct AccessEntry {
    pub ip: IpAddr,
    pub uri: String,
    pub status: u16,
}

/// `MESSAGE` の JSON を読む。アクセスログでない行・読めない行は `None`。
pub fn parse_access(message: &str) -> Option<AccessEntry> {
    let v: Value = serde_json::from_str(message).ok()?;
    if !v.get("logger")?.as_str()?.starts_with("http.log.access") {
        return None;
    }
    let status = u16::try_from(v.get("status")?.as_u64()?).ok()?;
    let request = v.get("request")?;
    let peer = request
        .get("client_ip")
        .or_else(|| request.get("remote_ip"))?
        .as_str()?;
    Some(AccessEntry {
        ip: canonical_ip(peer)?,
        uri: request.get("uri")?.as_str()?.to_string(),
        status,
    })
}

/// 区画がこれと一致したら当たる。
const BAD_SEGMENTS: &[&str] = &[
    ".git",
    ".aws",
    ".ssh",
    ".docker",
    ".claude",
    ".config",
    ".yarnrc",
    ".composer",
    ".gem",
    ".boto",
    "wp-login.php",
    "xmlrpc.php",
    "wp-admin",
    "wp-json",
    "wp-content",
    "wp-includes",
    "phpmyadmin",
    "cgi-bin",
    "phpinfo",
    "phpinfo.php",
];

/// 区画がこれで始まったら当たる (`.env.local`、`.env-example` など)。
const BAD_SEGMENT_PREFIX: &str = ".env";

/// パスの末尾がこれなら当たる (バックアップ探し)。
const BAD_SUFFIXES: &[&str] = &[".zip", ".rar", ".tar.gz", ".tgz", ".7z", ".sql", ".bak"];

/// クエリのキーがこれなら当たる。値は見ない。
const BAD_QUERY_KEYS: &[&str] = &["rest_route", "phpinfo"];

/// 既知の(正規でない)パスの判定器。組み込みの一覧に `extra` の正規表現を足せる。
pub struct BadPaths {
    extra: Vec<Regex>,
}

impl BadPaths {
    /// `extra` は組み込みの一覧に足す正規表現。設定の検証と同じ `build` で作る。
    pub fn new(extra: &[String]) -> Result<Self, FilterError> {
        let extra = extra
            .iter()
            .map(|p| build(p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { extra })
    }

    /// `uri` (パス + クエリ) が既知のパスに当たるか。
    pub fn matches(&self, uri: &str) -> bool {
        let (raw_path, query) = uri.split_once('?').unwrap_or((uri, ""));
        let path = decode_lower(raw_path);
        builtin_path(&path) || query_key_hit(query) || self.extra_hit(&path)
    }

    /// 正規表現が上限を超えて失敗したときは当たらないものとする。
    fn extra_hit(&self, path: &str) -> bool {
        self.extra
            .iter()
            .any(|re| re.is_match(path).unwrap_or(false))
    }
}

fn builtin_path(path: &str) -> bool {
    path.split('/')
        .filter(|s| !s.is_empty())
        .any(|s| s.starts_with(BAD_SEGMENT_PREFIX) || BAD_SEGMENTS.contains(&s))
        || BAD_SUFFIXES.iter().any(|suf| path.ends_with(suf))
}

fn query_key_hit(query: &str) -> bool {
    query
        .split('&')
        .map(|pair| pair.split_once('=').map_or(pair, |(k, _)| k))
        .any(|key| BAD_QUERY_KEYS.contains(&decode_lower(key).as_str()))
}

/// `%xx` を 1 回だけ解いて小文字にする。不正な `%` はそのまま残す。
fn decode_lower(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3).and_then(hex_pair))
            .flatten();
        match decoded {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_lowercase()
}

fn hex_pair(pair: &[u8]) -> Option<u8> {
    let hi = char::from(pair[0]).to_digit(16)?;
    let lo = char::from(pair[1]).to_digit(16)?;
    u8::try_from(hi * 16 + lo).ok()
}
