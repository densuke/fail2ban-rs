//! 標準出力に出す行を作る。判断はここに寄せ、メインのループは出すだけにする。

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{HttpConfig, Mode, RecidiveConfig};
use crate::http_engine::HttpOutcome;

/// 出力に載せる URI の最大文字数。
const MAX_URI_CHARS: usize = 200;

/// URI を 1 行に収まる形にする。
///
/// 制御文字と空白は UTF-8 のバイトごとに `%XX` にし、ログの偽造や端末の制御を防ぐ。
/// 200 文字を超えたら切って `...` を付ける。
pub fn sanitize_uri(uri: &str) -> String {
    let mut out = String::new();
    for (i, c) in uri.chars().enumerate() {
        if i == MAX_URI_CHARS {
            out.push_str("...");
            break;
        }
        if c.is_control() || c.is_whitespace() {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Log => "log",
        Mode::Nft => "nft",
    }
}

fn recidive_text(recidive: &Option<RecidiveConfig>) -> String {
    match recidive {
        None => "off".to_string(),
        Some(r) => format!(
            "{}/{}s/{}s",
            r.maxbans,
            r.findtime.as_secs(),
            r.bantime.as_secs()
        ),
    }
}

/// HTTP jail の起動時の 1 行。
pub fn http_start_line(http: &HttpConfig) -> String {
    let badpath = if http.badpath.enabled {
        format!(
            "{}(+{} extra)",
            mode_name(http.badpath.mode),
            http.badpath.extra.len()
        )
    } else {
        "off".to_string()
    };
    let notfound = if http.notfound.enabled {
        format!(
            "{}/{}/{}s",
            mode_name(http.notfound.mode),
            http.notfound.maxretry,
            http.notfound.findtime.as_secs()
        )
    } else {
        "off".to_string()
    };
    format!(
        "start http bantime={}s badpath={badpath} notfound={notfound} recidive={}",
        http.bantime.as_secs(),
        recidive_text(&http.recidive)
    )
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn uri_suffix(uri: &Option<String>) -> String {
    uri.as_deref()
        .map(|u| format!(" uri={}", sanitize_uri(u)))
        .unwrap_or_default()
}

/// HTTP の結果に対応する出力の行。出さない結果は `None`。
pub fn http_outcome_line(outcome: &HttpOutcome) -> Option<String> {
    match outcome {
        HttpOutcome::Banned {
            ip,
            rule,
            bantime,
            long,
            uri,
        } => {
            let note = if *long { " (recidive)" } else { "" };
            Some(format!(
                "ban {ip} for {}s{note} jail=http rule={}{}",
                bantime.as_secs(),
                rule.as_str(),
                uri_suffix(uri)
            ))
        }
        HttpOutcome::WouldBan {
            ip,
            rule,
            bantime,
            uri,
        } => Some(format!(
            "would ban {ip} for {}s jail=http rule={}{}",
            bantime.as_secs(),
            rule.as_str(),
            uri_suffix(uri)
        )),
        HttpOutcome::AlreadyBanned { ip, rule, until } => Some(format!(
            "already banned {ip} until {} jail=http rule={}",
            unix_secs(*until),
            rule.as_str()
        )),
        HttpOutcome::Ignored(ip) => Some(format!("ignored {ip} jail=http")),
        HttpOutcome::NoMatch | HttpOutcome::Counted(_) => None,
    }
}

/// sshd で、すでにより長いブロックが続いていたときの行。
pub fn sshd_already_banned_line(ip: IpAddr, until: SystemTime) -> String {
    format!(
        "already banned {ip} until {} jail=sshd rule=sshd",
        unix_secs(until)
    )
}
