//! fail2ban 6c88de7 の `sshd.conf` (mode = normal, publickey = nofail) の移植。
//!
//! 式は `docs/upstream/sshd.conf` からそのまま写している。順序も上流と同じ。

use fancy_regex::{Regex, RegexBuilder};

use super::{FilterError, FilterMatch, expand};

/// 攻撃者が行を書けるので、バックトラックの上限を付ける。
const BACKTRACK_LIMIT: usize = 100_000;

/// 上流の `prefregex` のうち `__pref` の部分 (先頭の `error: ` など)。
const PREFIX: &str = r"^(?:(?:error|fatal): (?:PAM: )?)?";

const VARS: &[(&str, &str)] = &[
    ("__pref", r"(?:(?:error|fatal): (?:PAM: )?)?"),
    ("__on_port_opt", r"(?: port \d+)?"),
    ("__suff", r"%(__on_port_opt)s(?: \[preauth\])?\s*"),
    (
        "__authng_user",
        r"(?: (?:by|from))?(?: (?:invalid|authenticating) user <F-USER>\S+|.*?</F-USER>)?(?: from)?",
    ),
    ("__alg_match", r"(?:(?:\w+ (?!found\b)){0,2}\w+)"),
    ("__pam_auth", r"pam_[a-z]+"),
    // cmnfailed-nofail (publickey = nofail)
    ("cmnfailed", r"(?:<F-NOFAIL>publickey</F-NOFAIL>|\S+)"),
];

/// cmnfailre-failed-pub-invalid (publickey = nofail でも同じ式)
const PUB_INVALID: &str = r"^Failed publickey for invalid user <F-USER>(?P<cond_user>\S+)|(?:(?! from ).)*?</F-USER> from <HOST>%(__on_port_opt)s(?: ssh\d*)?(?(cond_user): |(?:(?:(?! from ).)*)$)";

/// mdre-normal-other
const MDRE_NORMAL_OTHER: &str = r"^<F-NOFAIL><F-MLFFORGET>(?:Connection (?:closed|reset)|Disconnect(?:ed|ing))</F-MLFFORGET></F-NOFAIL>%(__authng_user)s <ADDR>%(__on_port_opt)s(?:: (?!Too many authentication failures)[^\[]+)?(?: \[preauth\])?\s*$";

/// cmnfailre の各行 -> cfooterre の順 (mdre-normal は空)。
fn templates() -> Vec<&'static str> {
    vec![
        r"^[aA]uthentication (?:failure|error|failed) for <F-USER>.*?</F-USER> (?:from )?<HOST>( via \S+)?%(__suff)s$",
        r"^User not known to the underlying authentication module for <F-USER>.*?</F-USER> (?:from )?<HOST>%(__suff)s$",
        PUB_INVALID,
        r"^Failed <cmnfailed> for (?P<cond_inv>invalid user )?<F-USER>(?P<cond_user>\S+)|(?(cond_inv)(?:(?! from ).)*?|[^:]+)</F-USER> from <HOST>%(__on_port_opt)s(?: ssh\d*)?(?(cond_user): |(?:(?:(?! from ).)*)$)",
        r"^<F-USER>ROOT</F-USER> LOGIN REFUSED FROM <HOST>",
        r"^[iI](?:llegal|nvalid) user <F-USER>.*?</F-USER> (?:from )?<HOST>%(__suff)s$",
        r"^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because not listed in AllowUsers%(__suff)s$",
        r"^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because listed in DenyUsers%(__suff)s$",
        r"^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because not in any group%(__suff)s$",
        r"^refused connect from \S+ \(<HOST>\)",
        r"^Received <F-MLFFORGET>disconnect</F-MLFFORGET> from <HOST>%(__on_port_opt)s:\s*3: .*: Auth fail%(__suff)s$",
        r"^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because a group is listed in DenyGroups%(__suff)s$",
        r"^User <F-USER>\S+|.*?</F-USER> (?:from )?<HOST> not allowed because none of user's groups are listed in AllowGroups%(__suff)s$",
        r"^<F-NOFAIL>%(__pam_auth)s\(sshd:auth\):\s+authentication failure;</F-NOFAIL>(?:\s+(?:(?:logname|e?uid|tty)=\S*)){0,4}\s+ruser=<F-ALT_USER>\S*</F-ALT_USER>\s+rhost=<HOST>(?:\s+user=<F-USER>\S*</F-USER>)?%(__suff)s$",
        r"^maximum authentication attempts exceeded for (?:invalid user )?<F-USER>.*?</F-USER> (?:from )?<HOST>%(__on_port_opt)s(?: ssh\d*)?%(__suff)s$",
        r"^User <F-USER>\S+|.*?</F-USER> not allowed because account is locked%(__suff)s",
        r"^<F-MLFFORGET>Disconnecting</F-MLFFORGET>(?: from)?(?: (?:invalid|authenticating)) user <F-USER>\S+</F-USER> <HOST>%(__on_port_opt)s:\s*Change of username or service not allowed:\s*.*\[preauth\]\s*$",
        r"^Disconnecting: Too many authentication failures(?: for <F-USER>\S+|.*?</F-USER>)?%(__suff)s$",
        r"^<F-NOFAIL>Received <F-MLFFORGET>disconnect</F-MLFFORGET></F-NOFAIL> from <HOST>%(__on_port_opt)s:\s*11:",
        MDRE_NORMAL_OTHER,
        r"^<F-MLFFORGET><F-MLFGAINED>Accepted \w+</F-MLFGAINED></F-MLFFORGET> for <F-USER>\S+</F-USER> from <HOST>(?:\s|$)",
        // cfooterre
        r"^<F-NOFAIL>Connection from</F-NOFAIL> <HOST>",
    ]
}

fn build(pattern: &str) -> Result<Regex, FilterError> {
    RegexBuilder::new(pattern)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map_err(|e| FilterError::Regex {
            pattern: pattern.to_string(),
            source: Box::new(e),
        })
}

pub struct SshdFilter {
    prefix: Regex,
    failregex: Vec<Regex>,
}

impl SshdFilter {
    pub fn new() -> Result<Self, FilterError> {
        let failregex = templates()
            .into_iter()
            .map(|t| expand(t, VARS))
            .filter(|p| !p.is_empty())
            .map(|p| build(&p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            prefix: build(PREFIX)?,
            failregex,
        })
    }

    /// 最初に当たった式の結果を返す。実行時のエラー (バックトラック上限など) は不一致扱い。
    pub fn check(&self, message: &str) -> Option<FilterMatch> {
        let body = match self.prefix.find(message) {
            Ok(Some(m)) => &message[m.end()..],
            _ => message,
        };
        self.failregex
            .iter()
            .find_map(|re| match re.captures(body) {
                Ok(Some(caps)) => to_match(&caps),
                _ => None,
            })
    }
}

fn to_match(caps: &fancy_regex::Captures<'_, str>) -> Option<FilterMatch> {
    let group = |name: &str| caps.name(name).map(|m| m.as_str().to_string());
    let host = group("ip4")
        .or_else(|| group("ip6"))
        .or_else(|| group("dns"))?;
    Some(FilterMatch {
        host,
        user: group("user"),
        // <F-MLFGAINED> (成功したログイン) も失敗としては数えない
        nofail: caps.name("nofail").is_some() || caps.name("mlfgained").is_some(),
    })
}
