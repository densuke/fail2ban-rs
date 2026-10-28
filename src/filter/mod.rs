//! ログ行から攻撃元を取り出すフィルタ。

mod expand;
mod sshd;

pub use expand::expand;
pub use sshd::SshdFilter;

use fancy_regex::{Regex, RegexBuilder};

/// 攻撃者が行を書けるので、バックトラックの上限を付ける。
const BACKTRACK_LIMIT: usize = 100_000;

/// 上限付きで正規表現を作る。フィルタはこれで式を作る。
pub(crate) fn build(pattern: &str) -> Result<Regex, FilterError> {
    RegexBuilder::new(pattern)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map_err(|e| FilterError::Regex {
            pattern: pattern.to_string(),
            source: Box::new(e),
        })
}

/// フィルタが行から取り出した結果。
#[derive(Debug, Clone, PartialEq)]
pub struct FilterMatch {
    /// 攻撃元のアドレス (IPv4 / IPv6 / ホスト名のいずれか)。
    pub host: String,
    pub user: Option<String>,
    /// 失敗として数えない行 (上流の `<F-NOFAIL>` / `<F-MLFGAINED>`)。
    pub nofail: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("正規表現を作れません: {pattern}: {source}")]
    Regex {
        pattern: String,
        #[source]
        source: Box<fancy_regex::Error>,
    },
}
