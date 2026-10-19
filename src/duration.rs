//! 時間の書式 (`600`, `30s`, `10m`, `1h`, `1d`) を `Duration` に変換する。

use std::time::Duration;

use crate::config::ConfigError;

/// 秒数の書式を解釈する。単位がなければ秒とみなす。
///
/// 空文字、負数、未知の単位、0 秒、オーバーフローはエラーにする。
pub fn parse_duration(s: &str) -> Result<Duration, ConfigError> {
    let invalid = || ConfigError::InvalidDuration(s.to_string());

    let digits_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, unit) = s.split_at(digits_end);
    if digits.is_empty() {
        return Err(invalid());
    }

    let value: u64 = digits.parse().map_err(|_| invalid())?;
    let factor: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(invalid()),
    };
    let secs = value
        .checked_mul(factor)
        .filter(|&secs| secs > 0)
        .ok_or_else(invalid)?;
    Ok(Duration::from_secs(secs))
}
