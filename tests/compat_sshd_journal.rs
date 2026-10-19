//! 上流 fail2ban の sshd-journal テストデータ (tests/fixtures/sshd-journal) との互換性確認。
//!
//! normal モード (filterOptions に `mode` を持たない要素を含む節) だけを確かめる。

use fail2ban_rs::filter::SshdFilter;
use fail2ban_rs::ip::canonical_ip;
use fancy_regex::Regex;
use serde_json::Value;

/// 確かめた件数の下限。飛ばす条件が壊れて全部飛ばす事故を防ぐ。
const MIN_CHECKED: usize = 82;

/// 設計書の対象外 (MLF の複数行関連付け、prefregex の MLFID、pam の複数ユーザー計数、
/// 非 normal モード、DNS) のために合わない行。(ログ行の行番号, 理由)
const KNOWN_UNSUPPORTED: &[(usize, &str)] = &[
    (
        101,
        "MLF: 同じ MLFID の前の行から host を引き継いで失敗になる (複数行の関連付けは対象外)",
    ),
    (
        116,
        "MLF: 同じ MLFID の前の行から host を引き継いで失敗になる (複数行の関連付けは対象外)",
    ),
    (
        180,
        "MLF: 同じ MLFID の前の行から host を引き継いで失敗になる (複数行の関連付けは対象外)",
    ),
    (
        201,
        "MLF: 同じ MLFID の前の行から host を引き継いで失敗になる (複数行の関連付けは対象外)",
    ),
    (
        206,
        "MLF: 同じ MLFID の前の行から host を引き継いで失敗になる (複数行の関連付けは対象外)",
    ),
    (
        216,
        "MLF: 同じ MLFID の前の行から host を引き継いで失敗になる (複数行の関連付けは対象外)",
    ),
    (
        222,
        "非 normal モード: constraint が aggressive モードのときだけ有効な期待値",
    ),
];

struct Case {
    line_no: usize,
    message: String,
    expect: Value,
}

/// 節の filterOptions に mode を持たない要素があるか。
fn section_has_normal(json: &str) -> bool {
    match serde_json::from_str::<Value>(json) {
        Ok(Value::Array(items)) => items.iter().any(|v| v.get("mode").is_none()),
        Ok(obj @ Value::Object(_)) => obj.get("mode").is_none(),
        _ => false,
    }
}

fn parse_cases(text: &str) -> Vec<Case> {
    let prefix = Regex::new(r"^\S+ \S+?(?:\[\d+\])?: ").unwrap();
    let mut cases = Vec::new();
    let mut in_normal = false;
    let mut pending: Option<Value> = None;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        if let Some(rest) = line.strip_prefix("# filterOptions:") {
            in_normal = section_has_normal(rest.trim());
            pending = None;
        } else if let Some(rest) = line.strip_prefix("# failJSON:") {
            pending = Some(serde_json::from_str(rest.trim()).expect("failJSON が不正"));
        } else if line.starts_with('#') || line.is_empty() {
            continue;
        } else if let Some(expect) = pending.take() {
            if !in_normal {
                continue;
            }
            let message = match prefix.find(line).unwrap() {
                Some(m) => line[m.end()..].to_string(),
                None => line.to_string(),
            };
            cases.push(Case {
                line_no: i + 1,
                message,
                expect,
            });
        }
    }
    cases
}

fn expected_host(expect: &Value) -> Option<&str> {
    ["host", "ip4", "ip6"]
        .iter()
        .find_map(|k| expect.get(*k).and_then(Value::as_str))
}

#[test]
fn upstream_sshd_journal_corpus() {
    let text = std::fs::read_to_string("tests/fixtures/sshd-journal").expect("読めない");
    let filter = SshdFilter::new().expect("フィルタを作れない");
    let (mut checked, mut skipped, mut unsupported) = (0usize, 0usize, 0usize);
    let mut failures = Vec::new();

    for case in parse_cases(&text) {
        let matched = case
            .expect
            .get("match")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // 飛ばしてよいもの 2: 複数行の関連付けと pam の複数ユーザー計数
        if case.expect.get("attempts").is_some() || case.expect.get("users").is_some() {
            skipped += 1;
            continue;
        }
        let want_ip = if matched {
            let Some(ip) = expected_host(&case.expect).and_then(canonical_ip) else {
                // 飛ばしてよいもの 1: 期待の host が IP として解釈できない
                skipped += 1;
                continue;
            };
            Some(ip)
        } else {
            None
        };
        let result = filter.check(&case.message);
        let ok = match (&want_ip, &result) {
            (Some(ip), Some(m)) => !m.nofail && canonical_ip(&m.host) == Some(*ip),
            (Some(_), None) => false,
            (None, Some(m)) => m.nofail,
            (None, None) => true,
        };
        let known = KNOWN_UNSUPPORTED.iter().find(|(n, _)| *n == case.line_no);
        match (ok, known) {
            (true, None) => checked += 1,
            (false, Some(_)) => unsupported += 1,
            (false, None) => failures.push(format!(
                "line {}: {:?} => {:?} (期待 {})",
                case.line_no, case.message, result, case.expect
            )),
            (true, Some((n, _))) => failures.push(format!(
                "line {n}: KNOWN_UNSUPPORTED に載っているが合っている。項目を消すこと"
            )),
        }
    }
    eprintln!("checked={checked} skipped={skipped} known_unsupported={unsupported}");
    assert!(failures.is_empty(), "不一致:\n{}", failures.join("\n"));
    assert!(
        checked >= MIN_CHECKED,
        "確かめた件数が少なすぎる: {checked}"
    );
}
