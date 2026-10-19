//! fail2ban の式テンプレート (`%(name)s`, `<name>`, `<HOST>`, `<F-XXX>`) の展開。

const MAX_ROUNDS: usize = 10;

const IP4: &str = r"(?:::f{4,6}:)?(?P<ip4>(?:\d{1,3}\.){3}\d{1,3})";
const IP6: &str = r"(?P<ip6>(?:[0-9a-fA-F]{1,4}::?|:){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):))";
const DNS: &str = r"(?P<dns>[\w\-.^_]*\w)";

/// `vars` の参照を、置き換えが無くなるまで (最大 10 回) 展開し、
/// そのあと `<HOST>` / `<ADDR>` / `<F-XXX>` を正規表現の断片にする。
pub fn expand(template: &str, vars: &[(&str, &str)]) -> String {
    let mut text = template.to_string();
    for _ in 0..MAX_ROUNDS {
        let next = vars.iter().fold(text.clone(), |acc, (name, value)| {
            acc.replace(&format!("%({name})s"), value)
                .replace(&format!("<{name}>"), value)
        });
        if next == text {
            break;
        }
        text = next;
    }
    expand_builtins(&text)
}

fn expand_builtins(text: &str) -> String {
    let host = format!(r"(?:\[?(?:{IP4}|{IP6})\]?|{DNS})");
    let addr = format!(r"(?:\[?(?:{IP4}|{IP6})\]?)");
    let text = text.replace("<HOST>", &host).replace("<ADDR>", &addr);
    expand_tags(&text)
}

/// `<F-XXX>` を群の開始に、`</F-XXX>` を `)` にする。
fn expand_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("<") {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        match parse_tag(tail) {
            Some((replacement, len)) => {
                out.push_str(replacement);
                rest = &tail[len..];
            }
            None => {
                out.push('<');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// 先頭が `<F-XXX>` / `</F-XXX>` なら (置換後の文字列, 元の長さ) を返す。
fn parse_tag(tail: &str) -> Option<(&'static str, usize)> {
    let (closing, body) = match tail.strip_prefix("</F-") {
        Some(b) => (true, b),
        None => (false, tail.strip_prefix("<F-")?),
    };
    let end = body.find('>')?;
    let name = &body[..end];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
        return None;
    }
    let len = tail.len() - body.len() + end + 1;
    let replacement = if closing {
        ")"
    } else {
        match name {
            "NOFAIL" => "(?P<nofail>",
            "MLFGAINED" => "(?P<mlfgained>",
            "USER" => "(?P<user>",
            "ALT_USER" => "(?P<alt_user>",
            _ => "(?:",
        }
    };
    Some((replacement, len))
}
