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
    resolve_conditions(&expand_builtins(&text))
}

/// `(?(name)yes|no)` を `(?(N)yes|no)` にする。
///
/// fancy-regex は名前の条件を「その文字列にマッチする先読み」と解釈し、
/// 上流 (Python の re) の「名前の群が当たっているか」にならないので、群の番号に直す。
fn resolve_conditions(pattern: &str) -> String {
    group_names(pattern)
        .into_iter()
        .fold(pattern.to_string(), |acc, (name, index)| {
            acc.replace(&format!("(?({name})"), &format!("(?({index})"))
        })
}

/// 名前つき群の (名前, 番号) を開き括弧の順に集める。
fn group_names(pattern: &str) -> Vec<(String, usize)> {
    let chars: Vec<char> = pattern.chars().collect();
    let (mut names, mut count, mut i, mut in_class) = (Vec::new(), 0, 0, false);
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => {
                if chars.get(i + 1) == Some(&'?') && chars.get(i + 2) == Some(&'(') {
                    // 条件式 `(?(cond)` の内側の括弧は群ではない
                    i += 2;
                } else if chars.get(i + 1) != Some(&'?') {
                    count += 1;
                } else if let Some(name) = named_group(&chars[i..]) {
                    count += 1;
                    names.push((name, count));
                }
            }
            _ => {}
        }
        i += 1;
    }
    names
}

/// `(?P<name>` / `(?<name>` なら name を返す (先読み・後読みは None)。
fn named_group(chars: &[char]) -> Option<String> {
    let head: String = chars.iter().take(64).collect();
    let rest = head
        .strip_prefix("(?P<")
        .or_else(|| head.strip_prefix("(?<"))?;
    if rest.starts_with('=') || rest.starts_with('!') {
        return None;
    }
    rest.find('>').map(|end| rest[..end].to_string())
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
