# 複数の jail と HTTP jail 実装計画 (v0.4.0)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** sshd の jail をそのまま残したまま、Caddy の JSON アクセスログを読む HTTP の jail (既知のパス・404 の回数・recidive、ルールごとの記録モード) を足す。

**Architecture:** jail ごとに journalctl の読み取りスレッドを立て、`(JailId, LogEntry)` を 1 本の channel に送る。メインのループが jail ごとの Engine (`Engine` = sshd、`HttpEngine` = HTTP) に振り分ける。両 Engine は共有の `BanLedger` (IP ごとのブロックの終わる時刻) を見て、長いブロックを短く上書きしない。出力の行は `report.rs` の純粋関数で組み立てる。

**Tech Stack:** Rust edition 2024 / fancy-regex 0.19 / serde + serde_json / toml / clap 4 / ipnet / thiserror (依存は増やさない)

**Spec:** `docs/superpowers/specs/2026-10-28-multi-jail-http-design.md` (前提として `docs/superpowers/specs/2026-10-20-fail2ban-rs-design.md` も読む)

## Global Constraints

- 依存を増やさない。dev 用も今の `tempfile` だけ。
- 対象は `x86_64-unknown-linux-musl` と `aarch64-unknown-linux-musl` の静的バイナリのまま。
- テスト以外で `unwrap()` / `expect()` を使わない。1 ファイル 400 行以内。コメント・README は日本語。絵文字は使わない。
- 正規表現は `fancy_regex::RegexBuilder` で `backtrack_limit(100_000)` を付けて作る (今の `filter/sshd.rs` の `build` を `filter/mod.rs` に移して共用する)。
- 今の sshd の設定ファイル・起動の行・`ban` / `would ban` / `ignored` の行の形は変えない。既存のテストは中身を変えずに通す (`render_command`・`Engine::new`・`spawn_reader` の呼び出しの引数追加だけは可)。
- HTTP の既定値: `[http] bantime` 300 秒 / journalmatch `["_SYSTEMD_UNIT=caddy.service"]` / `notfound` maxretry 20・findtime 600 秒 / `[http.recidive]` maxbans 3・findtime 86400 秒・bantime 86400 秒。
- テストのデータは手で作り、IP は 192.0.2.0/24、198.51.100.0/24、203.0.113.0/24、2001:db8::/32 を使う。e2 の実ログはリポジトリに入れない。
- 各タスクの最後に `cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` が通ること。
- コミットの末尾に `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` を付ける。

## Review Focus

- 攻撃者が `X-Forwarded-For: 198.51.100.9` を送る → 接続元は `request.client_ip` (無ければ `remote_ip`) のままで、198.51.100.9 は数えない。(Task 2 にテスト)
- `http.log.error` など access 以外の logger の行 (`request` も `status` も持ちうる) → 捨てる。(Task 2 にテスト)
- feedgen の `/feed?url=https://example.com/.env/a.zip` のように、クエリの値に穴探しと同じ文字列が入る → 当たらない。(Task 2 にテスト)
- `/%2E%65nv`、`/.ENV`、`/blog/WP-JSON/`、不正な `%zz`・`%` で終わるパス → 前の 3 つは当たり、不正な `%` は panic せずそのまま扱う。(Task 2 にテスト)
- 攻撃者の URI に改行や ESC が入る → `ban` の行の `uri=` はエスケープされ、1 行のまま。(Task 6 にテスト)

---

### Task 1: HTTP の設定

**Model:** sonnet

**Files:**
- Create: `src/config/http.rs` (`src/config.rs` から `mod http;` で読む)
- Modify: `src/config.rs` (`Config` に `http` を足す、recidive の検証を jail の名前で切り替える)
- Test: `tests/config_http_test.rs`

**Interfaces:**
- Produces (`fail2ban_rs::config` から `pub use`):
  - `#[derive(Debug, Clone, PartialEq)] pub struct HttpConfig { pub enabled: bool, pub bantime: Duration, pub journalmatch: Vec<String>, pub badpath: BadpathConfig, pub notfound: NotfoundConfig, pub recidive: Option<RecidiveConfig> }`
  - `#[derive(Debug, Clone, PartialEq)] pub struct BadpathConfig { pub enabled: bool, pub mode: Mode, pub extra: Vec<String> }`
  - `#[derive(Debug, Clone, PartialEq)] pub struct NotfoundConfig { pub enabled: bool, pub mode: Mode, pub maxretry: u32, pub findtime: Duration }`
  - `Config` に `pub http: Option<HttpConfig>` (`[http]` が無ければ `None`)。
  - `Mode` に `Copy` は既にある。ルールの `mode` は解決済みの値 (省略時は全体の `mode`) を入れる。

- [ ] **Step 1: 失敗するテストを書く** (`tests/config_http_test.rs`)
  - `parse_config("").http == None`
  - `parse_config("mode = \"nft\"\n[http]")` → `http` が `Some` で、enabled true、bantime 300s、journalmatch `["_SYSTEMD_UNIT=caddy.service"]`、badpath `{ enabled: true, mode: Nft, extra: [] }`、notfound `{ enabled: true, mode: Nft, maxretry: 20, findtime: 600s }`、recidive `None`
  - `mode = "nft"` で `[http.notfound] mode = "log"` → notfound の mode は Log、badpath は Nft
  - `mode = "log"` (または省略) で `[http.badpath] mode = "nft"` → `Err` (全体が log のときにルールだけ nft は不可)
  - `[http.recidive]` だけ書く → `Some(RecidiveConfig { maxbans: 3, findtime: 86400s, bantime: 86400s })`
  - `[http] bantime = "1d"` と `[http.recidive]` → `Err`、メッセージに `http.recidive.bantime` を含む
  - `[http.badpath] extra = ["("]` (正規表現として不正) → `Err`、メッセージに `http.badpath.extra` を含む
  - `[http.notfound] maxretry = 0` → `Err`
  - `[http] journalmatch = ["-f"]` → `Err`
  - `[http.badpath] enabled = false` → badpath の enabled false
  - `[http] foo = 1` → `Err` (未知のキー)
  - 既存の `tests/config_test.rs` (sshd の recidive の `sshd.recidive.bantime` のメッセージを含む) がそのまま通る
- [ ] **Step 2:** `cargo test --test config_http_test` が失敗することを確かめる。
- [ ] **Step 3:** 実装する。`ConfigError::InvalidValue` の `key` は `&'static str` のままにし、recidive と journalmatch の検証には jail ごとのキーの組 (`"sshd.recidive.bantime"` / `"http.recidive.bantime"` など) を渡す。`extra` は Task 2 で使う `filter::build` で 1 本ずつ作れるか確かめる (作った値は捨てる)。そのため `build` の移動 (Global Constraints) をこのタスクで行う。
- [ ] **Step 4:** `cargo test` がすべて通る。
- [ ] **Step 5:** Commit `feat: [http] の設定を読む`

---

### Task 2: Caddy のアクセスログの読み取りと既知のパスの判定

**Model:** sonnet

**Files:**
- Create: `src/filter/caddy.rs`
- Modify: `src/filter/mod.rs` (`pub use caddy::{AccessEntry, BadPaths, parse_access};`)
- Test: `tests/caddy_filter_test.rs`

**Interfaces:**
- Consumes: `crate::ip::canonical_ip`、`filter::build` (Task 1 で移動)
- Produces:
  - `#[derive(Debug, Clone, PartialEq)] pub struct AccessEntry { pub ip: IpAddr, pub uri: String, pub status: u16 }`
  - `pub fn parse_access(message: &str) -> Option<AccessEntry>` — `MESSAGE` の JSON を読む。`logger` が `http.log.access` で始まらない、`status` が無い、接続元が IP でない行は `None`。接続元は `request.client_ip`、無ければ `request.remote_ip`。ヘッダは見ない。
  - `pub struct BadPaths` / `impl BadPaths { pub fn new(extra: &[String]) -> Result<Self, FilterError>; pub fn matches(&self, uri: &str) -> bool }`

- [ ] **Step 1: 失敗するテストを書く** (`tests/caddy_filter_test.rs`)
  - 行は `{"level":"info","logger":"http.log.access.log0","request":{"remote_ip":"203.0.113.7","client_ip":"203.0.113.7","host":"fuga.jp","uri":"/.env","headers":{"X-Forwarded-For":["198.51.100.9"]}},"status":404}` の形で作るヘルパを置く。
  - `parse_access` が `AccessEntry { ip: 203.0.113.7, uri: "/.env", status: 404 }` を返す (X-Forwarded-For は無視)
  - `client_ip` が無く `remote_ip` だけ → remote_ip を使う
  - `client_ip` が `"::ffff:192.0.2.1"` → `192.0.2.1`、`"2001:db8::1"` → IPv6 のまま
  - `logger` が `"http.log.error"` の行、JSON でない行、`status` の無い行、`client_ip` が `"example.com"` の行 → `None`
  - `BadPaths::new(&[])` で次が `true`: `/.env`、`/app/.env.local`、`/.env-example`、`/.git/config`、`/.aws/credentials`、`/.ssh/id_rsa`、`/.claude/settings.json`、`/wp-login.php`、`/blog/wp-json/`、`/BLOG/WP-JSON/`、`/xmlrpc.php`、`/phpmyadmin/`、`/cgi-bin/x`、`/phpinfo.php`、`/_profiler/phpinfo`、`/backup.zip`、`/b45d3cda3836.tar.gz`、`/dump.sql`、`/db.bak`、`/?rest_route=/`、`/?phpinfo=1`、`/%2E%65nv`
  - 次が `false`: `/`、`/login`、`/feed?url=https://example.com/.env/a.zip`、`/feed?url=http://example.com/?rest_route=/`、`/posts/phpinfo-tips`、`/environment`、`/a%zz`、`/a%`
  - `/.envoy` は `true` (`.env` で始まる区画なので当たる。設計書どおり)
  - `BadPaths::new(&["^/\\.svn/".into()])` で `/.svn/entries` が `true`、`BadPaths::new(&[])` では `false`
- [ ] **Step 2:** `cargo test --test caddy_filter_test` が失敗することを確かめる。
- [ ] **Step 3:** 実装する。判定は設計書「既知のパスのルール」のとおり (区画の完全一致・`.env` で始まる区画・末尾の拡張子・クエリのキー名)。`%xx` の解き方は自前で書き、不正な `%` はそのまま残す。解いたバイト列は `String::from_utf8_lossy` で読む。`extra` は解いて小文字にしたパス全体に当てる。
- [ ] **Step 4:** `cargo test` がすべて通る。
- [ ] **Step 5:** Commit `feat: Caddy のアクセスログを読み、既知のパスを判定する`

---

### Task 3: ブロックの終わる時刻の表と、sshd の Engine への組み込み

**Model:** sonnet

**Files:**
- Create: `src/ledger.rs`
- Modify: `src/tracker.rs` (`would_reach` を足す)、`src/engine.rs`、`src/lib.rs`
- Test: `tests/ledger_test.rs`、`tests/tracker_test.rs` (追記)、`tests/engine_test.rs` (追記)

**Interfaces:**
- Produces:
  - `pub struct BanLedger` / `impl BanLedger { pub fn new() -> Self; pub fn admit(&mut self, ip: IpAddr, at: SystemTime, bantime: Duration) -> Result<(), SystemTime>; pub fn prune(&mut self, now: SystemTime) }` — `admit` は、今の終わる時刻が `at + bantime` 以上なら `Err(今の終わる時刻)` を返して何も変えない。そうでなければ終わる時刻を `at + bantime` にして `Ok(())`。`prune` は終わる時刻が `now` 以前の IP を消す。
  - `pub type SharedLedger = std::rc::Rc<std::cell::RefCell<BanLedger>>`
  - `FailTracker::would_reach(&self, ip: IpAddr, at: SystemTime) -> bool` — `record(ip, at)` をしたら `true` になるかを、状態を変えずに返す。
  - `Engine::new(config: &Config, action: A, ledger: Option<SharedLedger>) -> Result<Self, EngineError>` — `None` なら表を見ない (log モードの sshd はこれ。今と同じ動作)。
  - `Outcome` に `AlreadyBanned(IpAddr, SystemTime)` を足す。

- [ ] **Step 1: 失敗するテストを書く**
  - ledger: 空の表に `admit(ip, t, 300s)` は `Ok`。続けて `admit(ip, t+60s, 300s)` は `Ok` (終わりが延びる)。`admit(ip, t, 86400s)` のあと `admit(ip, t+60s, 300s)` は `Err(t+86400s)`。`prune(t+86400s)` のあとは `admit(ip, t+86401s, 300s)` が `Ok`。別の IP は互いに影響しない。
  - tracker: maxretry 3 で 2 回記録したあと `would_reach(ip, t)` は `true`、呼んだあとも `len()` は変わらない。窓の外の記録は数えない。
  - engine: ledger 付きで、sshd の recidive (maxbans 3) を有効にした設定。同じ IP に (a) 表に 1 日の終わる時刻を先に入れておく → 閾値に達しても `Outcome::AlreadyBanned(ip, t+86400s)` で、action の `ban` は呼ばれない (b) そのあと recidive の回数が増えていない (続けて 3 回ブロックさせて、3 回目までは長期にならないことで確かめる)。ledger が `None` の Engine は今の engine_test の振る舞いのまま。
- [ ] **Step 2:** 新しいテストが失敗することを確かめる。
- [ ] **Step 3:** 実装する。`Engine::handle` は、閾値に達したら `recidive` の tracker で `would_reach` を見て長期かどうかを決め、ledger があれば `admit(ip, entry.time, bantime)`。`Err` なら `AlreadyBanned` を返す (recidive に記録しない)。`Ok` なら recidive に `record` して、今と同じく `ban`。時刻はすべて `entry.time` を使う。`Engine::prune` は ledger も掃除しない (掃除はメインのループが 1 回だけ行う)。既存の `Engine::new` の呼び出し (main.rs、tests) は `None` を渡すように直す。
- [ ] **Step 4:** `cargo test` がすべて通る。
- [ ] **Step 5:** Commit `feat: 長いブロックを短いブロックで上書きしない`

---

### Task 4: HTTP の Engine

**Model:** sonnet

**Files:**
- Create: `src/http_engine.rs`
- Modify: `src/lib.rs`
- Test: `tests/http_engine_test.rs`

**Interfaces:**
- Consumes: `HttpConfig` (Task 1)、`parse_access` / `BadPaths` (Task 2)、`BanLedger` / `SharedLedger` / `FailTracker::would_reach` (Task 3)、`BanAction`、`IgnoreList`
- Produces:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum HttpRule { Badpath, Notfound }` と `pub fn as_str(self) -> &'static str` (`"badpath"` / `"notfound"`)
  - `#[derive(Debug, Clone, PartialEq)] pub enum HttpOutcome { NoMatch, Ignored(IpAddr), Counted(IpAddr), Banned { ip: IpAddr, rule: HttpRule, bantime: Duration, long: bool, uri: Option<String> }, WouldBan { ip: IpAddr, rule: HttpRule, bantime: Duration, uri: Option<String> }, AlreadyBanned { ip: IpAddr, rule: HttpRule, until: SystemTime } }` — `uri` は badpath のときだけ `Some(当たった URI)`。
  - `pub struct HttpEngine<A: BanAction>` / `impl { pub fn new(http: &HttpConfig, ignoreip: &[String], action: A, ledger: SharedLedger) -> Result<Self, EngineError>; pub fn handle(&mut self, entry: &LogEntry) -> Result<HttpOutcome, ActionError>; pub fn prune(&mut self, now: SystemTime) }`

- [ ] **Step 1: 失敗するテストを書く** (`tests/http_engine_test.rs`。BanAction は engine_test と同じ記録用のものを置く)
  - `/.env` の 404 が 1 行 → `Banned { rule: Badpath, bantime: 300s, long: false, uri: Some("/.env") }`、action に `(ip, 300s)`
  - ステータス 502 や 303 の `/.env` でも Badpath で Banned
  - `/x1`〜`/x19` の 404 (10 分以内) は `Counted`、20 本目で `Banned { rule: Notfound, uri: None }`。10 分を超えて間が空いた 404 は数え直し
  - 200 の `/` は `NoMatch`。404 でも `notfound.enabled = false` なら `NoMatch`
  - `/.env` の 404 の行で、badpath と notfound の両方が閾値に達しても、ブロックは 1 回 (Badpath)
  - ignoreip の IP の `/.env` → `Ignored(ip)`、action は呼ばれない
  - `[http.badpath] mode = "log"` (全体は nft) → `WouldBan { rule: Badpath, bantime: 300s }`、action は呼ばれず、ledger にも載らない、recidive の回数にも足さない (同じ IP が 3 回 WouldBan のあと nft のルールで 1 回ブロックしても長期にならない)
  - recidive (maxbans 3) あり: 同じ IP が badpath・notfound・badpath の順に 3 回ブロック (各回の間は 300 秒以上空ける) → 3 回目が `Banned { long: true, bantime: 86400s }`
  - ledger に 1 日の終わる時刻がある IP の `/.env` → `AlreadyBanned { rule: Badpath, until }`、action は呼ばれない
  - access 以外の logger の行 → `NoMatch`
- [ ] **Step 2:** `cargo test --test http_engine_test` が失敗することを確かめる。
- [ ] **Step 3:** 実装する。1 行の処理の順番:
  1. `parse_access` が `None` なら `NoMatch`。
  2. badpath が有効で当たる行でも、notfound が有効で 404 の行でもなければ `NoMatch`。
  3. ignoreip の IP なら `Ignored` (何も記録しない)。
  4. badpath が有効で当たれば、badpath のルールで閾値に達したものとする (404 の tracker には記録しない)。
  5. そうでなければ 404 を notfound の tracker に `record`。閾値に達しなければ `Counted`。
  6. 閾値に達したルールの mode が log なら `WouldBan`。nft なら Task 3 と同じ手順 (recidive の `would_reach` → ledger の `admit` (`Err` なら `AlreadyBanned`) → recidive の `record` → `ban` → `Banned`)。
- [ ] **Step 4:** `cargo test` がすべて通る。
- [ ] **Step 5:** Commit `feat: HTTP の jail の判定とブロック`

---

### Task 5: 通知の置き換えに {jail} と {rule}

**Model:** haiku

**Files:**
- Modify: `src/notify.rs`、`src/main.rs` (呼び出し)、`tests/notify_test.rs`、`deploy/config.example.toml`、`README.md` (通知の節)

**Interfaces:**
- Produces: `pub fn render_command(template: &[String], ip: IpAddr, bantime: Duration, kind: &str, jail: &str, rule: &str) -> Vec<String>`

- [ ] **Step 1:** `tests/notify_test.rs` に、`["{jail}:{rule}:{kind}"]` が `jail = "http"`、`rule = "badpath"`、`kind = "長期"` で `["http:badpath:長期"]` になるテストを足す。既存のテストは `jail = "sshd"`、`rule = "sshd"` を渡すように引数だけ足す。
- [ ] **Step 2:** 失敗を確かめ、実装し、通ることを確かめる。main.rs の sshd の呼び出しは `"sshd", "sshd"` を渡す。
- [ ] **Step 3:** config.example.toml と README の通知の説明に `{jail}` (`sshd` / `http`) と `{rule}` (`sshd` / `badpath` / `notfound`) を足す。
- [ ] **Step 4:** Commit `feat: 通知のコマンドに {jail} と {rule} を渡す`

---

### Task 6: 出力の行と、複数の jail を回すメインのループ

**Model:** sonnet

**Files:**
- Create: `src/report.rs` (出力の行を作る純粋関数)
- Modify: `src/journal.rs` (`spawn_reader` に jail の印)、`src/main.rs`、`src/lib.rs`
- Test: `tests/report_test.rs`、`tests/journal_test.rs` (呼び出しを直す)

**Interfaces:**
- Consumes: Task 3〜5 のすべて
- Produces:
  - `pub fn spawn_reader<T: Copy + Send + 'static>(journalctl: PathBuf, matches: Vec<String>, findtime: Duration, tag: T, tx: Sender<(T, LogEntry)>) -> JoinHandle<()>`
  - `report.rs`:
    - `pub fn sanitize_uri(uri: &str) -> String` — 制御文字と空白 (`char::is_control` か `char::is_whitespace`) を UTF-8 のバイトごとに `%XX` (大文字の 16 進) にする。200 文字を超えたら 200 文字で切って `...` を付ける。
    - `pub fn http_start_line(http: &HttpConfig) -> String` — 例 `start http bantime=300s badpath=nft(+0 extra) notfound=nft/20/600s recidive=3/86400s/86400s`。無効なルールは `badpath=off`、recidive が無ければ `recidive=off`、mode は小文字。
    - `pub fn http_outcome_line(outcome: &HttpOutcome) -> Option<String>` — `Banned`: `ban <ip> for <secs>s[ (recidive)] jail=http rule=<rule>[ uri=<sanitize_uri>]`。`WouldBan`: `would ban <ip> for <secs>s jail=http rule=<rule>[ uri=...]`。`AlreadyBanned`: `already banned <ip> until <UNIX 秒> jail=http rule=<rule>`。`Ignored`: `ignored <ip> jail=http`。それ以外は `None`。
    - `pub fn sshd_already_banned_line(ip: IpAddr, until: SystemTime) -> String` — `already banned <ip> until <UNIX 秒> jail=sshd rule=sshd`
  - 今の sshd の起動の行・`ban`・`ignored` の行は main.rs の今の書式のまま (report.rs に移してもよいが、文字列は変えない)。

- [ ] **Step 1: 失敗するテストを書く** (`tests/report_test.rs`)
  - `sanitize_uri("/a b\n\x1b[31m")` == `"/a%20b%0A%1B[31m"`、`sanitize_uri` に 300 文字の `/aaa...` → 200 文字 + `...`、`/日本語` はそのまま
  - `http_start_line` が既定の `[http]` + `[http.recidive]` (mode nft) で `start http bantime=300s badpath=nft(+0 extra) notfound=nft/20/600s recidive=3/86400s/86400s`。notfound を `enabled = false`、recidive なしで `... notfound=off recidive=off`
  - `http_outcome_line` の各行が上の書式どおり。例: `ban 203.0.113.7 for 300s jail=http rule=badpath uri=/.env`、`ban 203.0.113.7 for 86400s (recidive) jail=http rule=notfound`、`would ban 203.0.113.8 for 300s jail=http rule=notfound`、`already banned 203.0.113.7 until 1700086400 jail=http rule=badpath`
  - 改行入りの URI の `Banned` の行が 1 行 (`'\n'` を含まない)
- [ ] **Step 2:** 失敗を確かめる。
- [ ] **Step 3:** report.rs を実装する。
- [ ] **Step 4:** `spawn_reader` に `tag` を足し、`tests/journal_test.rs` の呼び出しを `((), LogEntry)` を受けるように直す。
- [ ] **Step 5:** main.rs の `run` を直す:
  - 有効な jail (sshd の `enabled`、`http` が `Some` で `enabled`) が 1 つも無ければ `no jail is enabled; exiting` を出して正常終了。今の `sshd jail is disabled; exiting` は消す。
  - `enum JailId { Sshd, Http }` で読み取りスレッドを jail ごとに起動する。HTTP の `findtime` には `notfound.findtime` を渡す。
  - ledger は 1 つ作り、mode が nft のときだけ sshd の Engine に渡す。HTTP の Engine には常に渡す (log のルールは表を見ないので問題ない)。
  - 起動の行は、sshd が有効なら今の行、HTTP が有効なら `http_start_line`。
  - HTTP の `Banned` / `WouldBan` のとき、`on_ban` があれば `render_command(.., kind, "http", rule.as_str())` で通知する (log のルールの `WouldBan` でも通知する。今の log モードと同じ)。`AlreadyBanned` では通知しない。
  - sshd の `AlreadyBanned` は `sshd_already_banned_line` を出し、通知はしない。
  - 古い記録の掃除 (今の `PRUNE_EVERY` と `RECV_TIMEOUT`) で、両 Engine と ledger (`SystemTime::now()`) を掃除する。
  - main.rs が 400 行を超えるなら、ループを `src/daemon.rs` に移す。
- [ ] **Step 6:** `cargo test` がすべて通る。手で確かめる: `printf 'mode = "log"\n[http]\n' > /tmp/x.toml && cargo run -- check-config --config /tmp/x.toml` が `http: Some(...)` を表示する。
- [ ] **Step 7:** Commit `feat: sshd と HTTP の jail を同時に動かす`

---

### Task 7: test-filter --jail http

**Model:** haiku

**Files:**
- Modify: `src/main.rs`
- Test: `tests/cli_test_filter.rs` (新規。`env!("CARGO_BIN_EXE_fail2ban-rs")` でバイナリを起動する)

**Interfaces:**
- Consumes: `parse_access`、`BadPaths::new(&[])`
- Produces: `fail2ban-rs test-filter [--jail sshd|http] [FILE]`。`--jail` の既定は `sshd` (今の動作)。`http` では 1 行 1 件の Caddy の JSON を読み、行ごとに `badpath <ip> <sanitize_uri(uri)>`、404 なら `notfound <ip>`、それ以外 (読めない行を含む) は `other` を出す。最後に `badpath <n> notfound <m> other <k> / <total> lines`。

- [ ] **Step 1:** テストを書く: 3 行 (`/.env` の 404、`/x` の 404、`/` の 200) を標準入力に渡し、出力が `badpath 203.0.113.7 /.env`、`notfound 203.0.113.7`、`other`、`badpath 1 notfound 1 other 1 / 3 lines` であること。`--jail` なしの今の sshd の動作が変わらないこと (sshd の失敗の行 1 本で `fail ...` と `matched 1/1 lines`)。
- [ ] **Step 2:** 失敗を確かめ、実装し、通ることを確かめる。
- [ ] **Step 3:** README の `test-filter` の節に `--jail http` の例を足す: `journalctl -u caddy -o cat | fail2ban-rs test-filter --jail http`
- [ ] **Step 4:** Commit `feat: test-filter で Caddy のログを試せるようにする`

---

### Task 8: 文書・設定例・版の更新と、e2 のログでの確認

**Model:** sonnet

**Files:**
- Modify: `README.md`、`deploy/config.example.toml`、`Cargo.toml` (`version = "0.4.0"`、`description` を「sshd と Caddy (HTTP)」に)

- [ ] **Step 1:** README に「HTTP (Caddy) の jail」の節を足す: Caddy のアクセスログを journal に出す方法 (`log` を各サイトに `import` する snippet の例)、2 つのルールと recidive、ルールごとの `mode`、`already banned` の行、`jail=` / `rule=` の付いた行を `journalctl -u fail2ban-rs | grep 'jail=http'` で数えられること。「対象外の機能」の「sshd 以外のジェイル」を「sshd と Caddy 以外のジェイル」に直す。
- [ ] **Step 2:** config.example.toml に、設計書「設定の形」の `[http]` 一式をコメント付きで足す (既定では `[http]` を書かない = 無効、の形でコメントアウトしておく)。
- [ ] **Step 3:** `cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test` が通る。
- [ ] **Step 4:** e2 で確かめる (**e2 に触る前にユーザーに確認する**)。aarch64 / x86_64 のうち e2 に合う musl のバイナリを作って e2 の一時ディレクトリに置き、`sudo journalctl -u caddy --since "2026-10-26 08:06" -o cat | ./fail2ban-rs test-filter --jail http` を実行する。期待: badpath の行が 2,500 前後 (設計書の集計では 2,494 行・71 IP)、`uri` の欄に正規の利用 (feedgen・rss-proxy の `/feed?url=`、Slackbot・GoogleChatRssApp) が出ない。大きく違えば理由を調べ、ユーザーに報告する。置いた一時ファイルは消す。
- [ ] **Step 5:** Commit `docs: HTTP の jail の説明を足し、v0.4.0 にする`

デプロイ (e2 のバイナリの入れ替え、`config.toml` の変更、`fail2ban-rs-notify-long` への `{jail}` の追加) は、この計画のあと、ユーザーの確認をとってから設計書「デプロイ (e2)」の手順で行う。
