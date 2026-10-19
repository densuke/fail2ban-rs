# fail2ban-rs 設計書

## 目的

fail2ban (Python) の sshd 向けの中核を Rust に移植する。sshd の認証失敗を
systemd journal から読み、一定時間内に一定回数失敗した IP を nftables で一定時間ブロックする。
対応は Linux の x86_64 と aarch64 (musl の静的バイナリ)。

最低限の達成条件: sshd の jail が、fail2ban の既定値 (maxretry 5 / findtime 10m / bantime 10m) で
連続して認証に失敗する IP をブロックし、bantime の後に解除される。

## 移植の可能性の検討

上流: https://github.com/fail2ban/fail2ban (調査時 6c88de7)。本体は約 18,500 行の Python。

| 上流の部品 | 規模 | 扱い |
|---|---|---|
| filter.d/sshd.conf の正規表現 (normal モード) | 約 40 行 | **移植する**。Python の `re` の条件分岐 `(?(name)…)` と先読み `(?!…)` を使うため、`regex` クレートでは書けない。`fancy-regex` 0.19 で同じ式が動くことを確認済み |
| `<HOST>` / `<ADDR>` / `<F-*>` タグの展開 (failregex.py) | 約 100 行 | **移植する** (固定の表で展開) |
| INI 形式の設定と `%(x)s`・入れ子の `<tag>` の展開 (configreader 他) | 約 1,500 行 | 移植しない。sshd の normal モードの式を Rust のデータに展開して持つ |
| filtersystemd.py (journal の読み取り) | 約 580 行 | `journalctl -f -o json` を子プロセスで読む形で置き換える。libsystemd に依存しないので musl の静的バイナリにできる |
| datedetector.py (ログの日付の解釈) | 約 560 行 | 不要。journal の `__REALTIME_TIMESTAMP` を使う |
| failmanager / ticket (失敗回数の計数) | 約 300 行 | 移植する (スライディングウィンドウ) |
| action.d/nftables.conf (シェルのテンプレート) | 約 220 行 | nft のスクリプトを Rust で生成する組み込みの動作に置き換える |
| database.py (sqlite での永続化) | 約 900 行 | 移植しない。ブロックは nft の timeout 付き set に入れるので、デーモンを再起動しても残る (OS の再起動では消える) |
| client / server のソケット通信、DNS 解決、ファイルの tail、MLF (複数行の関連付け)、ddos / aggressive モード、pam の複数ユーザーの計数、bantime の段階的な延長 | — | 対象外 |

結論: 対象を「sshd・journal・nftables」に絞れば移植できる。互換性は上流のテストデータ
`fail2ban/tests/files/logs/sshd-journal` で確かめる。

## ライセンス

上流の正規表現とテストデータから派生するので、GPL-2.0-or-later とする。
`tests/fixtures/sshd-journal` は上流 (6c88de7) からの写し。

## 実機で確かめた事実 (pi, Ubuntu 26.04, 2026-10-20)

- sshd のログは `_COMM=sshd-session` (受付は `_COMM=sshd`)。ユニットは `ssh.service` で、`sshd.service` ではない。
- 認証の失敗に関わる sshd / sshd-session のメッセージは `_UID=0` で記録される (`_UID=1000` はログイン後のセッションのメッセージだけ)。
  `_COMM` は一般ユーザーが `prctl(PR_SET_NAME)` や改名した logger で偽装でき、偽の失敗行で他人の IP をブロックさせられる。
  そのため既定の journalmatch は各条件に `_UID=0` を AND で足している。
- `MESSAGE` は文字列。ただし journal の仕様上、バイト列 (数値の配列) で来ることもある。
- `journalctl --since=-600s`、`--after-cursor=<cursor>`、`A + B` (OR) が使える。
- nftables v1.1.6。timeout 付き set に同じ要素を `add element` すると、エラーにならず期限が上書きされる。
  `add table` / `add set` は既にあっても成功し、要素は消えない。
- 既存の `table ip filter` は iptables-nft の管理下にあるので触らない。

## 動作

1. 設定 (TOML) を読み、検証する。不正なら終了コード 1。
2. `mode = "nft"` なら nft の表を用意する (何度流しても同じ結果になり、ブロック中の要素は消えない)。
3. `journalctl -f -o json --no-pager --since=-<findtime>s <journalmatch...>` を起動し、1 行ずつ JSON を読む。
   journalctl が終わったら 5 秒待ち、最後に読んだ `__CURSOR` から `--after-cursor` で再開する。
4. 各エントリの `MESSAGE` に sshd のフィルタを当てる。
   - 先頭の `error: ` / `fatal: ` / `error: PAM: ` を外し、失敗の式を上から順に試して最初に当たったものを採る。
   - `<F-NOFAIL>` の部分が当たったものは失敗として数えない。
   - ホストが IP として解釈できないもの (DNS 名、`192.030.0.6` のような先頭 0) は数えない。
   - `::ffff:a.b.c.d` は IPv4 として扱う。
5. `ignoreip` に入る IP は数えない (ブロックもしない)。
6. IP ごとに、直近 findtime の間の失敗の時刻を持つ。maxretry 回に達したらブロックし、その IP の記録を消す。
7. ブロック: `mode = "log"` なら標準出力に記録するだけ。`mode = "nft"` なら timeout = bantime で set に入れる。
   解除は nft の timeout に任せる。

## 設定 (TOML)

```toml
mode = "log"                 # "log" (記録のみ・既定) | "nft"
ignoreip = ["127.0.0.0/8", "::1"]

[sshd]
enabled = true
maxretry = 5
findtime = "10m"
bantime = "10m"
# _COMM は一般ユーザーでも偽装できるため、root 発 (_UID=0) の行だけを読む。
journalmatch = ["_COMM=sshd", "_UID=0", "+", "_COMM=sshd-session", "_UID=0"]

[nft]
table = "fail2ban_rs"
priority = -10
nft_path = "/usr/sbin/nft"
journalctl_path = "/usr/bin/journalctl"
```

時間の書式は `600`、`30s`、`10m`、`1h`、`1d`。省いた項目は上の既定値。bantime と findtime は 365 日まで (nft 側の桁あふれで無期限にならないように)。既定の mode が `log` なのは、
ignoreip の書き忘れで自分を締め出さないため。

## nftables

自前の `table inet <table>` に、`addr4` / `addr6` の timeout 付き set と、input の hook の chain を置く。
ブロックした IP からの通信はすべて落とす (fail2ban の既定はポート単位だが、ここでは簡単にする)。
デーモンの終了時に表は消さない (ブロックを残す)。解除と撤去は README に nft のコマンドで書く。

## CLI

- `fail2ban-rs run [--config /etc/fail2ban-rs/config.toml]`
- `fail2ban-rs test-filter [FILE]` — 1 行 1 メッセージを読み (`-` か省略で標準入力)、判定を表示する
  (`journalctl -o cat _COMM=sshd-session | fail2ban-rs test-filter` で手元のログを試せる)。
- `fail2ban-rs check-config [--config …]` — 設定を検証し、実際に使う値を表示する。

## テストの方針

「壊れたときに気づけない、戻せない」ものを必須とする。

- 必須: フィルタの判定 (上流のテストデータ)、生成する nft のスクリプトの文字列、ignoreip、
  スライディングウィンドウの境界、journal の JSON の解釈、ban までの一連の流れ。
- 必須 (高コスト、1 本): 実際の nft を netns の中で動かし、要素が timeout 付きで入ることを確かめる (`#[ignore]`、sudo で実行)。
- 必須にしない: CLI の引数、表示の文言。
