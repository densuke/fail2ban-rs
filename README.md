# fail2ban-rs

sshd の認証失敗を systemd-journal から読み、同じ IP が短時間に失敗を繰り返したら nftables の timeout 付き set に入れて一定時間ブロックする、単一バイナリのツールです。

fail2ban (上流 6c88de7) の sshd 用の動作を Rust に移植したものです。対象は sshd のフィルタ (normal モード) と、nftables によるブロックです。対応は Linux の x86_64 と aarch64 (musl の静的バイナリ) です。

ライセンスは GPL-2.0-or-later です。詳しくは `LICENSE` を参照してください。

## 導入

GitHub Release から、自分の環境に合うバイナリを取得します。

```bash
# x86_64 の場合
curl -fLO https://github.com/densuke/fail2ban-rs/releases/latest/download/fail2ban-rs-x86_64-linux-musl
# aarch64 (Raspberry Pi など) の場合
curl -fLO https://github.com/densuke/fail2ban-rs/releases/latest/download/fail2ban-rs-aarch64-linux-musl

sudo install -m 0755 fail2ban-rs-*-linux-musl /usr/local/bin/fail2ban-rs
```

設定ファイルとユニットファイルは `deploy/` にあります。

```bash
# 既存の設定は上書きしない (既にあれば何もしない)
[ -e /etc/fail2ban-rs/config.toml ] || sudo install -D -m 0644 deploy/config.example.toml /etc/fail2ban-rs/config.toml
sudo install -m 0644 deploy/fail2ban-rs.service /etc/systemd/system/fail2ban-rs.service
sudo systemctl daemon-reload
```

`/etc/fail2ban-rs/config.toml` を自分の環境に合わせてから、起動します。

```bash
sudo systemctl enable --now fail2ban-rs
```

ユニットは root で動きます。nft と journal の読み取りに必要なためです。

## 設定の確認

```bash
fail2ban-rs check-config --config /etc/fail2ban-rs/config.toml
```

設定を検証し、実際に使う値を表示します。不正な設定は終了コード 1 で止まり、nft には触りません。

## 試運転: まず `mode = "log"` で様子を見る

既定の mode は `log` です。この mode では、閾値に達した IP を `would ban <ip> for <secs>s` と標準出力に出すだけで、nft には触りません。

```text
would ban 203.0.113.7 for 600s
```

ログに出た IP が本当に攻撃元かどうかを確かめてから、`mode = "nft"` に切り替えます。切り替えるときは、`ignoreip` に自分の接続元 (LAN、VPN、踏み台) がすべて入っていることを先に確かめてください。入っていないと、ブロックされた後に自分が締め出されます。

```toml
mode = "nft"
```

設定の変更は再起動するまで反映されません。

```bash
sudo systemctl restart fail2ban-rs
```

`nft` の mode で実際にブロックすると、ログには `ban <ip> for <secs>s` と出ます (`log` の mode では上の `would ban` だけが出ます)。

読む journal の行は、既定で `_UID=0` (root) が書いた sshd / sshd-session のものに限ります。`_COMM` は一般ユーザーでも偽装できるため、偽の失敗行で他人の IP をブロックさせないための条件です。`bantime` と `findtime` は 365 日までです。

## 常習犯を長くブロックする: `[sshd.recidive]`

同じ IP が `findtime` の間に `maxbans` 回ブロックされたら、その回は長い `bantime` でブロックします。fail2ban の recidive と同じ考え方です。長期ブロックのあとは数え直しになります。`[sshd.recidive]` を書くと有効になり、書かなければ無効です (中身は省略できます)。

```toml
[sshd.recidive]
maxbans = 3       # 既定は 3。2 以上
findtime = "1d"   # 既定は "1d"
bantime = "1d"    # 既定は "1d"。sshd.bantime より長くする。365 日まで
```

`nft` の mode では、長期ブロックのログは `ban <ip> for <secs>s (recidive)` と出ます。起動時の行には `recidive=3/86400s/86400s` (maxbans/findtime/bantime。無効なら `recidive=off`) が出ます。

## ブロックしたときに通知する

`[notify]` の `on_ban` にコマンドを配列で書くと、ブロックのたびに実行する。
シェルを通さず、引数をそのまま渡す。先頭の要素は絶対パスにする。
各要素の `{ip}` はブロックした IP、`{bantime}` は実際に使った bantime の秒数、`{kind}` はブロックの種類 (通常は `通常`、常習犯の長期ブロックは `長期`) に置き換わる。
`{jail}` はブロックした jail の名前 (`sshd` / `http`)、`{rule}` はブロックの理由になった規則 (`sshd` / `badpath` / `notfound`) に置き換わる。
`mode = "log"` でも実行するので、通知の動作確認に使える。
通知コマンドが失敗しても、ブロックは妨げない (stderr に 1 行出るだけ)。

```toml
[notify]
on_ban = ["/usr/sbin/runuser", "-u", "densuke", "--", "/home/densuke/.local/bin/discord-send-notifier",
          "--level", "warning", "--title", "fail2ban-rs: {ip} をブロック", "--description", "{bantime} 秒"]
```

fail2ban-rs は root で動くので、ユーザーのバイナリは上のように `runuser` 経由で呼ぶ。

## HTTP (Caddy) の jail

Caddy のアクセスログ (JSON) を journal から読み、穴探しのアクセスをブロックします。`[http]` を書くと有効になり、書かなければ無効です。sshd の jail とは同時に動き、それぞれ別の journalctl を読みます。nft の表・set は 1 つを共有します。

### Caddy のログを journal に出す

Caddy のログを標準出力に出せば、systemd が journal に入れます。サイトごとに `import` する snippet の例です。

```caddyfile
(log) {
	log {
		output stdout
		format json
	}
}

example.com {
	import log
	respond "ok"
}

www.example.com {
	import log
	respond "ok"
}
```

読む行は `logger` が `http.log.access` で始まる JSON だけです。接続元は `request.client_ip` (無ければ `remote_ip`) で、`X-Forwarded-For` などのヘッダは見ません。`trusted_proxies` を設定していないことを前提にしています。journal の既定の絞り込みは `_SYSTEMD_UNIT=caddy.service` です。

### 設定

```toml
[http]
bantime = "5m"                  # 2 つのルール共通の短いブロック。既定は 5 分

[http.badpath]                  # 既知のパスのルール。書かなくても有効
# mode = "log"                  # 省略時は全体の mode
# extra = ['^/\.svn/']          # 組み込みの一覧に足す正規表現

[http.notfound]                 # 404 のルール。書かなくても有効
maxretry = 20                   # 既定は 20
findtime = "10m"                # 既定は 10 分

[http.recidive]                 # 書けば有効。既定は 3 回 / 1d / 1d
maxbans = 3
```

- **badpath (既知のパス)**: `.env` や `.git`、`wp-login.php`、`.zip` で終わるパスなど、正規でないパスに 1 回アクセスしたらブロックします。ステータスは見ません。クエリは値を見ず、キー (`rest_route` など) だけを見ます。`extra` は `%xx` を解いて小文字にしたパス全体に当てる正規表現です。
- **notfound (404)**: findtime の間に 404 を maxretry 回出した IP をブロックします。badpath に当たった行が 404 なら、こちらにも数えます。1 行で 2 回はブロックしません (badpath が先)。
- **recidive**: HTTP の jail でのブロックを、2 つのルール合わせて IP ごとに数えます。findtime の間に maxbans 回目になったら、その回は recidive の bantime (既定 1 日) でブロックします。sshd のブロックとは別に数えます。
- **ルールごとの `mode`**: `log` か `nft` です。`log` のルールは `would ban` を出すだけで、recidive の回数には足しません。全体が `log` のときにルールだけ `nft` にはできません。新しいルールを試すときは `log` にします。ルールは `enabled = false` で止められます。
- badpath が `log` でも、badpath に当たった 404 の行は notfound に数えます。その行で notfound が閾値に達したときは、実際のブロックが勝ちます。
- 長いブロックは、別のルールや別の jail の短いブロックで短くなりません。プロセスの中で IP ごとに「ブロックが終わる時刻」を持ち、それより早く終わるブロックは nft に流しません。流さなかったときは `ban` ではなく `already banned <ip> until <UNIX 秒> jail=<jail> rule=<rule>` の行を出します。この行は通知せず、recidive にも数えません。nft への追加に失敗したブロックも recidive に数えず、「ブロックが終わる時刻」の表は元に戻します。

### 出力と数え方

```text
start http bantime=300s badpath=nft(+0 extra) notfound=nft/20/600s recidive=3/86400s/86400s
ban 203.0.113.7 for 300s jail=http rule=badpath uri=/.env
ban 203.0.113.7 for 86400s (recidive) jail=http rule=notfound
would ban 203.0.113.8 for 300s jail=http rule=notfound
already banned 203.0.113.7 until 1793000000 jail=http rule=badpath
```

HTTP の行には `jail=` と `rule=` が付きます。badpath の行には当たった URI が `uri=` で付きます (制御文字や空白はエスケープし、200 文字で切ります)。sshd の `ban` の行の形は変わりません。効果は journal を数えて測れます。

```bash
journalctl -u fail2ban-rs -o cat | grep 'jail=http' | grep -c '^ban '
```

`already banned` の行は `ban` で始まらないので、`^ban ` で数えれば件数は膨らみません。`on_ban` の通知コマンドの `{jail}` と `{rule}` でも、どの jail のどのルールで捕まったかを渡せます。

## 判定だけを試す: `test-filter`

手元のログに対して sshd のフィルタを当て、判定を確かめられます。1 行 1 メッセージを読み、標準入力 (`-` か省略) か指定したファイルから読みます。

```bash
journalctl -o cat _COMM=sshd-session | fail2ban-rs test-filter
fail2ban-rs test-filter /path/to/messages.txt
```

Caddy の JSON のアクセスログを試すときは `--jail http` を付けます。行ごとに `badpath <ip> <uri>`、`notfound <ip>`、`other` を出し、最後に件数を出します。

```bash
journalctl -u caddy -o cat | fail2ban-rs test-filter --jail http
```

## 手で解除する・撤去する

ブロックは nft の timeout 付き set に入るので、bantime が過ぎれば自動で解除されます。急いで解除したいときは、要素を消します。

```bash
# IPv4
sudo nft delete element inet fail2ban_rs addr4 { 192.0.2.10 }
# IPv6
sudo nft delete element inet fail2ban_rs addr6 { 2001:db8::10 }
```

fail2ban-rs が作った表をすべて消して撤去するには、次のコマンドを使います。停止してから実行してください。撤去するとブロックはすべて解除されます。

```bash
sudo systemctl disable --now fail2ban-rs
sudo nft delete table inet fail2ban_rs
```

デーモンは終了しても表を消さないので、デーモンの再起動ではブロックが残ります。OS の再起動では nft の表が消えます。

## 対象外の機能

次の機能は移植していません。

- 設定ファイルの INI 形式、`%(x)s` や入れ子の `<tag>` の展開。sshd の式は Rust のデータとして持ちます。
- sqlite による永続化。ブロックは nft の set に入るので、デーモンの再起動では残りますが、OS の再起動では消えます。
- MLF (複数行の関連付け)、ddos モード、aggressive モード。
- クライアントとサーバーのソケット通信、DNS 名の解決、ファイルの tail。
- pam の複数ユーザーの計数、bantime の段階的な延長 (常習犯の 1 段階だけの長期ブロックは `[sshd.recidive]` にあります)。
- sshd と Caddy 以外のジェイル。
- ポート単位のブロック。ブロックした IP からの通信はすべて落とします。

## 互換性

上流のテストデータ `tests/fixtures/sshd-journal` (上流 6c88de7 の `tests/files/logs/sshd-journal` の写し) の 82 行で判定を確かめています。そのうち 7 行は既知の未対応です (MLF と aggressive モードに関するもの)。

## テスト

```bash
cargo test
```

実際の nft を使うテストは、netns の中で動かします。`#[ignore]` が付いているので、通常の `cargo test` では走りません。

```bash
cargo test --test nft_netns_test --no-run
sudo unshare -n <表示されたテストバイナリのパス> --ignored
```

## ライセンスと上流

GPL-2.0-or-later です。`LICENSE` を参照してください。

このプロジェクトは fail2ban (https://github.com/fail2ban/fail2ban, 6c88de7) を元にした派生物です。上流の正規表現とテストデータを使っています。
