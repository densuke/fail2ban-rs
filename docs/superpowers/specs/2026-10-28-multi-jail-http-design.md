# 複数の jail と HTTP jail の設計 (v0.4.0)

## 目的と背景

e2 (GCP、外から 22・80・443・25 番に届く) では、Caddy の前に置いた 10 サイトに
穴探しのアクセスが絶えず来ている。fail2ban-rs は今は sshd 専用なので、これを止められない。

2026-10-26 から e2 の Caddy のアクセスログを journal に出して記録を取り、
2026-10-28 に 2 日ぶん (10/26 08:06〜、外からの 7,474 件・1,032 IP) を集計した。
その結果から、HTTP の jail を足し、ブロックまで行う。

集計で分かったこと:

- 全体の 58% が 404。中身は秘密ファイル探し (`/.env*`、`/.git/config`、`/.aws/credentials`、
  `/.ssh/id_rsa`、`/.claude/settings.json`)、バックアップ探し (`/backup.zip`、ランダム名の `.tar.gz`)、
  WordPress 探し (`/wp-login.php`、`/{blog,wp,cms,...}/wp-json/`、`?rest_route=/`)、
  管理画面・登録ページ探し (`/login`、`/register`、`/admin/login`)。
- 既知のパス (下の「既知のパスのルール」) に当たった IP は 66、3 回以上は 32。
- IP ごとの「10 分間の 404 の最大数」は、1〜12 回 (230 IP) と 32 回以上 (22 IP) に分かれ、
  13〜31 回は 0。22 IP のうち 19 は既知のパスでも捕まる。404 でしか捕まらないのは 3 IP
  (登録ページ探し 2、フィードを探すクローラ LivelapBot 1)。
- 本物の Googlebot・Slackbot・GoogleChatRssApp は、10 分で 404 が数回以下。
- 同じ組織 (`45.138.12.x`、`45.148.10.x`、`195.178.110.x`) が何時間もかけて少しずつ来る。
  これは recidive (常習犯の長期ブロック) で捕まえる。
- 自分の接続元 (221.247.29.226、Tailscale) は Caddy の `log_skip` でログから外しているため、
  自分の使い方が 404 のルールに掛からないことは確かめていない (ignoreip で守る)。
- データは 2 日ぶんだけ。

## 目標

1. jail を複数持てるようにする。sshd の jail は今と同じ動作のまま残す。
2. Caddy の JSON アクセスログを読む HTTP の jail を足す。
   - **既知のパスのルール**: いかにも正規でないパスに 1 回でもアクセスしたら、5 分ブロック。
   - **404 のルール**: 10 分間に 404 を 20 回出したら、5 分ブロック。
   - **recidive**: HTTP の jail で 24 時間に 3 回ブロックされたら、その回は 1 日ブロック。
     2 つのルールのブロックは合わせて数える。sshd のブロックとは別に数える。
3. Discord への通知は今と同じく 1 日ブロックのときだけ (e2 の通知スクリプトが「長期」だけを送る)。
   どの jail で捕まったかを通知に出せるようにする。
4. 記録モード (ブロックせず `would ban` を出すだけ) を、ルールごとに選べるようにする。
   新しいルールを試すための仕組みで、v0.4.0 の e2 では両ルールともブロックで動かす。
5. 効果を測るための材料をログに残す。ブロックの行に jail とルールを出す。

ここまでの数値 (5 分、3 回、1 日、10 分で 404 が 20 回) はユーザーとの会話で決めたもの。

## 目標にしないこと

- 効果測定の集計そのもの (週 1 のまとめ、レポート)。v0.4.0 ではログに材料を残すところまで。
  集計は別の作業にする。
- Caddy 以外の Web サーバー (nginx、Apache の combined 形式)。
- SMTP (25 番) の jail。jail を複数持てる作りにするので、あとで同じ枠に足せる。
- jail ごとの ignoreip。今の全体の `ignoreip` を全 jail で共有する。
- ポート単位のブロック。今と同じく、ブロックした IP からの通信はすべて落とす。
- 再起動をまたいだ計数の保存 (今の sshd と同じく、メモリ上だけ)。

## やってはいけないこと (失敗とみなすもの)

- 今の `/etc/fail2ban-rs/config.toml` (`[sshd]`、`[sshd.recidive]`、`[notify]`) が、
  そのままでは読めなくなる。または sshd の動作や起動時の行・ブロックの行の形が変わり、
  今の運用 (journal の目視、`fail2ban-rs-notify-long`) が壊れる。
- 攻撃者が送れる値 (Host ヘッダ、X-Forwarded-For、User-Agent、URI の中身) によって、
  攻撃者以外の IP をブロックさせられる。
- 長いブロックが、別のルールや別の jail の短いブロックで上書きされて短くなる。
- feedgen・rss-proxy の正規の利用 (`/feed?url=https://...` のように、クエリに任意の URL が入る)
  が既知のパスのルールに当たる。

## 前提と制約

### e2 で確かめた事実 (2026-10-28)

- Caddy v2.11.7、ユニットは `caddy.service`、uid 993 (`caddy`)。
- アクセスログは journal に 1 行 1 JSON で出る (`_TRANSPORT=stdout`、`_COMM=caddy`、`_UID=993`)。
  `MESSAGE` の JSON の例 (必要な欄だけ):
  ```json
  {"level":"info","ts":1793...,"logger":"http.log.access.log0","msg":"handled request",
   "request":{"remote_ip":"203.0.113.7","client_ip":"203.0.113.7","method":"GET",
              "host":"fuga.jp","uri":"/.env?x=1","headers":{"User-Agent":["..."]}},
   "status":404}
  ```
  `logger` は `http.log.access` で始まる。同じユニットにエラーログ (`http.log.error`) なども出るので、
  それ以外の logger の行は捨てる。
- Caddyfile に `trusted_proxies` は無い。よって `client_ip` は `remote_ip` (TCP の接続元) と同じで、
  ヘッダからは作られない。
- 外からのアクセスは 1 日 3,500 行ほど。
- `auto.fuga.jp` は裏のサービスが止まっていて全部 502 を返すので、404 のルールでは拾えない
  (既知のパスのルールでは拾える)。
- `post.fuga.jp` はどのパスにも 303 (ログインへの転送) を返す。

### 既存の設計から引き継ぐこと

- 既存の設計書 (`2026-10-20-fail2ban-rs-design.md`) の事実と方針はそのまま。特に、nftables では
  timeout 付き set に同じ要素を `add element` すると、エラーにならず**期限が上書きされる**。
- 依存は増やさない方向 (今の `fancy-regex`、`serde_json`、`toml` で足りるはず)。
- musl の静的バイナリのまま。

## 設定の形 (決めたこと)

今の `[sshd]` はそのまま。`[http]` を足す。`[http]` が無ければ HTTP の jail は無効。

```toml
mode = "nft"                      # 全体の既定。今と同じ
ignoreip = ["127.0.0.0/8", "::1", ...]   # 全 jail で共有

[sshd]                            # 今のまま
maxretry = 3
findtime = "10m"
bantime = "5m"
[sshd.recidive]
maxbans = 3

[http]
enabled = true                    # 既定 true (セクションを書けば有効)
bantime = "5m"                    # 両ルール共通の短いブロック
journalmatch = ["_SYSTEMD_UNIT=caddy.service"]   # 既定値

[http.badpath]                    # 既知のパスのルール。書かなくても有効
# mode = "log"                    # 省略時は全体の mode
# extra = ['^/\.svn/']            # 組み込みの一覧に足す正規表現 (パスに当てる)

[http.notfound]                   # 404 のルール。書かなくても有効
maxretry = 20
findtime = "10m"
# mode = "log"

[http.recidive]                   # 書けば有効。中身の既定は sshd と同じ (3 回 / 1d / 1d)
maxbans = 3
```

- ルールごとの `mode` は `log` か `nft`。省略時は全体の `mode`。全体が `log` のときにルールだけ
  `nft` にすることは許さない (検証で弾く)。安全側に倒すため。
- `log` のルールで閾値に達したら `would ban ...` を出すだけで、**recidive の回数には足さない**
  (実際にはブロックしていないため)。通知も今の log モードと同じく実行する。
- ルールを止めたいときは `enabled = false` をルールごとに書ける。
- 既知のパスの一覧は**バイナリに組み込み**、`extra` で足せる形にした (私の判断。ユーザーには
  一覧の置き場所を聞いたが、答えは出ていない)。見直しで見つけたものはまず `extra` に足して restart、
  定着したら組み込みに移してリリースする。

## 判定 (決めたこと)

### 行の読み方

1. journal の `MESSAGE` を JSON として読む。読めない行、`logger` が `http.log.access` で
   始まらない行は捨てる。
2. 接続元は `request.client_ip`。無ければ `request.remote_ip`。IP として解釈できなければ捨てる。
   ヘッダ (X-Forwarded-For など) は見ない。
3. 時刻は今と同じく journal の `__REALTIME_TIMESTAMP` を使う (JSON の `ts` は使わない)。
4. `ignoreip` に入る IP は数えない。

### 既知のパスのルール

- `request.uri` を `?` の前 (パス) と後 (クエリ) に分ける。パスは `%xx` を 1 回だけ解いてから当てる
  (`/%2eenv` 対策)。大文字小文字は区別しない。解いた結果の `%2F` も `/` として区画を分ける。
- パスは `/` で区切った**区画 (セグメント) 単位**で当てる。どの階層の区画でもよい
  (`/blog/wp-json/` も `/app/.env` も当たる)。部分一致はしない (`/posts/phpinfo-tips` は当たらない)。
- **区画が一致したら当たるもの** (組み込みの一覧の初版。集計で実際に来ていたもの):
  - 隠しファイル・設定: `.env` で**始まる**区画 (`.env.local`、`.env-example` など)、
    `.git`、`.aws`、`.ssh`、`.docker`、`.claude`、`.config`、`.yarnrc`、`.composer`、`.gem`、`.boto`
  - WordPress: `wp-login.php`、`xmlrpc.php`、`wp-admin`、`wp-json`、`wp-content`、`wp-includes`
  - そのほか: `phpmyadmin`、`cgi-bin`、`phpinfo`、`phpinfo.php`
- **パスの末尾で当たるもの** (バックアップ探し): `.zip`・`.rar`・`.tar.gz`・`.tgz`・`.7z`・`.sql`・`.bak`
- **クエリのキーで当たるもの**: `rest_route` (WordPress の REST)、`phpinfo`。
  クエリはキーの名前だけを見て、値には当てない (feedgen・rss-proxy のクエリの値に任意の URL が入るため)。
- `extra` の正規表現は、`%xx` を解いて小文字にしたパス全体に当てる。
- 1 回当たったら閾値に達したものとする (maxretry は 1 で固定)。
- ステータスは見ない (502 や 303 を返すサイトでも捕まえるため)。
- **2 日ぶんのログで確かめた結果 (2026-10-28、上の判定を Python で書いて当てた)**: 当たったのは
  2,494 行・71 IP。応答が 2xx だったのは `fuga.jp` の `?rest_route=` と `?phpinfo=1` の 26 行だけで、
  どれも穴探しの IP が叩いたもの (`fuga.jp` は `/usr/share/caddy` の `file_server` で、クエリを無視して
  トップページを返す)。正規の利用者への当たりは 0。`.zip` などの拡張子で 2xx を返したものも 0。
  e2 で `file_server` を使っているのは `fuga.jp` だけ。
- Mastodon (`m.fuga.jp`) のデータのエクスポートは `.zip` だが、利用者はユーザー本人だけで、
  本人の接続元は ignoreip に入っている。よって拡張子のルールはそのまま全サイトに当てる (ユーザーの判断)。
- 当たりが正規の利用だと分かったら、その型を組み込みから外すか狭める (host やステータスで除く仕組みは
  作らない)。私の判断。
- 実装のあと、リリースの前に、`test-filter --jail http` を e2 の journal (`journalctl -u caddy -o cat`) に
  当てて、上の結果と大きく違わないことを確かめる。実装者が e2 に入って行う。

### 404 のルール

- `status` が 404 の行を、IP ごとに findtime (既定 10 分) の窓で数える。maxretry (既定 20) 回で閾値。
  今の `FailTracker` と同じ数え方。
- 既知のパスのルールに当たった行も 404 なら数えてよい (どちらかが先に閾値に達すればよい)。
  ただし 1 行で 2 回ブロックしない (既知のパスが先)。

### ブロックと recidive

- どちらのルールでも、閾値に達したら `[http] bantime` (既定 5 分) でブロック。
- `[http.recidive]` があれば、HTTP の jail でブロックした回数を IP ごとに数え、
  findtime (既定 1d) の間に maxbans (既定 3) 回目になったら、その回は recidive の bantime (既定 1d) にする。
  今の sshd の recidive と同じ数え方 (長期ブロックのあとは数え直し)。
- sshd と HTTP のブロック回数は別々に数える。

### 長いブロックを短く上書きしない

nft では同じ要素の `add element` が期限を上書きする。ブロック中の IP は全ポートが落ちるので
新しい行はふつう来ないが、起動時に findtime ぶんさかのぼって読む行や、journal の遅れで、
1 日ブロック中の IP に 5 分ブロックがかかりうる。そこで、プロセスの中で IP ごとに
「今のブロックの終わる時刻」を全 jail で共有して持ち、それより早く終わるブロックは nft に流さない
(ログには出す)。表の終わる時刻は journal の時刻から計算する。起動時にさかのぼって読む行では、
表の終わりが nft の timeout より早くなりうる (短くなる向きにはならない)。
まだ終わっていないブロックがある IP の行は、閾値に達しても `AlreadyBanned` にし、ブロックを延ばさない
(badpath は 1 行ごとに閾値に達するため、スキャナの連続した行が nft への再送や recidive の回数になるのを防ぐ。
判断 7)。再起動をまたいでは守れないが、それは今の設計と同じ制約として受け入れる。

流さなかったブロックの扱い (私の判断):

- `ban` ではなく別の行 `already banned <ip> until <終わる時刻 (UNIX 秒)> jail=<jail> rule=<rule>` を出す。
  `ban` の行を数える効果測定で件数が膨らまないようにするため。sshd の `ban` の行の形は変えない
  (sshd で流さなかったときも、この別の行になるだけ)。
- recidive の回数には足さない。通知も実行しない。
- 表に載るのは nft に実際に流したブロックだけ。log のルールの `would ban` は表を見ず、表にも載せない
  (今の log モードと同じく、閾値に達するたびに出る)。

## 出力 (決めたこと)

今の sshd の行は形を変えない。HTTP の行は末尾に jail とルールを足す。

```text
start mode=Nft maxretry=3 findtime=600s bantime=300s recidive=3/86400s/86400s ignoreip=[...]
start http bantime=300s badpath=nft(+0 extra) notfound=nft/20/600s recidive=3/86400s/86400s
ban 203.0.113.7 for 300s jail=http rule=badpath uri=/.env
ban 203.0.113.7 for 86400s (recidive) jail=http rule=notfound
would ban 203.0.113.8 for 300s jail=http rule=notfound
```

- 1 行目は今の sshd の起動の行 (そのまま)。sshd が無効なら出さない。
- `uri` は既知のパスのルールのときだけ、当たった URI を出す (攻撃者が送った文字列なので、
  制御文字や空白はエスケープし、長さを 200 文字で切る)。見直しで新しいパターンを探す材料になる。
- 効果測定は、この `ban` / `would ban` の行を journalctl で数える前提にする。

### 通知

`on_ban` の置き換えに `{jail}` (`sshd` か `http`) と `{rule}` (sshd では `sshd`、HTTP では
`badpath` か `notfound`) を足す。`{kind}` は今と同じ (`通常` / `長期`)。
e2 の `fail2ban-rs-notify-long` は、デプロイのときに `{jail}` を通知の本文に足すよう直す。

## 内部の形 (決めたこと)

- jail ごとに journalctl の読み取りスレッドを 1 本立てる (journalmatch が違うため)。
  各スレッドは「どの jail の行か」を付けて、1 本の channel に送る。メインのループが jail に振り分ける。
- `Engine` は jail ごとに持つ。sshd の `Engine` は今の動作のまま。
- nft の表・set は全 jail で 1 つ (今の `fail2ban_rs`)。
- `run` は、有効な jail が 1 つも無ければ今と同じく終了する (`no jail is enabled; exiting`)。
- `test-filter` に `--jail http` を足し、Caddy の JSON (journal の `MESSAGE` の中身、1 行 1 件) を
  読んで、行ごとに `badpath <ip> <uri>` / `notfound <ip>` / `other` を出す。最後に件数を出す。
  `--jail` の既定は `sshd` (今の動作)。
- `check-config` は今と同じく、検証した設定全体を表示する。

## テスト

方針は既存と同じ (壊れたら取り返しがつかないところを必ず)。特に:

- 攻撃者が選べる値で他人をブロックさせられないこと (ヘッダの X-Forwarded-For を無視する、
  `logger` が access 以外の行を捨てる、クエリの任意の URL に当たらない)。
- 長いブロックが短いブロックで上書きされないこと。
- 今の sshd の設定ファイル・出力が変わらないこと (既存のテストが通ること)。
- 既知のパスのルールの一覧: 実際に来ていたもの (上の集計の例) は当たり、feedgen・rss-proxy の
  正規の URL (`/feed?url=https://example.com/a.zip` など) は当たらない。
- テストのデータは手で作る。IP は文書用の範囲 (192.0.2.0/24、198.51.100.0/24、203.0.113.0/24、
  2001:db8::/32) を使う。e2 の実ログはリポジトリに入れない。

## デプロイ (e2)

1. v0.4.0 をリリースし、e2 のバイナリを入れ替える。
2. `config.toml` に `[http]`・`[http.recidive]` を足す。最初の 1 日は `[http]` の両ルールを
   `mode = "log"` にして `would ban` を確かめ、問題なければ外して `nft` にする。
3. `fail2ban-rs-notify-long` に `{jail}` を足す。
4. ignoreip に自分の接続元 (221.247.29.226、Tailscale、GCP IAP) が入っていることを確かめる (入っている)。

## 実装者に任せること

- モジュールの分け方 (`filter/caddy.rs` などの名前、`Engine` を trait にするか enum にするか)。
- 組み込みの一覧の正規表現の書き方 (上の意味を満たせばよい)。
- 起動の行の細かい書式 (上の例の情報が入っていればよい)。
- 「今のブロックの終わる時刻」の表を、いつ掃除するか。
