# fail2ban-rs

sshd の認証失敗を systemd-journal から読み、同じ IP が短時間に失敗を繰り返したら nftables の timeout 付き set に入れて一定時間ブロックする、単一バイナリのツールです。

fail2ban (上流 6c88de7) の sshd 用の動作を Rust に移植したものです。対象は sshd のフィルタ (normal モード) と、nftables によるブロックです。

ライセンスは GPL-2.0-or-later です。詳しくは `LICENSE` を参照してください。

## 使い方

使い方は後で書きます。
