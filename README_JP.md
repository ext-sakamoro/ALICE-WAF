[English](README.md) | **日本語**

# ALICE-WAF

A.L.I.C.E. エコシステム向けWebアプリケーションファイアウォール。ルールベースのHTTPリクエスト検査、SQLインジェクション・XSS検出、IPフィルタリング、レート制限を純Rustで実装。

## 機能

- **ルールエンジン** — マッチ条件とアクション（Block/Allow/Log）の設定可能なルール
- **SQLインジェクション検出** — URI・ヘッダー・ボディ全体のパターンベースSQLi検出
- **XSS検出** — スクリプトタグ、イベントハンドラ、JavaScript URIパターンマッチング
- **IPフィルタリング** — `IpAddr`対応の許可リスト・ブロックリスト
- **レート制限** — IP単位のリクエストレート追跡、設定可能な時間ウィンドウ
- **リクエスト検査** — 完全なHTTPリクエスト分析（メソッド、URI、ヘッダー、ボディ、送信元IP）
- **OWASPパターン** — OWASP Top 10の一般的な攻撃ベクターをカバー

## アーキテクチャ

```
HTTPリクエスト
  │
  ├── Request      — メソッド、URI、ヘッダー、ボディ、送信元IP
  ├── RuleEngine   — ルールマッチングと判定生成
  ├── SqliDetector — SQLインジェクションパターン検出
  ├── XssDetector  — クロスサイトスクリプティング検出
  ├── IpFilter     — 許可リスト / ブロックリスト評価
  ├── RateLimiter  — IP単位レート追跡
  └── Verdict      — Block / Allow / Log（理由付き）
```

## 使用例

```rust
use alice_waf::{Request, Verdict};

let req = Request::new("GET", "/api/users")
    .with_header("host", "example.com");
```

## ライセンス

`AGPL-3.0 OR LicenseRef-Commercial` — デュアルライセンス どちらかを選べる

| 選択肢 | 条文 | こういう時 |
|--------|------|-----------|
| **AGPL-3.0** | [LICENSE-AGPL](LICENSE-AGPL) — 無償、報告義務なし | 自分の project も AGPL 互換の OSS、または社内利用のみ |
| **商用ライセンス** | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — 有償、コピーレフト義務を解除 | クローズドソース製品 / 商用 SaaS / エッジ・ファームウェア配布 / plugin 再配布 / ソース開示を禁じるプラットフォーム NDA |

AGPL は強いコピーレフト: `alice-waf` を link して配布 / 提供する製品・ファームウェア・
サービスは AGPL で公開する義務がある これはオープンなエコシステムのための意図的な
選択で、それが実行できない場合のために商用ライセンスを用意している

商用ライセンスの問い合わせ: <contact@extoria.co.jp>
