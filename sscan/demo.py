"""--demo 用の見本データ。実在しない会社・アカウント・リポジトリだけを使う。"""
from __future__ import annotations

from .common import Result

NEW_KEYS = {"svc|examplehelper", "leak|demo|stripe", "gh-2fa|example-inc"}


def result() -> Result:
    r = Result()
    a = r.add
    a("windows", "high", "サービス: Example Helper Service", "ExampleHelper（LocalSystem / Auto）",
      "SYSTEM/管理者権限で動くのに、起動するファイルを Users（全ユーザー） が書き換えられる（すり替えで乗っ取られる）\n"
      "起動: C:\\ProgramData\\ExampleHelper\\helper.exe（引数は秘密が入りうるので記録しない）",
      "心当たりがなければ services.msc で無効にしてから提供元を確認する", key="svc|examplehelper")
    a("windows", "critical", "ディスク暗号化（BitLocker / デバイスの暗号化）がオフ", "このPC C:", "システムドライブが暗号化されていない",
      "設定 → プライバシーとセキュリティ → デバイスの暗号化 をオンにし、回復キーを保存する", key="win-bitlocker")
    a("windows", "high", "サポートが終了したWindowsを使っている（セキュリティ更新が来ない）", "このPC",
      "Windows 10 22H2 (build 19045, Professional) / サポート終了 2025-10-14", "設定 → Windows Update から Windows 11 へ更新する", key="win-eol")
    a("windows", "medium", "外部から接続を受け付けるポート 3389（リモートデスクトップ）", "tcp/3389", "プロセス: svchost",
      "使っていなければリモートデスクトップをオフにする", key="win-port|3389")
    a("windows", "low", "外部から接続を受け付けるポート 3000", "tcp/3000", "プロセス: node", "開発サーバーは 127.0.0.1 にバインドする")
    a("repos", "critical", "コミット履歴に秘密情報らしき文字列: stripe-access-token", "~/dev/shop-demo  (example-inc/shop-demo・公開)",
      "2箇所（値は伏せ字）\nsrc/pay.ts:12 (3f2a91c)\n.env.local:4 (8bd0e17)",
      "①そのキーを発行元で無効化・再発行 ②偽値なら .gitleaksignore に登録 ③公開リポなら履歴からの除去も検討", key="leak|demo|stripe")
    a("repos", "high", ".env ファイルがgitに登録されている", "~/dev/landing  (example-inc/landing)", ".env", "git rm --cached で追跡を外し .gitignore に追加")
    a("repos", "medium", "git に登録していない .env に平文のキー: 3件", "~/dev/old-chatbot  (example-inc/old-chatbot)",
      "最後のコミットから31か月放置されたリポジトリ（使っていないキーが生きたまま残っている可能性）\n"
      ".env（値は表示しない）\nEXAMPLE_AI_API_KEY（51文字）\nSAMPLE_VECTOR_DB_KEY（36文字）\nDEMO_VOICE_TOKEN（32文字）",
      "①使っていないキーは発行元で無効化 ②使うキーは資格情報マネージャー（Windows 資格情報マネージャー・1Password 等）へ移す"
      " ③不要になった古いcloneはフォルダごと削除", key="envfile|demo|old-chatbot")
    a("repos", "high", "依存パッケージに既知の脆弱性", "~/dev/admin-panel  (example-inc/admin-panel)",
      "23件（critical:2 / high:9 / medium:12）\nnext@14.1.0: GHSA-xxxx（見本）", "npm audit fix 等で更新し、動作確認してからPR")
    a("github", "high", "組織で2段階認証が必須になっていない", "example-inc", "", "Settings → Authentication security で必須化", key="gh-2fa|example-inc")
    a("github", "high", "2段階認証を設定していないメンバー", "example-inc / taro-sample", "", "本人に2FA設定を依頼する")
    a("web", "critical", "公開してはいけないファイルが見える: /.env", "lp.example.com", "https://lp.example.com/.env",
      "デプロイ対象から除外し、中のキーをすぐローテーション")
    a("web", "low", "セキュリティヘッダーが不足", "www.example.com", "不足: Content-Security-Policy", "vercel.json の headers に追加")
    a("aws", "critical", "ルートユーザーにMFAがない", "prod (000000000000)", "", "ルートでログインしMFAを登録")
    a("aws", "high", "インターネット全体に開いた管理/DBポート", "prod (000000000000) / ap-northeast-1 / sg-0example", "22(SSH)",
      "送信元を絞るか SSM Session Manager に切り替える")
    a("supabase", "critical", "Security Advisor: RLS Disabled in Public", "shop-demo / public.orders",
      "Table public.orders is public, but RLS has not been enabled.", "テーブルの RLS を有効にし、必要な行だけ読めるポリシーを書く")
    a("gcp", "critical", "誰でも読めるCloud Storageバケット", "example-prod / gs://example-uploads", "roles/storage.objectViewer",
      "allUsers を外し、公開アクセス防止を有効に")
    a("azure", "high", "インターネット全体に開いた管理/DBポート", "Example Sub / nsg-web / allow-rdp", "3389(RDP)",
      "送信元を絞るか、Azure Bastion に切り替える")
    a("cloudflare", "medium", "SSL/TLS が Flexible（Cloudflare→サーバー間が暗号化されない）", "example.com", "", "Full (strict) に")
    a("gmail", "high", "全メールの自動転送がオン", "you@example.com", "転送先: unknown@example.net", "覚えがなければ即オフにしてパスワード変更")
    a("gmail", "info", "このアカウントから送信できる別アドレス（Send As）", "you@example.com", "info@example.com", "")
    for m, item in [("windows", "ウイルス対策"), ("windows", "UAC"), ("github", "example-inc Dependabot"), ("aws", "prod (000000000000)"),
                    ("gmail", "you@example.com")]:
        r.cov(m, item, "ok")
    r.cov("gmail", "Workspace管理 (example.com)", "skip", "Admin APIはドメイン全体の委任が必要")
    return r


def previous() -> list[dict]:
    """前回分の見本。NEW_KEYS 以外は前回もあった扱いにし、1件を「解消」に見せる。"""
    cur = [f.to_dict() for f in result().findings if f.key not in NEW_KEYS]
    cur.append({"module": "web", "severity": "high", "title": "SSL証明書の期限が近い", "target": "old.example.com",
                "detail": "", "fix": "", "key": "demo-resolved"})
    return cur
