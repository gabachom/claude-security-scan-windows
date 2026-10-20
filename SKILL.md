---
name: security-scan
description: 開発者のWindows PC・手元のgitリポジトリ・GitHub・Vercelと公開サイト・クラウド（AWS / Google Cloud / Azure / Cloudflare / Supabase）・Gmailを読み取り専用で横断スキャンし、重要度別のHTMLレポートと前回からの差分を出すスキル。「セキュリティチェックして」「セキュリティスキャン」「脆弱性ないか見て」「APIキー漏れてない？」「乗っ取られてないか確認」「新しく出たリスクだけ教えて」「毎週スキャンを設定して」等で使う。設定の変更・送信・削除はしない。直すときは1件ずつ利用者の承認を取る。
---

# security-scan

このフォルダ（以下 `$SKILL`）の `scan.py` を実行して、結果を日本語で説明するスキル（Windows版）。
スキャナーは**読み取り専用**。設定の書き換え・送信・削除は一切しない。

## 1. 初回だけ

```bash
py -3 --version                        # 3.11 以上が必要（tomllib を使う）。py が無ければ python
powershell -ExecutionPolicy Bypass -File "$SKILL/scripts/install-tools.ps1"   # gitleaks と osv-scanner を公式リリースから取得し SHA256 を検証
```

各CLIは**入っているものだけ**使う。無いモジュールは「確認できなかった項目」に理由つきで出るだけで、止まらない。

| モジュール | 必要なもの | 見るもの |
|---|---|---|
| `windows` | Windows 10 / 11（管理者権限不要） | サポート期限・BitLocker・ファイアウォール・Defender（リアルタイム保護・定義・改ざん防止・除外）・UAC・SmartScreen・セキュアブート・メモリ整合性・自動ログイン・画面ロック・RDP・SMBv1・Guest / 管理者グループ・Windows Update・待ち受けポート・共有・秘密ファイルの ACL・自動起動（Run・スタートアップ・タスク・サービス。SYSTEM 常駐が書き換え可能／未署名のファイルを起動していないか） |
| `repos` | gitleaks / osv-scanner | 手元の全gitリポジトリのコミット履歴にある秘密情報（値は伏せ字）・.env のgit登録・依存パッケージの既知脆弱性・OneDrive 等の同期フォルダ内のリポジトリ |
| `github` | `gh auth login` 済み | 本人と所属orgの2FA・2FA必須設定・未設定メンバー・公開リポ作成権限・外部コラボレーター・Webhook・Dependabot / Secret scanning |
| `web` | `vercel login`（任意） | Vercel全チームの本番ドメイン＋設定のURL: HTTPS・証明書期限・ヘッダー・.env/.git の露出・プレビュー保護・ブラウザに出る秘密っぽい環境変数 |
| `aws` | aws CLI のプロファイル | （リージョン単位の検査は既定で東京とバージニア）ルートMFA・MFAなしIAMユーザー・放置キー・公開S3・CloudTrail・GuardDuty・全開放の管理/DBポート・公開RDS |
| `gcp` | `gcloud auth login` | allUsers への権限・個人Gmailへのオーナー権限・サービスアカウントの鍵・公開バケット・全開放のファイアウォール / Cloud SQL |
| `azure` | `az login` | 匿名公開のストレージ・HTTP許可・全開放のNSG / Azure SQL・Defender for Cloud |
| `cloudflare` | `CLOUDFLARE_API_TOKEN`（読み取り専用） | SSL/TLSモード・Always Use HTTPS・最小TLS・DNSSEC・2FAの無いメンバー |
| `supabase` | `supabase login`（診断は `SUPABASE_ACCESS_TOKEN`） | 公式 Security Advisor（RLSの無い公開テーブル等） |
| `gmail` | [gog](https://github.com/steipete/gogcli) で認証済み | 自動転送・転送フィルタ・警告メールを隠すフィルタ・委任・最近のセキュリティ通知（件名のみ） |

設定は無くても動く（ログイン済みのCLIから対象を自動検出）。絞りたいときだけ
`$SKILL/config.example.toml` を `%USERPROFILE%\.config\security-scan\config.toml` にコピーして編集する。

## 2. 実行

```bash
py -3 "$SKILL/scan.py"                   # 全部（リポジトリが多いと10〜20分。Windows Update の検索に数分かかることもある）
py -3 "$SKILL/scan.py" --skip repos      # 重いコード検査を外す（数分）
py -3 "$SKILL/scan.py" --only windows,gmail --open
py -3 "$SKILL/scan.py" --demo --open     # 見本データでレポートの見た目だけ確認（何もスキャンしない）
```

結果は `$SKILL/reports/<日時>/` に `report.html`（絞り込み付き）・`summary.md`・`findings.json`。最新は `reports/latest/`（コピー）。
出力は UTF-8。Windows の端末で文字化けする場合は `PYTHONIOENCODING=utf-8` を付けるか、`summary.md` を読む。
長くかかるのでバックグラウンドで実行し、終わったら `reports/latest/findings.json` を読む。

## 3. 結果の伝え方

1. `findings.json` の `findings` を **緊急→高→中** の順に、`new` に key があるもの（前回から増えたもの）を先頭にして要点を伝える
2. 1件ごとに「何が起きうるか」「誰が直すか（本人の画面操作／Claudeがコードで直せる／チームへの依頼）」「手順」を添える
3. `coverage` の `error` / `skip` は「確認できなかった項目」として必ず伝える。**未確認を問題なしと言わない**
4. `info` は棚卸し（常駐・フィルタ・外部コラボレーター等の一覧）。前回から増えたものだけ触れる。乗っ取りの兆候になりうるため
5. 「直せるところある？」と聞かれたら、**Claudeがすぐ直せる／承認があれば直せる／本人しかできない** の3つに分けて答える
6. レポートは弱点の一覧。利用者の許可なく外部へ送ったり公開したりしない

## 4. 直すとき

- コード（依存の更新・.gitignore・ヘッダー追加）: ブランチを切ってPRを作る。既定ブランチへ直接コミットしない
- Windows 本体の設定（BitLocker・Defender・ファイアウォール・UAC・RDP・自動起動の無効化など）: 手順を示して本人に操作してもらう。管理者権限が要る変更・セキュリティ設定の変更を Claude が勝手に実行しない
- 自動起動・サービスの「高」: すぐ削除せず、まず提供元（署名・インストール元）を本人と確認する。止めるなら無効化して隔離。削除はしない
- 外部の設定（GitHub org・AWS IAM/S3/CloudTrail・Vercel・Gmailのフィルタ）: 内容を1件ずつ示し、承認を得てから変更する。メンバーに影響するもの（2FA必須化など）は周知文の下書きから
- 秘密情報が漏れていた場合: 値を画面に出さない。発行元での無効化・再発行を最優先で案内する。gitの履歴から消すだけでは不十分
- パスワード入力・MFA登録・ルートアカウントでの操作は利用者本人が行う
- 誤検知の抑え方: gitleaks はリポジトリの `.gitleaksignore`、Gmailの転送先は設定の `allowed_forwarding`、サイトは `[web] exclude`。
  Windows の自動起動は、ZoomIt のように一時フォルダへ展開して動く正規ソフトもある（署名と提供元で判断する）

## 5. 毎週の自動実行

```bash
powershell -ExecutionPolicy Bypass -File "$SKILL/scripts/install-schedule.ps1"                       # 毎週月曜 8:00（タスクスケジューラ）。新しい緊急・高があれば通知
powershell -ExecutionPolicy Bypass -File "$SKILL/scripts/install-schedule.ps1" -Day Sunday -At 21:00  # 日曜 21:00 にしたい場合
powershell -ExecutionPolicy Bypass -File "$SKILL/scripts/install-schedule.ps1" -Remove
```

ログオン中の本人の権限で、窓を出さずに（pythonw）動く。ログは `reports/schedule.log`。PC がその時刻に寝ていたら起動後に実行する。

## つまずき

- `aws ... SSOの期限切れ` → `aws sso login --profile <名前>`
- `gog ... invalid_grant` → `gog auth add <メール>` で再認証（ブラウザでの本人操作）
- `osv-scanner.exe` / `gitleaks.exe` が「アクセスが拒否されました」→ ウイルス対策ソフトが未署名の exe を止めている。`bin` を除外に入れるか winget で入れ直す（本人の操作）
- タスクスケジューラから gog が鍵束を開けない → gog の鍵束パスワード（`GOG_KEYRING_PASSWORD`）をユーザー環境変数に設定しておく
- Defender の除外・共有フォルダが「確認できなかった」→ 管理者権限が必要。必要なら本人が管理者の PowerShell で `py -3 scan.py --only windows` を実行する
- Google Workspace 全体の管理設定（社員の2段階認証の強制など）は Admin API の委任が要るため対象外。管理コンソールの「セキュリティの状況」で確認する
