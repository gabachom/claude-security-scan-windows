# NOTICE

このリポジトリは、Masahiro Chaen 氏の
[chaenmasahiro0425/claude-security-scan](https://github.com/chaenmasahiro0425/claude-security-scan)
（MIT License）をもとに、Windows 向けに改変したものです。

- 元の著作権表示と MIT License の全文は [LICENSE](LICENSE) にそのまま残しています
- 元リポジトリのコミット履歴もそのまま引き継いでいます（`git log` で元の作者のコミットを確認できます）
- 改変部分の著作権: Masayuki Tomoyasu / Amico Consulting LLC

## 元リポジトリからの主な変更

- macOS 本体の検査（`sscan/mac.py`）を、Windows 本体の検査（`sscan/windows.py`）に置き換え
- macOS 用のシェルスクリプト（launchd 登録・ツール取得）を PowerShell 版に置き換え
  （`scripts/install-schedule.ps1` はタスクスケジューラ、`scripts/install-tools.ps1` は Windows 用バイナリを SHA256 検証つきで取得）
- Windows で動かすための共通部分の修正（`.cmd` ラッパーの安全な起動、UTF-8 入出力、`reports/latest` の symlink 廃止、レポートの ACL 制限、トースト通知）
- OneDrive などクラウド同期フォルダの中にあるリポジトリ・レポートの検出を追加
- 元 README にあった講座・法人相談の案内（広告）を削除

元のプロジェクトの作者は、この Windows 版の内容について責任を負いません。不具合はこのリポジトリの Issue へお願いします。
