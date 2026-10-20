#!/usr/bin/env python3
"""security-scan (Windows版): Windows本体・コード・GitHub・Web/Vercel・クラウド・Gmail を読み取り専用で横断チェックする。

使い方:
  py -3 scan.py                       # 全部
  py -3 scan.py --only windows,web    # 一部だけ
  py -3 scan.py --skip repos          # 重いものを外す
  py -3 scan.py --notify --open       # 新しい高リスクがあれば通知、終わったらレポートを開く
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import tomllib
import traceback
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sscan import aws, azure, cloudflare, gcp, github, gmail, report, repos, supabase, web, windows  # noqa: E402
from sscan.common import ROOT, WHOLE, WINDOWS, Result, powershell, run  # noqa: E402

MODULES = {"windows": windows, "repos": repos, "github": github, "web": web, "aws": aws, "gcp": gcp, "azure": azure,
           "cloudflare": cloudflare, "supabase": supabase, "gmail": gmail}
REPORTS = Path(os.environ.get("SECURITY_SCAN_REPORTS", ROOT / "reports"))
CONFIG_CANDIDATES = [Path.home() / ".config/security-scan/config.toml", ROOT / "config.toml"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--skip", default="")
    ap.add_argument("--config", default="", help="既定は ~/.config/security-scan/config.toml → 同梱の config.toml。無くても自動検出で動く")
    ap.add_argument("--demo", action="store_true", help="見本データでレポートだけ作る（スクショ・動作確認用。何もスキャンしない）")
    ap.add_argument("--notify", action="store_true", help="新しい緊急/高があれば Windows の通知を出す")
    ap.add_argument("--open", action="store_true", help="終了後にレポートをブラウザで開く")
    ap.add_argument("--log", default="", help="標準出力の代わりにこのファイルへ追記する（タスクスケジューラ用）")
    a = ap.parse_args()
    _setup_output(a.log)

    cfg_path = Path(a.config) if a.config else next((p for p in CONFIG_CANDIDATES if p.exists()), None)
    cfg = tomllib.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path else {}
    skip = a.skip.split(",")
    mods = [m for m in (a.only.split(",") if a.only else MODULES) if m and m not in skip]
    unknown = [m for m in mods if m not in MODULES]
    if unknown:
        ap.error("不明なモジュール: " + ", ".join(unknown) + "（使えるもの: " + ", ".join(MODULES) + "）")
    if not WINDOWS and "windows" in mods and not a.only:
        mods.remove("windows")
    started = datetime.now()
    os.umask(0o077)  # レポートには弱点の一覧が入るので本人以外読めないようにする（Windows では下の ACL で行う）
    REPORTS.mkdir(parents=True, exist_ok=True)
    _lock_down(REPORTS)
    outdir = REPORTS / (started.strftime("%Y-%m-%d_%H%M%S") + ("_demo" if a.demo else ""))
    outdir.mkdir(parents=True, exist_ok=False)

    total = Result()
    if a.demo:
        from sscan import demo
        total = demo.result()
        mods = sorted({f.module for f in total.findings})
    for m in ([] if a.demo else mods):
        t = time.time()
        print(f"▶ {m} ...", flush=True)
        try:
            res = MODULES[m].scan(cfg)
        except Exception as e:  # noqa: BLE001  1モジュールの失敗で全体を止めない
            res = Result()
            # 例外文に秘密が混ざりうるので型名と発生箇所だけ残す
            tb = traceback.extract_tb(e.__traceback__)[-1]
            res.cov(m, "モジュール全体", "error", f"{type(e).__name__} at {Path(tb.filename).name}:{tb.lineno}", blocks=WHOLE)
            print(f"  ERROR {type(e).__name__} at {Path(tb.filename).name}:{tb.lineno}", flush=True)
        total.extend(res)
        print(f"  {len(res.findings)}件 / {time.time() - t:.0f}秒", flush=True)

    if not a.demo:
        _reports_location_check(total)
    findings = [f.to_dict() for f in total.findings]
    coverage = [c.to_dict() for c in total.coverage]
    prev, prev_cov = (demo.previous(), []) if a.demo else _previous(outdir, set(mods))
    # 確認できなかった範囲は「解消」「新規」と判定しない（見えなかっただけの可能性がある）
    new, resolved = report.diff(findings, prev, coverage, prev_cov)
    meta = {"demo": a.demo, "started": started.strftime("%Y-%m-%d %H:%M"), "elapsed": int((datetime.now() - started).total_seconds()),
            "modules": mods}
    report.write(outdir, meta, findings, coverage, new, resolved)

    if not a.demo:  # 見本は latest を上書きしない（次回の差分が壊れるため）
        _update_latest(outdir)

    hot = [f for f in findings if f["key"] in new and f["severity"] in ("critical", "high")]
    print((outdir / "summary.md").read_text(encoding="utf-8"))
    print(f"レポート: {outdir / 'report.html'}")
    if a.notify and hot:
        _notify("セキュリティスキャン", f"新しい緊急/高リスク {len(hot)}件: " + hot[0]["title"][:40], outdir / "report.html")
    if a.open:
        _open(outdir / "report.html")


def _setup_output(log: str):
    """コンソールやリダイレクト先が cp932 でも落ちないように UTF-8 で書く。pythonw（窓なし）では stdout が無いので --log を使う。"""
    if log:
        Path(log).parent.mkdir(parents=True, exist_ok=True)
        sys.stdout = sys.stderr = open(log, "a", encoding="utf-8", buffering=1)  # noqa: SIM115
        print(f"\n===== {datetime.now():%Y-%m-%d %H:%M} =====")
        return
    for s in (sys.stdout, sys.stderr):
        if s is not None and hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")


def _lock_down(d: Path):
    """reports フォルダを本人と SYSTEM だけが読める ACL にする（継承を切る）。Windows 以外は umask で足りる。"""
    if not WINDOWS:
        return
    rc, out, _ = run(["whoami", "/user", "/fo", "csv", "/nh"], 20)
    sid = out.strip().split(",")[-1].strip('"') if rc == 0 and "S-1-" in out else ""
    if sid:
        run(["icacls", str(d), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "/T", "/Q"], 120)


def _reports_location_check(total: Result):
    """レポート（弱点の一覧）がクラウド同期フォルダに置かれていないか。"""
    synced = [os.environ.get(k) for k in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")]
    p = str(REPORTS.resolve()).lower()
    if any(s and p.startswith(s.lower().rstrip("\\") + "\\") for s in synced) or "dropbox" in p or "google drive" in p:
        total.add("windows", "medium", "スキャン結果の保存先がクラウド同期フォルダの中にある", str(REPORTS),
                  "弱点の一覧がクラウドへアップロードされ、共有設定次第で他人に見える",
                  "スキルを %USERPROFILE%\\.claude\\skills\\security-scan など同期外に置くか、環境変数 SECURITY_SCAN_REPORTS で同期外を指定する",
                  key="reports-synced")


def _update_latest(outdir: Path):
    """reports/latest を最新結果のコピーにする（Windows では symlink に管理者権限か開発者モードが要るため）。"""
    latest = REPORTS / "latest"
    try:
        if latest.is_symlink() or latest.is_file():
            latest.unlink()
        elif latest.is_dir():
            shutil.rmtree(latest)
        shutil.copytree(outdir, latest)
        (latest / "SOURCE.txt").write_text(outdir.name + "\n", encoding="utf-8")
    except OSError as e:
        print(f"reports/latest を更新できませんでした（{type(e).__name__}）")


_TOAST = r"""
$d = $env:SSCAN_DATA | ConvertFrom-Json
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$t = $x.GetElementsByTagName('text'); $null = $t.Item(0).AppendChild($x.CreateTextNode($d.title)); $null = $t.Item(1).AppendChild($x.CreateTextNode($d.msg))
$x.DocumentElement.SetAttribute('activationType', 'protocol'); $x.DocumentElement.SetAttribute('launch', $d.url)
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))
"""


def _notify(title: str, msg: str, html: Path):
    if WINDOWS:
        # 文言はスクリプトに埋め込まず環境変数の JSON で渡す（finding 由来の文字列を PowerShell として解釈させない）
        rc, _, _ = powershell(_TOAST, 60, {"title": title, "msg": msg, "url": html.resolve().as_uri()})
        if rc != 0:
            print("通知を出せませんでした（Windows の通知設定を確認）")
    elif sys.platform == "darwin":
        run(["osascript", "-e", "on run argv", "-e", "display notification (item 1 of argv) with title (item 2 of argv)", "-e", "end run", msg, title])
    else:
        run(["notify-send", title, msg])


def _open(path: Path):
    try:
        if WINDOWS:
            os.startfile(str(path))  # noqa: S606  既定のブラウザで開く
            return
        rc, _, _ = run(["open" if sys.platform == "darwin" else "xdg-open", str(path)])
        if rc == 0:
            return
    except OSError:
        pass
    print(f"ブラウザで開けませんでした: {path}")


def _previous(current: Path, mods: set[str]):
    """同じモジュール構成で回した直近のレポートを前回とみなす（部分実行で差分が壊れないように）。"""
    for d in sorted(REPORTS.glob("20*"), reverse=True):
        if d == current or d.name.endswith("_demo") or not (d / "findings.json").exists():
            continue
        try:
            data = json.loads((d / "findings.json").read_text(encoding="utf-8"))
            if set(data["meta"]["modules"]) >= mods:
                return ([f for f in data["findings"] if f["module"] in mods and {"key", "severity", "title", "target"} <= f.keys()],
                        data.get("coverage", []))
        except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError):
            continue
    return None, []


if __name__ == "__main__":
    main()
