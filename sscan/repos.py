"""ローカルのgitリポジトリ: コミット履歴の秘密情報（gitleaks）・.env の追跡・依存の既知脆弱性（osv-scanner か内蔵の OSV.dev 検査）。"""
from __future__ import annotations

import json
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import osvlite
from .common import WHOLE, WINDOWS, ROOT, Result, run, run_json, short_err, tool

GITLEAKS = OSV = None

M = "repos"
SKIP_DIRS = {"node_modules", ".venv", "venv", ".next", "dist", "build", ".git", "__pycache__", ".cache", "vendor", "Pods"}
ENV_TRACKED = re.compile(r"(^|/)\.env(\.[\w-]+)?$")
ENV_OK = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)


def discover(roots: list[str], exclude: list[str], max_depth: int) -> list[Path]:
    found = []
    for root in roots:
        root = Path(os.path.expanduser(root))
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            p = Path(dirpath)
            if ".git" in dirnames or ".git" in filenames:
                found.append(p)
            if len(p.parts) - base_depth >= max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not any(x in (p / d).as_posix() + "/" for x in exclude)]
    # worktree は本体と履歴を共有するので、git の共通ディレクトリごとに1つ（パスが最も短いもの）だけ残す
    by_common: dict[str, Path] = {}
    for repo in sorted(set(found), key=lambda x: (len(x.parts), str(x))):
        _, out, _ = run(["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-common-dir"], 10)
        by_common.setdefault(out.strip() or str(repo), repo)
    return sorted(by_common.values())


def _remote(repo: Path) -> str:
    _, out, _ = run(["git", "-C", str(repo), "remote", "get-url", "origin"], 10)
    m = re.search(r"github\.com[:/]([^/]+/[^/\s]+?)(?:\.git)?$", out.strip())
    return m.group(1).lower() if m else ""


def _owners_and_public() -> tuple[set[str], dict[str, str]]:
    """自分と所属orgのアカウント名と、そこが持つ public リポジトリ（値はフォーク元。フォークでなければ空文字）。"""
    pub: dict[str, str] = {}
    me, _ = run_json(["gh", "api", "user", "--jq", "{login: .login}"])
    orgs, _ = run_json(["gh", "api", "user/orgs", "--jq", "[.[].login]"])
    owners = ([me["login"]] if me else []) + (orgs or [])
    for o in owners:
        data, _ = run_json(["gh", "repo", "list", o, "--visibility", "public", "--limit", "1000", "--json", "nameWithOwner,isFork,parent"], 60)
        for d in data or []:
            par = d.get("parent") or {}
            parent = f'{(par.get("owner") or {}).get("login", "")}/{par.get("name", "")}' if d.get("isFork") and par else ""
            pub[d["nameWithOwner"].lower()] = parent.lower() if parent != "/" else ""
    return {o.lower() for o in owners}, pub


def _commit_state(repo: Path, sha: str, parent: str, cache: dict) -> str:
    """漏えいしたコミットの状態: parent（フォーク元にもある＝引き継いだ履歴）/ pushed（リモートのブランチにある）/ local（未push）。
    リモートの状態は手元の追跡ブランチで判定する（fetch はしない）。"""
    if not sha:
        return "pushed"
    if sha in cache:
        return cache[sha]
    state = "local"
    rc, out, _ = run(["git", "-C", str(repo), "branch", "-r", "--contains", sha], 30)
    if rc != 0 or out.strip():
        state = "pushed"
    if parent and run(["gh", "api", f"repos/{parent}/commits/{sha}", "--jq", ".sha"], 30)[0] == 0:
        state = "parent"
    cache[sha] = state
    return state


DEFAULT_ROOTS = ["~/dev", "~/work", "~/projects", "~/Project", "~/src", "~/code", "~/Developer", "~/repos", "~/git", "~/source/repos",
                 "~/Documents/GitHub"]


def _default_roots() -> list[str]:
    """既定の置き場に、Windows の実際の「ドキュメント」（OneDrive へ移動されていることがある）配下の GitHub / Visual Studio を足す。"""
    roots = list(DEFAULT_ROOTS)
    if WINDOWS:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
                docs = Path(os.path.expandvars(winreg.QueryValueEx(k, "Personal")[0]))
            roots += [str(docs / "GitHub"), str(docs / "Visual Studio 2022" / "Projects")]
        except OSError:
            pass
    seen, out = set(), []
    for d in roots:
        p = Path(os.path.expanduser(d))
        k = str(p.resolve()).lower() if p.is_dir() else ""
        if k and k not in seen:
            seen.add(k)
            out.append(str(p))
    return out


def _synced(p: Path) -> str:
    """OneDrive などクラウド同期フォルダの中なら、そのサービス名を返す。"""
    s = str(p).lower() + "\\"
    for k in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        v = os.environ.get(k)
        if v and s.startswith(v.lower().rstrip("\\") + "\\"):
            return "OneDrive"
    if "\\dropbox\\" in s:
        return "Dropbox"
    return "Google ドライブ" if "\\google drive\\" in s or "\\マイドライブ\\" in s else ""


def scan(cfg: dict) -> Result:
    global GITLEAKS, OSV
    c = cfg.get("repos", {})
    r = Result()
    GITLEAKS = _runnable(r, "gitleaks", ["version"])
    if not GITLEAKS:
        c = {**c, "gitleaks": False, "secret_dirs": []}
        r.cov(M, "gitleaks", "skip", "未インストールか起動できない（scripts/install-tools.ps1 で入る）。秘密情報の検査を省略", blocks=[("秘密情報", "")])
    # 依存の脆弱性: builtin（既定）= 内蔵（OSV.dev API に直接問い合わせ）/ osv-scanner / auto = osv-scanner が起動できればそれ
    # 既定で osv-scanner を起動しないのは、未署名の exe を起動するたびにウイルス対策ソフトの警告が出る環境があるため
    engine = c.get("osv_engine", "builtin")
    OSV = None if engine == "builtin" else _runnable(r if engine == "osv-scanner" else Result(), "osv-scanner", ["--version"])
    if c.get("osv", True) and not OSV:
        if engine == "osv-scanner":
            c = {**c, "osv": False}
            r.cov(M, "osv-scanner", "skip", "未インストールか起動できない（scripts/install-tools.ps1 で入る）。依存の脆弱性検査を省略", blocks=[("依存パッケージ", "")])
        else:
            r.cov(M, "依存の脆弱性検査", "ok", "内蔵の検査（OSV.dev API）を使用" + ("" if engine == "builtin" else "。osv-scanner は未インストールか起動できない"))
    roots = c.get("roots") or _default_roots()
    repos = discover(roots, c.get("exclude", ["/_archive/", "/node_modules/"]), c.get("max_depth", 6))
    owners, public = _owners_and_public()
    # 他者のリポジトリを手元にcloneしただけのもの（llama.cpp 等）は自分の漏えい・脆弱性ではないので外す
    theirs = [p for p in repos if owners and (rm := _remote(p)) and rm.split("/")[0] not in owners]
    repos = [p for p in repos if p not in theirs]
    r.cov(M, "対象リポジトリ", "ok", f"{len(repos)}件（他者のリポジトリ {len(theirs)}件は対象外）")
    with ThreadPoolExecutor(max_workers=c.get("workers", 4)) as ex:
        for sub in ex.map(lambda p: _safe_repo(p, public, c), repos):
            r.extend(sub)
    for d in c.get("secret_dirs", ["~/.claude/skills"]):
        _scan_dir(r, Path(os.path.expanduser(d)))
    return r


def _runnable(r: Result, name: str, probe: list[str]) -> str | None:
    """見つかっても起動できないことがある（ウイルス対策ソフトや Smart App Control が未署名の exe を止める）。"""
    path = tool(name)
    if not path:
        return None
    rc, _, err = run([path, *probe], 30)
    if rc in (0, 1):
        return path
    r.cov(M, f"{name} の起動", "error", f"起動できない（rc={rc}）: {short_err(err[-120:])}。"
          "ウイルス対策ソフトが未署名の実行ファイルを止めている可能性。bin フォルダを除外に入れるか、winget で入れ直す", blocks=[])
    return None


def _scan_dir(r: Result, d: Path):
    """gitで管理していない置き場（スキル等）を作業ツリーのまま検査する。"""
    if not d.is_dir():
        return
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        rp = tf.name
    try:
        rc, _, err = run([GITLEAKS, "dir", str(d), "--redact", "--no-banner", "--log-level", "error",
                          "--max-target-megabytes", "2", "--report-format", "json", "--report-path", rp, "--exit-code", "0"], 600)
        if rc != 0:
            r.cov(M, f"gitleaks {_label(d)}", "error", short_err(err[-200:]), blocks=[("ローカルの置き場", _label(d))])
            return
        by_file: dict[str, list[str]] = {}
        own_reports = str(ROOT / "reports")
        for l in json.loads(Path(rp).read_text(encoding="utf-8", errors="replace") or "[]"):
            if l.get("File", "").lower().startswith(own_reports.lower()):  # このツール自身のレポート（差分キーのハッシュが誤検知される）
                continue
            by_file.setdefault(l.get("File", "?"), []).append(f'{l.get("RuleID")} 行{l.get("StartLine")}')
        for f, hits in by_file.items():
            r.add(M, "medium", "ファイルに秘密情報らしき文字列（ローカルの置き場）", _label(Path(f)),
                  "値は伏せ字\n" + "\n".join(hits[:10]),
                  "本物のキーならユーザー環境変数や資格情報マネージャーへ移し、共有・公開するスキルに含めない。偽値なら無視",
                  key=f"dirleak|{f}")
        r.cov(M, f"秘密情報検査 {_label(d)}", "ok", f"{len(by_file)}ファイル")
    finally:
        Path(rp).unlink(missing_ok=True)


def _safe_repo(repo: Path, public: dict[str, str], c: dict) -> Result:
    try:
        return _scan_repo(repo, public, c)
    except Exception as e:  # noqa: BLE001  1リポの失敗で全体を止めない
        r = Result()
        r.cov(M, _label(repo), "error", type(e).__name__, blocks=[("", _label(repo) + "  ")])
        return r


def _label(repo: Path) -> str:
    return str(repo).replace(str(Path.home()), "~")


def _scan_repo(repo: Path, public: dict[str, str], c: dict) -> Result:
    r = Result()
    remote = _remote(repo)
    is_public = remote in public
    parent = public.get(remote, "")
    inactive = any(x in repo.as_posix() + "/" for x in ("/_archive/", "/_inactive/"))
    where = _label(repo) + (f"  ({remote}・公開)" if is_public else (f"  ({remote})" if remote else "  (リモートなし)"))

    # 0) クラウド同期フォルダの中のリポジトリ（.gitignore で除外した .env も同期される。同期が .git を壊すこともある）
    svc = _synced(repo)
    if svc:
        _, ign, _ = run(["git", "-C", str(repo), "ls-files", "--others", "--ignored", "--exclude-standard", "--directory"], 60)
        envs = [f for f in ign.splitlines() if ENV_TRACKED.search(f) and not ENV_OK.search(f)]
        r.add(M, "medium" if envs else "low", f"リポジトリが {svc} の同期フォルダの中にある", where,
              ("git では除外している .env もクラウドへ同期されている: " + ", ".join(envs[:5])) if envs else "コードと .git の中身がクラウドへ同期される",
              f"開発物は %USERPROFILE%\\Project など同期外へ移す（{svc} の同期中に .git や node_modules が壊れることもある）",
              key=f"synced|{repo}")

    # 1) .env の追跡
    _, out, _ = run(["git", "-C", str(repo), "ls-files"], 30)
    tracked = [f for f in out.splitlines() if ENV_TRACKED.search(f) and not ENV_OK.search(f)]
    if tracked:
        r.add(M, "critical" if is_public else "high", ".env ファイルがgitに登録されている", where,
              "\n".join(tracked[:20]),
              "git rm --cached で追跡を外し .gitignore に追加。中のキーは漏れた前提でローテーションする")

    # 2) コミット履歴の秘密情報（値は redact）
    if c.get("gitleaks", True):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            rp = tf.name
        try:
            rc, _, err = run([GITLEAKS, "git", str(repo), "--redact", "--no-banner", "--log-level", "error",
                              "--report-format", "json", "--report-path", rp, "--exit-code", "0"], timeout=c.get("gitleaks_timeout", 600))
            if rc == 0:
                leaks = json.loads(Path(rp).read_text(encoding="utf-8", errors="replace") or "[]")
                by_rule: dict[str, list[tuple[str, str]]] = {}
                cache: dict[str, str] = {}
                state_ja = {"local": "未push", "pushed": "push済み", "parent": "フォーク元の履歴"}
                for l in leaks:
                    sha = l.get("Commit") or ""
                    st = _commit_state(repo, sha, parent, cache) if is_public else "pushed"
                    loc = f'{l.get("File")}:{l.get("StartLine")} ({sha[:7]}' + (f"・{state_ja[st]})" if is_public else ")")
                    by_rule.setdefault(l.get("RuleID", "?"), []).append((st, loc))
                for rule, items in by_rule.items():
                    states = {st for st, _ in items}
                    locs = sorted({loc for _, loc in items})
                    fix = "①そのキーを発行元で無効化・再発行 ②テスト用の偽値なら .gitleaksignore に登録 ③公開リポなら履歴からの除去も検討（git filter-repo）"
                    note = ""
                    if is_public and "pushed" in states:
                        sev = "critical"
                    elif is_public and "local" in states:
                        # 公開リポだがまだ push していない。push した瞬間に公開される
                        sev = "high"
                        note = "まだ push していないコミット（push すると公開リポで誰でも読める）\n"
                        fix = "push する前にコミットからキーを取り除く（git reset / git commit --amend 等）。本物のキーなら念のため再発行も"
                    elif is_public:  # 全部フォーク元の履歴
                        sev = "low"
                        note = f"フォーク元（{parent}）にも同じコミットがある。自分が入れたキーではない可能性が高い\n"
                        fix = "自分のキーでなければ対応不要（気になればフォーク元に知らせる）。誤検知なら .gitleaksignore に登録"
                    else:
                        sev = "medium" if inactive else "high"
                    r.add(M, sev, f"コミット履歴に秘密情報らしき文字列: {rule}", where,
                          note + f"{len(items)}箇所（値は伏せ字）\n" + "\n".join(locs[:15]), fix, key=f"leak|{repo}|{rule}")
            else:
                r.cov(M, f"gitleaks {_label(repo)}", "error", short_err(err[-200:]), blocks=[("コミット履歴", _label(repo) + "  ")])
        finally:
            Path(rp).unlink(missing_ok=True)

    # 3) 依存の既知脆弱性
    if c.get("osv", True) and not OSV:
        data, notes, err = osvlite.scan_repo(repo)
        if err:
            r.cov(M, f"依存の脆弱性 {_label(repo)}", "error", err, blocks=[("依存パッケージ", _label(repo) + "  ")])
        elif notes:
            r.cov(M, f"依存ファイル {_label(repo)}", "skip", " / ".join(notes)[:300], blocks=[])
        if data:
            _osv(r, data, where, is_public, inactive)
    elif c.get("osv", True):
        # 脆弱性ありだと exit 1 になるので rc ではなく stdout の JSON で判定する
        rc, out, err = run([OSV, "scan", "source", "-r", "--format", "json", str(repo)], timeout=c.get("osv_timeout", 300))
        try:
            data = json.loads(out[out.find("{"):]) if "{" in out else None
        except json.JSONDecodeError:
            data = None
        if data is None and rc not in (0, 128) and "No package sources found" not in (err + out):
            r.cov(M, f"osv {_label(repo)}", "error", short_err(err[-200:]), blocks=[("依存パッケージ", _label(repo) + "  ")])
        if data:
            _osv(r, data, where, is_public, inactive)
    return r


def _sev_of(group: dict) -> str:
    try:
        score = float(group.get("max_severity") or 0)
    except ValueError:
        score = 0
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _osv(r: Result, data: dict, where: str, is_public: bool, inactive: bool):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    top: list[tuple[str, str]] = []
    for res in data.get("results", []):
        for pkg in res.get("packages", []):
            name = f'{pkg["package"]["name"]}@{pkg["package"].get("version", "")}'
            for g in pkg.get("groups", []):
                s = _sev_of(g)
                counts[s] += 1
                if s in ("critical", "high"):
                    top.append((s, f'{name}: {", ".join(g.get("aliases", g.get("ids", []))[:2])}'))
    total = sum(counts.values())
    if not total:
        return
    worst = next(s for s in ("critical", "high", "medium", "low") if counts[s])
    # 依存の脆弱性は外から突ける状態か（本番で動いているか）が分からないので1段下げ、
    # 「緊急」は公開中の漏えいなど今すぐ悪用できるものに残す。休眠リポはさらに1段下げる
    worst = {"critical": "high", "high": "medium", "medium": "low"}.get(worst, "low")
    if inactive:
        worst = {"high": "medium", "medium": "low"}.get(worst, "low")
    summary = " / ".join(f"{k}:{v}" for k, v in counts.items() if v)
    r.add(M, worst, "依存パッケージに既知の脆弱性", where,
          f"{total}件（{summary}）\n" + "\n".join(t for _, t in sorted(set(top))[:12]),
          "npm audit fix / pip install -U <pkg> 等で更新し、動作確認してからPR。休眠中なら archive 化も検討",
          key=f"osv|{where}")
