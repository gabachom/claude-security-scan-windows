"""osv-scanner を使わない依存パッケージの脆弱性検査（Python 標準ライブラリだけ）。

ロックファイル等から「パッケージ名＋バージョン」を読み、OSV.dev の公開 API に問い合わせる。
外へ送るのはパッケージ名・バージョン・エコシステム名だけ（コードやパスは送らない）。osv-scanner と同じ問い合わせ先。
結果は osv-scanner の JSON（results[].packages[].groups[]）と同じ形で返すので、repos._osv() でそのまま扱える。
新しい実行ファイルを置かないので、ウイルス対策ソフトや Smart App Control に止められない。
"""
from __future__ import annotations

import json
import math
import re
import threading
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .common import run

API = "https://api.osv.dev/v1"
UA = "claude-security-scan-windows (osvlite)"
BATCH = 1000  # querybatch の1回あたりの上限

# ファイル名 → (エコシステム, 読み取り関数名)
LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm",
    "poetry.lock": "PyPI", "Pipfile.lock": "PyPI", "uv.lock": "PyPI", "pdm.lock": "PyPI",
    "Cargo.lock": "crates.io", "go.mod": "Go", "Gemfile.lock": "RubyGems", "composer.lock": "Packagist",
}
_REQ = re.compile(r"(?i)^requirements[\w.-]*\.txt$")
_SKIP_PARTS = {"node_modules", "vendor", ".venv", "venv", "site-packages", ".git", "dist", "build", ".next"}
MAX_BYTES = 50 * 1024 * 1024

_lock = threading.Lock()
_vuln_cache: dict[str, dict] = {}   # 脆弱性ID → 詳細（全リポで共有）
_query_cache: dict[tuple, list[str]] = {}  # (eco, name, ver) → 脆弱性ID一覧


# ---------------------------------------------------------------- 依存ファイルの読み取り

def _npm_lock(text: str) -> tuple[set, int]:
    d = json.loads(text)
    out = set()
    pk = d.get("packages")
    if isinstance(pk, dict):  # lockfileVersion 2 / 3
        for path, info in pk.items():
            if not path or info.get("link") or not info.get("version"):
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            out.add((name, info["version"]))
    else:  # lockfileVersion 1
        def walk(deps):
            for name, info in (deps or {}).items():
                if isinstance(info, dict) and info.get("version") and not str(info["version"]).startswith(("file:", "link:", "git")):
                    out.add((name, info["version"]))
                    walk(info.get("dependencies"))
        walk(d.get("dependencies"))
    return out, 0


_PNPM_KEY = re.compile(r"""^ {2}['"]?/?((?:@[^/@\s]+/)?[^/@\s(]+)[@/]([0-9][^\s('":_]*)""")


def _pnpm_lock(text: str) -> tuple[set, int]:
    out, inside = set(), False
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            inside = line.rstrip() in ("packages:", "snapshots:")
            continue
        if inside:
            m = _PNPM_KEY.match(line)
            if m:
                out.add((m.group(1), m.group(2)))
    return out, 0


def _yarn_lock(text: str) -> tuple[set, int]:
    out, names = set(), []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            spec = line.rstrip()[:-1].split(",")[0].strip().strip('"')
            if "@patch:" in spec or "@workspace:" in spec or "@link:" in spec or "@file:" in spec:
                names = []
                continue
            at = spec.rfind("@")
            names = [spec[:at]] if at > 0 and not spec.startswith("__") else []
        elif names:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m:
                out.add((names[0], m.group(1)))
                names = []
    return out, 0


def _toml_packages(text: str, need_source: bool = False) -> tuple[set, int]:
    d = tomllib.loads(text)
    out = set()
    for p in d.get("package", []):
        src = p.get("source")
        if need_source and not src:  # Cargo: ローカルのクレート
            continue
        if isinstance(src, dict) and ({"editable", "virtual", "path", "directory"} & src.keys()):  # uv: 自分のプロジェクト
            continue
        if p.get("name") and p.get("version"):
            out.add((p["name"], str(p["version"])))
    return out, 0


def _pipfile_lock(text: str) -> tuple[set, int]:
    d = json.loads(text)
    out = set()
    for sec in ("default", "develop"):
        for name, info in (d.get(sec) or {}).items():
            v = str((info or {}).get("version", ""))
            if v.startswith("=="):
                out.add((name, v[2:]))
    return out, 0


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#,]+)")


def _requirements(text: str) -> tuple[set, int]:
    out, unpinned = set(), 0
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s or s.startswith(("-", "git+", "http:", "https:", ".", "/")):
            continue
        m = _REQ_LINE.match(s)
        if m:
            out.add((m.group(1), m.group(2)))
        else:
            unpinned += 1
    return out, unpinned


def _go_mod(text: str) -> tuple[set, int]:
    out, block = set(), False
    for line in text.splitlines():
        s = line.split("//", 1)[0].strip()
        if s.startswith("require ("):
            block = True
            continue
        if block and s == ")":
            block = False
            continue
        if s.startswith("require "):
            s = s[len("require "):].strip()
        elif not block:
            continue
        parts = s.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.add((parts[0], parts[1][1:].replace("+incompatible", "")))
    return out, 0


_GEM_PLATFORM = re.compile(r"-(?:x86|x64|arm|aarch64|java|mingw|mswin|darwin|linux|universal)[\w.-]*$")


def _gemfile_lock(text: str) -> tuple[set, int]:
    out, inside = set(), False
    for line in text.splitlines():
        if line.strip() == "specs:":
            inside = True
            continue
        if inside and line and not line.startswith(" "):
            inside = False
        m = re.match(r"^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)$", line) if inside else None
        if m:
            out.add((m.group(1), _GEM_PLATFORM.sub("", m.group(2))))
    return out, 0


def _composer_lock(text: str) -> tuple[set, int]:
    d = json.loads(text)
    out = set()
    for p in (d.get("packages") or []) + (d.get("packages-dev") or []):
        v = str(p.get("version", ""))
        if p.get("name") and v and not v.startswith("dev-"):
            out.add((p["name"], v[1:] if v[:1] == "v" else v))
    return out, 0


PARSERS = {
    "package-lock.json": _npm_lock, "npm-shrinkwrap.json": _npm_lock, "pnpm-lock.yaml": _pnpm_lock, "yarn.lock": _yarn_lock,
    "poetry.lock": _toml_packages, "uv.lock": _toml_packages, "pdm.lock": _toml_packages,
    "Pipfile.lock": _pipfile_lock, "Cargo.lock": lambda t: _toml_packages(t, need_source=True),
    "go.mod": _go_mod, "Gemfile.lock": _gemfile_lock, "composer.lock": _composer_lock,
}


def find_manifests(repo: Path) -> list[Path]:
    """git が見ているファイル（追跡中＋無視されていない未追跡）から依存ファイルを探す。"""
    rc, out, _ = run(["git", "-C", str(repo), "ls-files", "--cached", "--others", "--exclude-standard"], 60)
    files = out.splitlines() if rc == 0 else []
    found = []
    for f in files:
        parts = f.split("/")
        if _SKIP_PARTS & set(parts[:-1]):
            continue
        if parts[-1] in PARSERS or _REQ.match(parts[-1]):
            found.append(repo / f)
    return sorted(set(found))


# ---------------------------------------------------------------- OSV.dev への問い合わせ

def _post(path: str, body: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _get(path: str, timeout: int = 60) -> dict:
    req = urllib.request.Request(API + path, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _query(pkgs: list[tuple[str, str, str]]) -> dict[tuple, list[str]]:
    """(eco, name, ver) の一覧を querybatch で問い合わせ、脆弱性IDの一覧を返す。結果はキャッシュする。"""
    with _lock:
        todo = [p for p in pkgs if p not in _query_cache]
    for i in range(0, len(todo), BATCH):
        chunk = todo[i:i + BATCH]
        queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]
        res = _post("/querybatch", {"queries": queries}).get("results", [])
        for p, q, rr in zip(chunk, queries, res):
            ids = [v["id"] for v in rr.get("vulns") or []]
            token = rr.get("next_page_token")
            while token:  # 1パッケージに大量の脆弱性があるとき
                more = _post("/querybatch", {"queries": [{**q, "page_token": token}]}).get("results", [{}])[0]
                ids += [v["id"] for v in more.get("vulns") or []]
                token = more.get("next_page_token")
            with _lock:
                _query_cache[p] = ids
    with _lock:
        return {p: _query_cache.get(p, []) for p in pkgs}


def _details(ids: set[str]) -> dict[str, dict]:
    with _lock:
        todo = [i for i in ids if i not in _vuln_cache]

    def fetch(vid):
        try:
            d = _get(f"/vulns/{vid}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            d = {"id": vid}
        with _lock:
            _vuln_cache[vid] = {"id": vid, "aliases": d.get("aliases") or [], "score": _score(d)}

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(fetch, todo))
    with _lock:
        return {i: _vuln_cache[i] for i in ids if i in _vuln_cache}


# ---------------------------------------------------------------- 重要度（CVSS v3 の基本値を計算）

_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44}, "UI": {"N": .85, "R": .62},
      "CIA": {"H": .56, "L": .22, "N": 0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3(vector: str) -> float | None:
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        if impact <= 0:
            return 0.0
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))
    except KeyError:
        return None


_LABEL = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.0}


def _score(d: dict) -> float:
    """CVSS v3 のベクトルがあれば計算、無ければ GitHub 等の重要度ラベルを数値に置き換える。"""
    best = None
    for s in d.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            v = cvss3(str(s.get("score", "")))
            best = v if best is None or (v is not None and v > best) else best
    if best is not None:
        return best
    labels = [str((d.get("database_specific") or {}).get("severity", ""))]
    labels += [str((a.get("ecosystem_specific") or {}).get("severity", "")) for a in d.get("affected") or []]
    return max([_LABEL.get(l.upper(), 0.0) for l in labels] or [0.0])


# ---------------------------------------------------------------- まとめ

def scan_repo(repo: Path) -> tuple[dict | None, list[str], str]:
    """戻り値: (osv-scanner 形式の結果 or None, 読めなかった依存ファイルなどの注記, エラー文)。"""
    notes, by_file = [], {}
    for f in find_manifests(repo):
        try:
            if f.stat().st_size > MAX_BYTES:
                notes.append(f"{f.name}: 大きすぎるので省略")
                continue
            parser = PARSERS.get(f.name, _requirements)
            pkgs, unpinned = parser(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError) as e:
            notes.append(f"{f.relative_to(repo).as_posix()}: 読めない（{type(e).__name__}）")
            continue
        if unpinned:
            notes.append(f"{f.relative_to(repo).as_posix()}: バージョン固定なし {unpinned}件は判定できない")
        eco = LOCKFILES.get(f.name, "PyPI")
        if pkgs:
            by_file[f] = [(eco, n, v) for n, v in sorted(pkgs)]
    if not by_file:
        return None, notes, ""
    allp = sorted({p for ps in by_file.values() for p in ps})
    try:
        ids = _query(allp)
        det = _details({i for v in ids.values() for i in v})
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        return None, notes, f"OSV.dev に問い合わせできない（{type(e).__name__}）"
    results = []
    for f, ps in by_file.items():
        packages = []
        for p in ps:
            vids = ids.get(p) or []
            if not vids:
                continue
            packages.append({"package": {"name": p[1], "version": p[2], "ecosystem": p[0]}, "groups": _group(vids, det)})
        if packages:
            results.append({"source": {"path": str(f), "type": "lockfile"}, "packages": packages})
    return {"results": results}, notes, ""


def _group(vids: list[str], det: dict[str, dict]) -> list[dict]:
    """別名（CVE と GHSA など）でつながる脆弱性を1件にまとめる（osv-scanner の groups と同じ考え方）。"""
    groups: list[dict] = []
    for vid in vids:
        d = det.get(vid, {"id": vid, "aliases": [], "score": 0.0})
        names = {vid, *d["aliases"]}
        hit = next((g for g in groups if g["_names"] & names), None)
        if hit:
            hit["_names"] |= names
            hit["ids"].append(vid)
            hit["_score"] = max(hit["_score"], d["score"])
        else:
            groups.append({"_names": names, "ids": [vid], "_score": d["score"]})
    rank = lambda n: (0 if n.startswith("CVE-") else 1 if n.startswith("GHSA-") else 2, n)  # noqa: E731  表示は CVE → GHSA → その他
    return [{"ids": g["ids"], "aliases": sorted(g["_names"], key=rank), "max_severity": str(g["_score"])} for g in groups]
