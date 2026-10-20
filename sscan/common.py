"""共通部品: Finding / Coverage / コマンド実行。

このツールは読み取り専用。外部状態を変える API は呼ばない。
秘密値はどの出力にも載せない（gitleaks は --redact、env は名前だけ）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_JA = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}

WINDOWS = sys.platform == "win32"


def _extra_path() -> list[str]:
    """タスクスケジューラから呼ばれても CLI が見つかるように、よく入る場所を PATH に足す。"""
    if not WINDOWS:
        return ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    env = os.environ.get
    home = Path.home()
    cands = [
        Path(env("APPDATA", home / "AppData/Roaming")) / "npm",                     # vercel / supabase（npm -g）
        Path(env("LOCALAPPDATA", home / "AppData/Local")) / "Microsoft/WinGet/Links",  # winget で入れた CLI
        home / "scoop/shims",
        Path(env("ProgramFiles", "C:/Program Files")) / "GitHub CLI",
        Path(env("ProgramFiles", "C:/Program Files")) / "Git/cmd",
        Path(env("ProgramFiles", "C:/Program Files")) / "Amazon/AWSCLIV2",
        Path(env("ProgramFiles", "C:/Program Files")) / "Microsoft SDKs/Azure/CLI2/wbin",
        Path(env("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft SDKs/Azure/CLI2/wbin",
        Path(env("LOCALAPPDATA", home / "AppData/Local")) / "Google/Cloud SDK/google-cloud-sdk/bin",
        Path(env("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Google/Cloud SDK/google-cloud-sdk/bin",
    ]
    return [str(c) for c in cands if c.is_dir()]


os.environ["PATH"] = os.pathsep.join([str(BIN), *_extra_path(), os.environ.get("PATH", "")])
os.environ.setdefault("USER", os.environ.get("USERNAME", Path.home().name))
os.environ.setdefault("HOME", str(Path.home()))


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    target: str
    detail: str = ""
    fix: str = ""
    # 差分判定に使う安定キー。detail が毎回変わる項目（件数など）でも同一扱いにする
    key: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(self.severity)
        if not self.key:
            self.key = hashlib.sha1(f"{self.module}|{self.title}|{self.target}".encode()).hexdigest()[:16]

    def to_dict(self):
        return asdict(self)


WHOLE = [("*", "*")]  # モジュール全体が見えていない


@dataclass
class Coverage:
    module: str
    item: str
    status: str  # ok / skip / error
    message: str = ""
    # この確認が通らなかったときに「解消」「新規」の判定から外す指摘の範囲。
    # (タイトルに含む文字列, 対象に含む文字列) の組。省略時は対象に item を含む指摘。("*","*") はモジュール全体
    blocks: list = None

    def __post_init__(self):
        if self.blocks is None:
            self.blocks = [] if self.status == "ok" else [("", self.item)]

    def to_dict(self):
        return asdict(self)


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)

    def add(self, *a, **kw):
        self.findings.append(Finding(*a, **kw))

    def cov(self, *a, **kw):
        self.coverage.append(Coverage(*a, **kw))

    def extend(self, other: "Result"):
        self.findings += other.findings
        self.coverage += other.coverage


def tool(name: str) -> str | None:
    """同梱の bin/ を優先し、無ければ PATH から探す。見つからなければ None。"""
    for n in ([name + ".exe", name] if WINDOWS else [name]):
        local = BIN / n
        if local.is_file():
            return str(local)
    return shutil.which(name)


# cmd.exe がクォートの中でも解釈してしまう文字。.cmd/.bat に渡す引数にあれば実行しない（コマンド注入対策）
_CMD_UNSAFE = re.compile(r'["%\r\n]')
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # タスクスケジューラ実行時に黒い窓を出さない


def _windows_cmdline(cmd: list[str]) -> str | list[str]:
    """Windows では gcloud / az / vercel などが .cmd のラッパーなので、実体を探して安全に起動できる形にする。"""
    exe = shutil.which(cmd[0]) or cmd[0]
    if not exe.lower().endswith((".cmd", ".bat")):
        return [exe, *cmd[1:]]
    bad = [a for a in cmd[1:] if _CMD_UNSAFE.search(a)]
    if bad:
        raise ValueError("unsafe argument for batch file")
    # 引数は全部 "..." で囲む（& | < > ^ をそのまま渡す）。/s で外側のクォートだけを外させ、/d で AutoRun を無効にする
    inner = " ".join(f'"{a}"' for a in [exe, *cmd[1:]])
    return f'cmd.exe /d /s /c "{inner}"'


def run(cmd: list[str], timeout: int = 120, cwd: str | None = None, env: dict | None = None) -> tuple[int, str, str]:
    try:
        args = _windows_cmdline(cmd) if WINDOWS else cmd
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                           cwd=cwd, env=env, stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except ValueError:
        return 126, "", f"refused: unsafe argument for {cmd[0]}"
    except PermissionError:  # ウイルス対策ソフト等が実行を止めた（WinError 5）
        return 126, "", f"permission denied: {Path(cmd[0]).name}"
    except OSError as e:
        return 126, "", f"{type(e).__name__}: {Path(cmd[0]).name}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


_PS_PRELUDE = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
               "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$OutputEncoding=[Text.Encoding]::UTF8;")


def powershell(script: str, timeout: int = 120, data=None) -> tuple[int, str, str]:
    """Windows PowerShell 5.1 でスクリプトを実行する（UTF-8 で受け取る）。
    スクリプトは -EncodedCommand で渡し、外から来た文字列（パス等）は data として環境変数 SSCAN_DATA の JSON で渡す。
    文字列をスクリプトに埋め込まないので、パス名などに記号が入っていても PowerShell として解釈されない。"""
    exe = shutil.which("powershell") or "powershell.exe"
    enc = base64.b64encode((_PS_PRELUDE + script).encode("utf-16-le")).decode()
    env = None
    if data is not None:
        env = {**os.environ, "SSCAN_DATA": json.dumps(data, ensure_ascii=False)}
    return run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc], timeout, env=env)


def powershell_json(script: str, timeout: int = 120, data=None):
    """PowerShell の結果を JSON で受け取る。script の最後で ConvertTo-Json すること。失敗時は (None, エラー文)。"""
    rc, out, err = powershell(script, timeout, data)
    if rc != 0:
        return None, short_err((err.strip() or out.strip())[-400:])
    out = out.strip()
    if not out:
        return [], ""
    try:
        return json.loads(out), ""
    except json.JSONDecodeError:
        return None, "JSON parse error（応答本文は記録しない）"


def run_json(cmd: list[str], timeout: int = 120, cwd: str | None = None):
    """JSON を返すコマンドを実行する。失敗時は (None, エラー文) を返す。"""
    rc, out, err = run(cmd, timeout, cwd)
    if rc != 0:
        return None, short_err((err.strip() or out.strip())[-400:])
    try:
        return json.loads(out), ""
    except json.JSONDecodeError:
        start = min([i for i in (out.find("{"), out.find("[")) if i >= 0], default=-1)
        if start >= 0:
            try:
                return json.loads(out[start:]), ""
            except json.JSONDecodeError:
                pass
        return None, "JSON parse error（応答本文は記録しない）"


_TOKENISH = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")
_ASSIGN = re.compile(r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH)[A-Z0-9_]*)\s*[=:]\s*\S+")
_URL_CRED = re.compile(r"(https?://)[^/@\s]+@")


def redact(msg: str) -> str:
    """エラー文に紛れ込んだ秘密値らしきものを伏せる（URLの認証情報・KEY=値・長いトークン列）。"""
    msg = _URL_CRED.sub(r"\1***@", msg)
    msg = _ASSIGN.sub(r"\1=***", msg)
    return _TOKENISH.sub(lambda m: m.group(0)[:4] + "***", msg)


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")  # gitleaks 等の色付けエスケープ


def short_err(msg: str) -> str:
    return redact(" ".join(_ANSI.sub("", msg).split()))[:300]
