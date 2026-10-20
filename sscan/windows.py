"""このWindows PC本体の設定チェック（管理者権限なしで読める範囲）。

読み取りだけ。レジストリは winreg で読み、それ以外は PowerShell の Get-* 系だけを使う。
常駐・タスク・サービスの「起動引数」は秘密が入りうるので記録しない（危険な書き方かの判定にだけ使う）。
"""
from __future__ import annotations

import os
import re
from datetime import date, datetime, timedelta
from pathlib import Path

from .common import WHOLE, WINDOWS, Result, powershell_json, run, short_err

if WINDOWS:
    import winreg

M = "windows"
PC = "このPC"
HOME = Path.home()
SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")


# ---------------------------------------------------------------- 共通部品

def _reg(hive, path: str, name: str):
    """レジストリ値を読む。無ければ None。64bit ビューを見る（32bit Python でも同じ結果になるように）。"""
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _reg_key_exists(hive, path: str) -> bool:
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        return False


def _reg_values(hive, path: str, view: int = 0) -> dict[str, str]:
    out = {}
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | (view or winreg.KEY_WOW64_64KEY)) as k:
            i = 0
            while True:
                try:
                    n, v, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                if isinstance(v, str):
                    out[n] = v
                i += 1
    except OSError:
        pass
    return out


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _split_cmdline(cmdline: str) -> tuple[str, str]:
    """コマンドラインを (実行ファイル, 引数) に分ける。環境変数（%ProgramFiles% 等）は展開する。"""
    s = os.path.expandvars((cmdline or "").strip())
    if s.startswith('"'):
        exe, _, rest = s[1:].partition('"')
        return exe, rest.strip()
    m = re.match(r"(?i)(.+?\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|msc|scr|cpl|dll))(?=\s|,|$)", s)
    if m:
        return m.group(1), s[m.end():].strip()
    exe, _, rest = s.partition(" ")
    return exe, rest.strip()


def _resolve(exe: str) -> str:
    """フルパスでない実行ファイル名（powershell.exe 等）は System32 / PATH から探す。"""
    if not exe or re.match(r"(?i)^[a-z]:\\|^\\\\", exe):
        return exe
    for d in (Path(SYSROOT) / "System32", Path(SYSROOT)):
        if (d / exe).is_file():
            return str(d / exe)
    from shutil import which
    return which(exe) or exe


def _in_windows_dir(p: str) -> bool:
    return p.lower().startswith(SYSROOT.lower().rstrip("\\") + "\\")


_SUSPICIOUS_DIRS = [os.environ.get("TEMP", ""), os.environ.get("TMP", ""), str(HOME / "Downloads"),
                    os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), ""), r"C:\$Recycle.Bin", "\\AppData\\Local\\Temp\\"]
_SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
                 "cmd.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe"}
_BAD_ARGS = re.compile(r"(?i)(?:^|\s)-e(?:nc(?:odedcommand)?)?\s|frombase64string|downloadstring|downloadfile|invoke-webrequest|"
                       r"\biwr\b|\biex\b|invoke-expression|https?://|javascript:|vbscript:|scrobj\.dll|"
                       r"-urlcache|/transfer\s")


def _judge_launch(exe: str, args: str) -> tuple[str, str]:
    """起動先と引数から危険度を判定する（引数そのものは返さない）。"""
    low = exe.lower()
    if any(d and d.lower() in low for d in _SUSPICIOUS_DIRS):
        return "high", "一時フォルダ・Downloads・公開フォルダ・ごみ箱から起動している。マルウェアの典型パターン"
    if Path(low).name in _SCRIPT_HOSTS and _BAD_ARGS.search(" " + (args or "") + " "):
        return "high", f"{Path(exe).name} に、隠し実行・エンコード済みコマンド・ネットからの取得など、攻撃でよく使われる書き方の引数が付いている"
    if Path(exe).name.startswith("."):
        return "medium", "隠しファイルを起動している"
    if re.match(r"(?i)^[a-z]:\\", exe) and not Path(exe).exists():
        return "low", "起動先のファイルが存在しない（アンインストールの残骸）"
    return "info", ""


# ---------------------------------------------------------------- 収集（PowerShell 1回でまとめて読む）

_COLLECT = r"""
$R=[ordered]@{}
function S($n,[scriptblock]$b){ try { $R[$n] = & $b } catch { $R[$n+'_err'] = $_.Exception.Message } }
S 'bitlocker' { (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive+'\').Self.ExtendedProperty('System.Volume.BitLockerProtection') }
S 'fw' { @(Get-NetFirewallProfile | % { [pscustomobject]@{n=[string]$_.Name; e=[string]$_.Enabled; inb=[string]$_.DefaultInboundAction} }) }
S 'mp' { $m=Get-MpComputerStatus; [pscustomobject]@{svc=[bool]$m.AMServiceEnabled; av=[bool]$m.AntivirusEnabled; rtp=[bool]$m.RealTimeProtectionEnabled; age=[int]$m.AntivirusSignatureAge; tamper=[bool]$m.IsTamperProtected; mode=[string]$m.AMRunningMode} }
S 'mpx' { $p=Get-MpPreference; @(@($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | ? { $_ } | % { [string]$_ }) }
S 'av' { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | % { [pscustomobject]@{n=[string]$_.displayName; s=[int]$_.productState} }) }
S 'fwp' { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | % { [pscustomobject]@{n=[string]$_.displayName; s=[int]$_.productState} }) }
S 'users' { @(Get-LocalUser | % { [pscustomobject]@{n=[string]$_.Name; e=[bool]$_.Enabled; sid=[string]$_.SID.Value} }) }
S 'admins' { @(Get-LocalGroupMember -SID 'S-1-5-32-544' | % { [pscustomobject]@{n=[string]$_.Name; src=[string]$_.PrincipalSource; cls=[string]$_.ObjectClass} }) }
S 'shares' { @(Get-SmbShare | ? { -not $_.Special -and $_.Name -notlike '*$' } | % { [pscustomobject]@{n=[string]$_.Name; p=[string]$_.Path} }) }
S 'listen' { $p=@{}; Get-Process | % { $p[[int]$_.Id]=$_.ProcessName }; @(Get-NetTCPConnection -State Listen | % { [pscustomobject]@{a=[string]$_.LocalAddress; port=[int]$_.LocalPort; proc=[string]$p[[int]$_.OwningProcess]} }) }
S 'tasks' { @(Get-ScheduledTask | ? { $_.TaskPath -notlike '\Microsoft\*' } | % { $t=$_; foreach($a in @($t.Actions)){ if($a.Execute){ [pscustomobject]@{id=[string]($t.TaskPath+$t.TaskName); exe=[string]$a.Execute; args=[string]$a.Arguments; user=[string]$t.Principal.UserId; lvl=[string]$t.Principal.RunLevel; st=[string]$t.State} } } }) }
S 'services' { @(Get-CimInstance Win32_Service | % { [pscustomobject]@{n=[string]$_.Name; dn=[string]$_.DisplayName; path=[string]$_.PathName; user=[string]$_.StartName; mode=[string]$_.StartMode} }) }
S 'startup' { $sh=New-Object -ComObject WScript.Shell; $cs=[Environment]::GetFolderPath('CommonStartup'); @(foreach($d in @([Environment]::GetFolderPath('Startup'),$cs)){ if($d -and (Test-Path -LiteralPath $d)){ Get-ChildItem -LiteralPath $d -File -Force | ? { $_.Name -ne 'desktop.ini' } | % { $t=$_.FullName; $ar=''; if($_.Extension -eq '.lnk'){ $l=$sh.CreateShortcut($_.FullName); $t=$l.TargetPath; $ar=$l.Arguments }; [pscustomobject]@{f=[string]$_.FullName; exe=[string]$t; args=[string]$ar; common=($d -eq $cs)} } } }) }
ConvertTo-Json -InputObject $R -Depth 5 -Compress
"""

# 実行ファイルとフォルダの ACL・署名。本人や一般ユーザーが書き換えられるかを SID で判定する（表示名は言語で変わるため）
_ACL = r"""
$d = $env:SSCAN_DATA | ConvertFrom-Json
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$low=@($me,'S-1-1-0','S-1-5-32-545','S-1-5-11','S-1-5-4','S-1-5-7')
$FW=[int64](0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)
$DR=[int64](0x40 -bor 0x40000 -bor 0x80000 -bor 0x10000000)
$DP=[int64](0x2 -bor 0x40000000)
$RD=[int64](0x1 -bor 0x10000000 -bor 0x80000000)
function W($p,$m){ try { foreach($a in (Get-Acl -LiteralPath $p).Access){ if([string]$a.AccessControlType -ne 'Allow'){continue}; if(([int]$a.PropagationFlags -band 2)){continue}; try{$sid=$a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}catch{continue}; if(($low -contains $sid) -and ($sid -ne $me -or $m -ne $RD) -and (([int64]$a.FileSystemRights) -band $m)){ return $sid } }; return '' } catch { return '?' } }
$out = @(foreach($p in @($d.paths)){
  $o=[ordered]@{p=[string]$p; ex=[bool](Test-Path -LiteralPath $p -PathType Leaf)}
  if($o.ex){
    if($d.mode -eq 'read'){ $o.rd=W $p $RD }
    else {
      $o.wf=W $p $FW; $par=[IO.Path]::GetDirectoryName($p); $o.wd=W $par $DR; $o.wp=W $par $DP
      try { $s=Get-AuthenticodeSignature -LiteralPath $p; $o.sig=[string]$s.Status; $o.signer=''; if($s.SignerCertificate){ $o.signer=[string]$s.SignerCertificate.GetNameInfo('SimpleName',$false) } } catch { $o.sig='?' }
    }
  }
  [pscustomobject]$o })
ConvertTo-Json -InputObject $out -Depth 3 -Compress
"""

_UPDATES = r"""
$s=New-Object -ComObject Microsoft.Update.Session; $q=$s.CreateUpdateSearcher()
$R=[ordered]@{}
try { $R.pending=@($q.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates | % { [pscustomobject]@{t=[string]$_.Title; sev=[string]$_.MsrcSeverity; cat=@($_.Categories | % { [string]$_.CategoryID })} }) } catch { $R.pending_err=$_.Exception.Message }
try { $n=$q.GetTotalHistoryCount(); $R.cu=@($q.QueryHistory(0,[Math]::Min($n,300)) | ? { $_.ResultCode -eq 2 -and $_.Operation -eq 1 -and $_.Title -match 'Cumulative|累積' } | % { $_.Date.ToString('yyyy-MM-dd') } | Sort-Object -Descending | Select-Object -First 1) } catch { $R.cu_err=$_.Exception.Message }
ConvertTo-Json -InputObject $R -Depth 4 -Compress
"""


def scan(cfg: dict) -> Result:
    r = Result()
    if not WINDOWS:
        r.cov(M, "モジュール全体", "skip", "Windows 以外の環境", blocks=WHOLE)
        return r
    c = cfg.get("windows", {})
    data, err = powershell_json(_COLLECT, 240)
    if data is None:
        r.cov(M, "PowerShell", "error", err, blocks=WHOLE)
        data = {}
    _os_support(r)
    _bitlocker(r, data)
    _firewall(r, data)
    _defender(r, data)
    _uac_smartscreen(r)
    _boot_integrity(r)
    _autologon_screenlock(r)
    _remote_access(r)
    _accounts(r, data)
    if c.get("check_updates", True):
        _updates(r)
    _listening(r, data)
    _shares(r, data)
    _secret_files(r)
    _autostart(r, data, c)
    return r


# ---------------------------------------------------------------- OS のサポート期限

# Windows 11 の各版のサポート終了日（Home / Pro）。Enterprise / Education は約1年長い
_W11_EOL = {22000: (date(2023, 10, 10), date(2024, 10, 8)), 22621: (date(2024, 10, 8), date(2025, 10, 14)),
            22631: (date(2025, 11, 11), date(2026, 11, 10)), 26100: (date(2026, 10, 13), date(2027, 10, 12)),
            26200: (date(2027, 10, 12), date(2028, 10, 10))}
_W10_EOL = date(2025, 10, 14)


def _os_support(r: Result):
    cv = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    build = _int(_reg(winreg.HKEY_LOCAL_MACHINE, cv, "CurrentBuildNumber"), 0)
    edition = str(_reg(winreg.HKEY_LOCAL_MACHINE, cv, "EditionID") or "")
    disp = str(_reg(winreg.HKEY_LOCAL_MACHINE, cv, "DisplayVersion") or "")
    name = ("Windows 11" if build >= 22000 else "Windows 10" if build >= 10240 else "Windows") + f" {disp} (build {build}, {edition})"
    if not build:
        r.cov(M, "Windowsのサポート期限", "error", "ビルド番号を読めない", blocks=[("サポート", "")])
        return
    if "LTSC" in edition.upper() or edition.endswith("S") or "Server" in edition:
        r.cov(M, "Windowsのサポート期限", "ok", f"{name}（LTSC / Server は期限が別。手動で確認）")
        return
    ent = edition.startswith(("Enterprise", "Education", "IoTEnterprise"))
    if build < 22000:
        end = _W10_EOL
    else:
        known = [b for b in _W11_EOL if b <= build]
        if not known:
            r.cov(M, "Windowsのサポート期限", "ok", name)
            return
        b = max(known)
        if build > b and b == max(_W11_EOL):  # 表より新しい版（Insider 等）
            r.cov(M, "Windowsのサポート期限", "ok", name)
            return
        end = _W11_EOL[b][1 if ent else 0]
    left = (end - date.today()).days
    if left < 0:
        r.add(M, "high", "サポートが終了したWindowsを使っている（セキュリティ更新が来ない）", PC,
              f"{name} / サポート終了 {end:%Y-%m-%d}",
              "設定 → Windows Update から新しい版へ更新する（Windows 10 は ESU 加入中なら対象外）", key="win-eol")
    elif left <= 90:
        r.add(M, "medium", f"Windowsのサポート終了が近い（あと{left}日）", PC, f"{name} / サポート終了 {end:%Y-%m-%d}",
              "設定 → Windows Update で新しい版（機能更新プログラム）を入れておく", key="win-eol-soon")
    else:
        r.cov(M, "Windowsのサポート期限", "ok", f"{name} / {end:%Y-%m-%d} まで")


# ---------------------------------------------------------------- 暗号化・ファイアウォール・ウイルス対策

def _bitlocker(r: Result, data: dict):
    v = data.get("bitlocker")
    # Shell の BitLockerProtection: 1=オン 2=オフ 3=暗号化中 4=解除中 5=一時停止 6=オン(ロック中) 8=有効化待ち
    if v in (1, 6):
        r.cov(M, "ディスク暗号化", "ok", "BitLocker / デバイスの暗号化 オン")
    elif v == 3:
        r.cov(M, "ディスク暗号化", "ok", "暗号化を実行中")
    elif v in (2, 8):
        r.add(M, "critical", "ディスク暗号化（BitLocker / デバイスの暗号化）がオフ", f"{PC} {os.environ.get('SystemDrive', 'C:')}",
              "有効化待ち（回復キー未保存）" if v == 8 else "システムドライブが暗号化されていない",
              "設定 → プライバシーとセキュリティ → デバイスの暗号化（Pro は BitLocker）をオンにし、回復キーを Microsoft アカウント等に保存する。"
              "盗難・紛失時に全データが読まれるのを防ぐ", key="win-bitlocker")
    elif v in (4, 5):
        r.add(M, "high", "ディスク暗号化が一時停止中・解除中", f"{PC} {os.environ.get('SystemDrive', 'C:')}", f"状態コード {v}",
              "BitLocker の管理画面で「保護の再開」を行う（更新プログラムの適用後に止まったままのことがある）", key="win-bitlocker")
    else:
        r.cov(M, "ディスク暗号化", "error", short_err(data.get("bitlocker_err") or "状態を判定できない（非対応の機種・エディションの可能性）"),
              blocks=[("ディスク暗号化", "")])


def _enabled(state: int) -> bool:
    """SecurityCenter2 の productState: 2バイト目 0x10/0x11 が有効。"""
    return ((state >> 8) & 0xFF) in (0x10, 0x11)


def _firewall(r: Result, data: dict):
    fws = data.get("fw")
    if not isinstance(fws, list) or not fws:
        r.cov(M, "ファイアウォール", "error", short_err(data.get("fw_err") or "取得できない"), blocks=[("ファイアウォール", "")])
        return
    other = [p["n"] for p in data.get("fwp") or [] if _enabled(_int(p.get("s"), 0))]
    for p in fws:
        prof = {"Domain": "ドメイン", "Private": "プライベート", "Public": "パブリック"}.get(p["n"], p["n"])
        if p.get("e") == "False":
            if other:
                r.add(M, "low", f"Windows ファイアウォールがオフ（{prof}）", PC,
                      "別のファイアウォールが有効: " + ", ".join(other), "そのソフトが動いていれば問題なし。アンインストール済みなら Windows ファイアウォールを戻す",
                      key=f"win-fw|{p['n']}")
            else:
                r.add(M, "critical" if p["n"] == "Public" else "high", f"ファイアウォールがオフ（{prof}ネットワーク）", PC, "",
                      "設定 → プライバシーとセキュリティ → Windows セキュリティ → ファイアウォールとネットワーク保護 でオンにする",
                      key=f"win-fw|{p['n']}")
        elif p.get("inb") == "Allow":
            r.add(M, "high", f"ファイアウォールが外からの接続を既定で許可している（{prof}）", PC, "DefaultInboundAction = Allow",
                  "既定の受信動作を「ブロック」に戻す（管理者の PowerShell: Set-NetFirewallProfile -Profile " + p["n"] + " -DefaultInboundAction Block）",
                  key=f"win-fw-in|{p['n']}")
        else:
            r.cov(M, f"ファイアウォール（{prof}）", "ok")


def _defender(r: Result, data: dict):
    avs = data.get("av") or []
    other_av = [a["n"] for a in avs if _enabled(_int(a.get("s"), 0)) and "defender" not in a["n"].lower()]
    mp = data.get("mp")
    if not isinstance(mp, dict):
        if other_av:
            r.cov(M, "ウイルス対策", "ok", "他社製: " + ", ".join(other_av))
        else:
            r.cov(M, "ウイルス対策", "error", short_err(data.get("mp_err") or "Defender の状態を取得できない"), blocks=[("ウイルス対策", ""), ("Defender", "")])
        return
    if not (mp.get("av") and mp.get("rtp")):
        if other_av:
            r.cov(M, "ウイルス対策", "ok", "他社製が有効: " + ", ".join(other_av))
        else:
            r.add(M, "critical", "ウイルス対策（Microsoft Defender のリアルタイム保護）がオフ", PC,
                  f"AntivirusEnabled={mp.get('av')} / RealTimeProtection={mp.get('rtp')}",
                  "Windows セキュリティ → ウイルスと脅威の防止 → 設定の管理 → リアルタイム保護 をオンにする。"
                  "自分でオフにした覚えがなければマルウェアの可能性があるのでフルスキャンも", key="win-av")
        return
    r.cov(M, "ウイルス対策", "ok", f"Microsoft Defender（{mp.get('mode')}）")
    age = _int(mp.get("age"), 0)
    if age > 7:
        r.add(M, "medium", f"Defender の定義ファイルが{age}日更新されていない", PC, "",
              "Windows セキュリティ → ウイルスと脅威の防止 → 保護の更新 を実行。更新が止まり続けるなら Windows Update を確認", key="win-av-age")
    if mp.get("tamper") is False:
        r.add(M, "medium", "改ざん防止（Tamper Protection）がオフ", PC, "マルウェアに Defender を勝手に止められやすい",
              "Windows セキュリティ → ウイルスと脅威の防止 → 設定の管理 → 改ざん防止 をオンにする", key="win-tamper")
    ex = [x for x in data.get("mpx") or [] if not x.startswith("{N/A")]
    if "mpx_err" in data or any(x.startswith("{N/A") for x in data.get("mpx") or []):
        r.cov(M, "Defender の除外設定", "skip", "一覧は管理者権限でしか読めない", blocks=[("除外", "")])
    broad = [x for x in ex if re.fullmatch(r"(?i)[a-z]:\\?|%?(userprofile|temp|tmp|appdata|localappdata)%?\\?|.*\\(downloads|temp|appdata|users)\\?|\.?(exe|dll|ps1|bat|cmd|js|vbs)", x.strip())
             or x.strip().lower().rstrip("\\") in (str(HOME).lower(), os.environ.get("TEMP", "").lower())]
    if broad:
        r.add(M, "high", "Defender に広すぎる除外設定がある（そこに置かれたマルウェアを検査しない）", PC, "\n".join(broad[:10]),
              "Windows セキュリティ → ウイルスと脅威の防止 → 除外 から削除する。覚えがなければ攻撃者が足した可能性がある", key="win-av-excl")
    for x in ex:
        if x not in broad:
            r.add(M, "info", f"Defender の除外設定: {x}", PC, "", "", key=f"win-av-excl|{x.lower()}")


# ---------------------------------------------------------------- UAC・起動の保護

def _uac_smartscreen(r: Result):
    pol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    lua = _reg(winreg.HKEY_LOCAL_MACHINE, pol, "EnableLUA")
    consent = _reg(winreg.HKEY_LOCAL_MACHINE, pol, "ConsentPromptBehaviorAdmin")
    secure = _reg(winreg.HKEY_LOCAL_MACHINE, pol, "PromptOnSecureDesktop")
    if lua == 0:
        r.add(M, "high", "ユーザーアカウント制御（UAC）が無効", PC, "EnableLUA = 0（全てのプログラムが管理者権限で動く）",
              "コントロールパネル → ユーザーアカウント → ユーザーアカウント制御設定の変更 で既定に戻し、再起動する", key="win-uac")
    elif consent == 0:
        r.add(M, "medium", "管理者への昇格が確認なしで行われる（UAC の通知が「通知しない」）", PC, "ConsentPromptBehaviorAdmin = 0",
              "ユーザーアカウント制御設定のつまみを既定（上から2番目）に戻す", key="win-uac-consent")
    elif secure == 0:
        r.add(M, "low", "UAC の確認画面がセキュリティで保護されたデスクトップで出ない", PC, "PromptOnSecureDesktop = 0",
              "ユーザーアカウント制御設定のつまみを既定（上から2番目）に戻す", key="win-uac-secure")
    elif lua is None:
        r.cov(M, "UAC", "error", "レジストリを読めない", blocks=[("UAC", "")])
    else:
        r.cov(M, "UAC", "ok")
    ss = _reg(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    ss2 = _reg(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled")
    if ss == 0 or str(ss2).lower() == "off":
        r.add(M, "medium", "SmartScreen（ダウンロードしたアプリの評判チェック）がオフ", PC, "",
              "Windows セキュリティ → アプリとブラウザーの制御 → 評価ベースの保護 をオンにする", key="win-smartscreen")
    else:
        r.cov(M, "SmartScreen", "ok")


def _boot_integrity(r: Result):
    sb = _reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    if sb == 1:
        r.cov(M, "セキュアブート", "ok")
    elif sb == 0:
        r.add(M, "medium", "セキュアブートがオフ（起動前に動くマルウェアを防げない）", PC, "UEFISecureBootEnabled = 0",
              "UEFI（BIOS）設定で Secure Boot を有効にする。Windows 11 の要件でもある", key="win-secureboot")
    else:
        r.cov(M, "セキュアブート", "skip", "UEFI ではない／状態を読めない", blocks=[("セキュアブート", "")])
    hv = _reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
    if hv == 1:
        r.cov(M, "メモリ整合性", "ok")
    else:
        r.add(M, "low", "コア分離の「メモリ整合性」がオフ", PC, "悪意あるドライバーがカーネルに入り込むのを防ぐ機能",
              "Windows セキュリティ → デバイス セキュリティ → コア分離 → メモリ整合性 をオンにする（古いドライバーが動かなくなることがある）",
              key="win-hvci")


# ---------------------------------------------------------------- 自動ログイン・画面ロック

def _powercfg(sub: str, setting: str) -> tuple[int | None, int | None]:
    """powercfg /q の現在値（AC, DC）。表示は言語で変わるので、最後の2つの16進値を読む。"""
    rc, out, _ = run(["powercfg", "/q", "SCHEME_CURRENT", sub, setting], 20)
    vals = re.findall(r"0x([0-9a-fA-F]{8})\s*$", out, re.M)
    if rc != 0 or len(vals) < 2:
        return None, None
    return int(vals[-2], 16), int(vals[-1], 16)


_CONSOLELOCK = "0e796bdb-100d-47d6-a2d5-f7d2daa51f51"  # スリープ解除時にサインインを求めるか（既定 1=求める）
_POWER = r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"


def _consolelock() -> int:
    """CONSOLELOCK は powercfg /q では隠し設定なので、ポリシー → 現在の電源プランの上書き → 既定(1) の順にレジストリで読む。"""
    pol = _reg(winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Policies\Microsoft\Power\PowerSettings\{_CONSOLELOCK}", "ACSettingIndex")
    if pol is not None:
        return _int(pol, 1)
    scheme = _reg(winreg.HKEY_LOCAL_MACHINE, _POWER, "ActivePowerScheme")
    if scheme:
        v = _reg(winreg.HKEY_LOCAL_MACHINE, rf"{_POWER}\{scheme}\{_CONSOLELOCK}\{_CONSOLELOCK}", "ACSettingIndex")
        if v is not None:
            return _int(v, 1)
    return 1


def _autologon_screenlock(r: Result):
    wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if str(_reg(winreg.HKEY_LOCAL_MACHINE, wl, "AutoAdminLogon") or "0") == "1":
        user = _reg(winreg.HKEY_LOCAL_MACHINE, wl, "DefaultUserName") or "?"
        r.add(M, "high", "自動ログインが有効（電源を入れた人が誰でも使える）", PC, f"ユーザー: {user}",
              "netplwiz を開き「ユーザーがこのコンピューターを使うには、ユーザー名とパスワードの入力が必要」にチェックを入れる", key="win-autologon")
    if _reg(winreg.HKEY_LOCAL_MACHINE, wl, "DefaultPassword"):  # 値そのものは保持しない
        r.add(M, "critical", "ログインパスワードがレジストリに平文で保存されている", PC,
              r"HKLM\...\Winlogon の DefaultPassword（値は表示しない）",
              "自動ログインを解除し、レジストリから DefaultPassword を削除してパスワードを変更する（Sysinternals Autologon なら暗号化保存になる）",
              key="win-autologon-pw")

    # どれか1つで「放置したら鍵がかかる」なら可: 非アクティブ制限のポリシー / パスワード付きスクリーンセーバー / スリープ＋復帰時サインイン
    reasons, ok = [], False
    inact = _int(_reg(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs"), 0)
    if 0 < inact <= 900:
        ok = True
    reasons.append(f"非アクティブ制限 {str(inact) + '秒' if inact else 'なし'}")
    desk = r"Control Panel\Desktop"
    pdesk = r"Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    get = lambda n: _reg(winreg.HKEY_CURRENT_USER, pdesk, n) or _reg(winreg.HKEY_CURRENT_USER, desk, n)  # noqa: E731
    ss_on = str(get("ScreenSaveActive") or "0") == "1" and bool(_reg(winreg.HKEY_CURRENT_USER, desk, "SCRNSAVE.EXE") or get("SCRNSAVE.EXE"))
    ss_secure, ss_to = str(get("ScreenSaverIsSecure") or "0") == "1", _int(get("ScreenSaveTimeOut"), 0)
    if ss_on and ss_secure and 0 < ss_to <= 900:
        ok = True
    reasons.append(f"スクリーンセーバー {'パスワード付き ' if ss_secure else ''}{ss_to if ss_on else 'なし'}{'秒' if ss_on else ''}")
    lock_ac = _consolelock()
    sleep_ac, sleep_dc = _powercfg("SUB_SLEEP", "STANDBYIDLE")
    if sleep_ac is None:
        r.cov(M, "スリープ設定", "error", "powercfg を読めない", blocks=[("ロック", "")])
    else:
        if lock_ac == 0:
            r.add(M, "medium", "スリープから復帰するときにサインインが不要", PC, "CONSOLELOCK = 0",
                  "設定 → アカウント → サインイン オプション →「しばらく操作しなかった場合に、もう一度サインインを求めるタイミング」を「PC のスリープを解除する時間」にする",
                  key="win-wake-lock")
        elif 0 < sleep_ac <= 1800:  # 据え置き・電源につないだノートでも30分以内に鍵がかかるか
            ok = True
        reasons.append(f"スリープ AC {sleep_ac // 60 if sleep_ac else 'なし'}分 / DC {sleep_dc // 60 if sleep_dc else 'なし'}分")
    if ok:
        r.cov(M, "画面ロック", "ok", " / ".join(reasons))
    else:
        r.add(M, "medium", "放置しても自動で画面ロックがかからない", PC, " / ".join(reasons),
              "設定 → システム → 電源 で「次の時間が経過した後にデバイスをスリープ状態にする」を15分程度に。離席時は Win + L でロック。"
              "動的ロック（スマホと連動）も有効", key="win-screenlock")


# ---------------------------------------------------------------- リモート接続・アカウント

def _remote_access(r: Result):
    ts = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    if _reg(winreg.HKEY_LOCAL_MACHINE, ts, "fDenyTSConnections") == 0:
        nla = _reg(winreg.HKEY_LOCAL_MACHINE, ts + r"\WinStations\RDP-Tcp", "UserAuthentication")
        if nla == 0:
            r.add(M, "high", "リモートデスクトップが有効で、接続前の認証（NLA）がオフ", PC, "UserAuthentication = 0",
                  "使わないなら 設定 → システム → リモートデスクトップ をオフ。使うならネットワークレベル認証を必須にする", key="win-rdp-nla")
        else:
            r.add(M, "medium", "リモートデスクトップが有効", PC, "fDenyTSConnections = 0",
                  "使っていなければ 設定 → システム → リモートデスクトップ をオフにする。使うならルーターでポート 3389 を外に開けない", key="win-rdp")
    else:
        r.cov(M, "リモートデスクトップ", "ok", "無効")
    smb1_srv = _reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    smb1_cli = _reg_key_exists(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\mrxsmb10") and \
        _reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start") != 4
    if smb1_srv == 1 or smb1_cli:
        r.add(M, "high", "古いファイル共有プロトコル SMBv1 が有効（WannaCry 等が使った経路）", PC,
              ("サーバー側 " if smb1_srv == 1 else "") + ("クライアント側" if smb1_cli else ""),
              "「Windows の機能の有効化または無効化」で「SMB 1.0/CIFS ファイル共有のサポート」のチェックを外す", key="win-smb1")
    else:
        r.cov(M, "SMBv1", "ok", "無効")


def _accounts(r: Result, data: dict):
    users = data.get("users")
    if not isinstance(users, list):
        r.cov(M, "ローカルアカウント", "error", short_err(data.get("users_err") or "取得できない"), blocks=[("アカウント", "")])
    else:
        for u in users:
            if u["sid"].endswith("-501") and u.get("e"):
                r.add(M, "high", "Guest アカウントが有効", PC, f"ユーザー: {u['n']}",
                      "管理者の PowerShell で Disable-LocalUser -Name '" + u["n"] + "'", key="win-guest")
            elif u["sid"].endswith("-500") and u.get("e"):
                r.add(M, "medium", "組み込みの Administrator アカウントが有効", PC, f"ユーザー: {u['n']}",
                      "普段使いのアカウントとは別の、総当たりの標的になりやすいアカウント。不要なら無効化する", key="win-builtin-admin")
        r.cov(M, "ローカルアカウント", "ok", f"{len(users)}件")
    admins = data.get("admins")
    if not isinstance(admins, list):
        r.cov(M, "管理者グループ", "skip", short_err(data.get("admins_err") or "取得できない"), blocks=[("管理者グループ", "")])
        return
    for a in admins:
        r.add(M, "info", f"管理者グループのメンバー: {a['n']}", PC, f"{a.get('cls')} / {a.get('src')}",
              "心当たりのないアカウントがあれば外す。普段使いは標準ユーザー、管理作業だけ管理者に分けるとより安全",
              key=f"win-admin|{a['n'].lower()}")


# ---------------------------------------------------------------- Windows Update

_SEC_CATS = {"0fa1201d-4330-4fa8-8ae9-b877473b6441", "e6cf1350-c01b-414d-a61f-263d14d133b4"}  # セキュリティ / 重要
_DEF_CAT = "e0789628-ce08-4437-be74-2495b842f43b"  # 定義ファイル（自動で入るので数えない）


def _updates(r: Result):
    data, err = powershell_json(_UPDATES, 420)
    if not isinstance(data, dict):
        r.cov(M, "Windows Update", "error", err, blocks=[("アップデート", ""), ("累積更新", "")])
        return
    pend = data.get("pending")
    if pend is None:
        r.cov(M, "未適用の更新", "error", short_err(data.get("pending_err", "")), blocks=[("アップデート", "")])
    else:
        pend = [u for u in pend if _DEF_CAT not in [x.lower() for x in u.get("cat") or []]]
        sec = [u for u in pend if u.get("sev") in ("Critical", "Important") or _SEC_CATS & {x.lower() for x in u.get("cat") or []}]
        if pend:
            r.add(M, "high" if sec else "medium", "未適用の Windows Update がある", PC,
                  "\n".join((f"[{u['sev']}] " if u.get("sev") else "") + u["t"] for u in pend[:15]),
                  "設定 → Windows Update →「更新プログラムのチェック」から適用する（再起動が必要なものは作業の区切りで）", key="win-updates")
        else:
            r.cov(M, "未適用の更新", "ok")
    last = data.get("cu")
    last = last[0] if isinstance(last, list) and last else last
    if isinstance(last, str) and last:
        days = (datetime.now() - datetime.strptime(last, "%Y-%m-%d")).days
        if days > 60:
            r.add(M, "medium", f"最後に月例の累積更新が入ってから{days}日たっている", PC, f"最終適用 {last}",
                  "Windows Update が止まっていないか（一時停止・容量不足・エラー）を確認する", key="win-cu-age")
        else:
            r.cov(M, "累積更新の適用", "ok", f"最終 {last}")
    elif "cu_err" in data:
        r.cov(M, "累積更新の適用", "error", short_err(data["cu_err"]), blocks=[("累積更新", "")])


# ---------------------------------------------------------------- 待ち受けポート・共有

_RISKY_PORTS = {3389: "リモートデスクトップ", 5900: "VNC", 22: "SSH", 5985: "WinRM", 5986: "WinRM(HTTPS)", 23: "Telnet", 21: "FTP",
                3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
_WIN_DEFAULT = {135: "RPC", 139: "NetBIOS", 445: "ファイル共有(SMB)", 5357: "ネットワーク探索(WSD)", 5040: "CDP", 7680: "配信の最適化"}
_RPC_PROCS = {"lsass", "wininit", "services", "spoolsv", "svchost", "system"}


def _listening(r: Result, data: dict):
    items = data.get("listen")
    if not isinstance(items, list):
        r.cov(M, "待ち受けポート", "error", short_err(data.get("listen_err") or "取得できない"), blocks=[("ポート", "")])
        return
    exposed: dict[int, set[str]] = {}
    for it in items:
        if it["a"] in ("127.0.0.1", "::1") or it["a"].startswith("127."):
            continue
        exposed.setdefault(it["port"], set()).add(it.get("proc") or "?")
    rpc = sorted(p for p, procs in exposed.items() if p >= 49152 and {x.lower() for x in procs} <= _RPC_PROCS)
    if rpc:
        r.add(M, "info", "Windows 標準の動的ポート（RPC 等）", PC, ", ".join(map(str, rpc)), "", key="win-rpc-ports")
    for port in sorted(exposed):
        if port in rpc:
            continue
        procs = ", ".join(sorted(exposed[port]))
        if port in _RISKY_PORTS:
            r.add(M, "medium", f"外部から接続を受け付けるポート {port}（{_RISKY_PORTS[port]}）", f"tcp/{port}", "プロセス: " + procs,
                  "使っていなければサービスを止める。使うならファイアウォールで接続元を絞る。公衆Wi-Fiでは特に注意", key=f"win-port|{port}")
        elif port in _WIN_DEFAULT:
            r.add(M, "low", f"外部から接続を受け付けるポート {port}（{_WIN_DEFAULT[port]}・Windows 標準）", f"tcp/{port}", "プロセス: " + procs,
                  "ネットワークの種類が「パブリック」ならファイアウォールで遮断される。カフェ等では「パブリック」にしておく", key=f"win-port|{port}")
        else:
            r.add(M, "low", f"外部から接続を受け付けるポート {port}", f"tcp/{port}", "プロセス: " + procs,
                  "開発サーバーなら 127.0.0.1 にバインドする。使っていない常駐なら止める", key=f"win-port|{port}")


def _shares(r: Result, data: dict):
    shares = data.get("shares")
    if not isinstance(shares, list):
        r.cov(M, "共有フォルダ", "skip", "一覧の取得に管理者権限が必要なことがある（" + short_err(data.get("shares_err") or "取得できない")[:80] + "）",
              blocks=[("共有フォルダ", "")])
        return
    for s in shares:
        r.add(M, "low", f"共有フォルダ: {s['n']}", s.get("p") or "?", "ネットワーク上の他のPCから見える可能性がある",
              "使っていなければ共有を止める（フォルダのプロパティ → 共有）。使うなら共有相手を Everyone にしない", key=f"win-share|{s['n'].lower()}")
    r.cov(M, "共有フォルダ", "ok", f"{len(shares)}件")


# ---------------------------------------------------------------- 秘密情報を含むファイル

SECRET_NAME = re.compile(r"^\s*(?:export\s+|\$env:)?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z0-9_]*)\s*=", re.M | re.I)


def _documents() -> Path:
    """「ドキュメント」の実際の場所（OneDrive へ移動されていることがある）。"""
    v = _reg(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Personal")
    return Path(os.path.expandvars(v)) if v else HOME / "Documents"


def _secret_files(r: Result):
    ssh = HOME / ".ssh"
    keys = [f for f in ssh.iterdir() if f.is_file() and f.suffix != ".pub" and
            f.name not in ("known_hosts", "known_hosts.old", "config", "authorized_keys")] if ssh.is_dir() else []
    docs = _documents()
    profiles = [docs / "PowerShell/Microsoft.PowerShell_profile.ps1", docs / "WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
                docs / "PowerShell/profile.ps1", docs / "WindowsPowerShell/profile.ps1"]
    files = [HOME / n for n in (".git-credentials", ".netrc", "_netrc", ".npmrc", ".pypirc", ".bashrc", ".bash_profile")]
    files += [HOME / ".aws/credentials", HOME / ".docker/config.json", *[p for p in profiles if p.is_file()]]
    secretish = []
    for f in files:
        if not f.is_file():
            continue
        n = len(SECRET_NAME.findall(f.read_text(encoding="utf-8", errors="ignore")))
        if f.name in (".git-credentials", ".netrc", "_netrc", ".npmrc", ".pypirc", "credentials", "config.json"):
            n = max(n, 1)
        if n:
            secretish.append(f)
    targets = keys + secretish
    if targets:
        acl, err = powershell_json(_ACL, 120, {"paths": [str(p) for p in targets], "mode": "read"})
        if acl is None:
            r.cov(M, "秘密ファイルの権限", "error", err, blocks=[("他ユーザーから読める", "")])
        else:
            for o in acl:
                if o.get("rd") and o["rd"] != "?":
                    is_key = Path(o["p"]).parent == ssh
                    r.add(M, "high" if is_key else "medium",
                          "SSH秘密鍵が他ユーザーから読める権限" if is_key else "秘密情報を含むファイルが他ユーザーから読める権限",
                          o["p"], f"読み取りを許可している相手: {_sid_name(o['rd'])}（値は表示しない）",
                          f'icacls "{o["p"]}" /inheritance:r /grant:r "%USERNAME%:F" で本人だけにする', key=f"win-acl|{o['p'].lower()}")
            r.cov(M, "秘密ファイルの権限", "ok", f"{len(acl)}件を確認")
    if (HOME / ".git-credentials").is_file():
        r.add(M, "medium", "Git の認証情報が平文ファイルに保存されている", str(HOME / ".git-credentials"),
              "credential.helper=store のとき、トークンがそのまま書かれる（値は表示しない）",
              "git config --global credential.helper manager（Git Credential Manager）に切り替え、中のトークンを発行元で再発行してからファイルを削除する",
              key="win-git-credentials")
    if (HOME / ".aws/credentials").is_file():
        r.add(M, "medium", "AWSの長期アクセスキーファイルが存在する", str(HOME / ".aws/credentials"), "SSOを使っている環境では通常不要",
              "中身のキーが使われていないかIAMで確認し、不要なら無効化→ファイル削除。SSO(aws sso login)へ寄せる", key="win-aws-credentials")
    for p in profiles:
        if p in secretish:
            r.add(M, "low", "PowerShell のプロファイルに秘密っぽい変数が書かれている", str(p), "値は表示しない",
                  "プロファイルは共有・同期されやすい。ユーザー環境変数（設定 → システム → バージョン情報 → システムの詳細設定 → 環境変数）か資格情報マネージャーへ移す",
                  key=f"win-psprofile|{str(p).lower()}")
    ak = [p for p in (ssh / "authorized_keys", Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ssh/administrators_authorized_keys") if p.is_file()]
    for p in ak:
        try:
            n = sum(1 for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#"))
        except OSError:
            continue
        r.add(M, "info", "このPCへSSHログインできる公開鍵が登録されている", str(p), f"{n}件",
              "心当たりのない鍵があれば削除する（OpenSSH サーバーを入れていなければ影響なし）", key=f"win-authkeys|{str(p).lower()}")


_SID_NAMES = {"S-1-1-0": "Everyone", "S-1-5-32-545": "Users（全ユーザー）", "S-1-5-11": "Authenticated Users", "S-1-5-4": "INTERACTIVE",
              "S-1-5-7": "ANONYMOUS"}


def _sid_name(sid: str) -> str:
    return _SID_NAMES.get(sid, "本人" if sid.startswith("S-1-5-21-") else sid)


# ---------------------------------------------------------------- 自動起動（Run キー・スタートアップ・タスク・サービス）

_PRIV_USERS = {"system", "nt authority\\system", "s-1-5-18", "localsystem", "", "nt authority\\localservice", "nt authority\\networkservice",
               "local service", "network service"}


def _autostart(r: Result, data: dict, c: dict):
    """常駐の棚卸し。新しく増えたものはレポートで NEW 表示になる。
    特権（SYSTEM / 管理者）で動くものは、起動するファイルを一般ユーザーが書き換えられないか・署名があるかも見る。"""
    items = []  # (key, title, target, exe, args, privileged)
    run_keys = [(winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", 0),
                (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0),
                (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", winreg.KEY_WOW64_64KEY),
                (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", winreg.KEY_WOW64_64KEY),
                (winreg.HKEY_LOCAL_MACHINE, "HKLM(32bit)", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", winreg.KEY_WOW64_32KEY),
                (winreg.HKEY_LOCAL_MACHINE, "HKLM(32bit)", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", winreg.KEY_WOW64_32KEY)]
    for hive, hname, path, view in run_keys:
        for name, cmd in _reg_values(hive, path, view).items():
            exe, args = _split_cmdline(cmd)
            where = f"{hname}\\{path.split(chr(92))[-1]}\\{name}"
            items.append((f"run|{where.lower()}", f"自動起動（レジストリ）: {name}", where, _resolve(exe), args, False))
    for s in data.get("startup") or []:
        exe, args = (s.get("exe") or s["f"]), s.get("args") or ""
        items.append((f"startup|{s['f'].lower()}", f"自動起動（スタートアップ）: {Path(s['f']).name}", s["f"], _resolve(os.path.expandvars(exe)), args, False))
    if "startup_err" in data:
        r.cov(M, "スタートアップフォルダ", "error", short_err(data["startup_err"]), blocks=[("スタートアップ", "")])
    tasks = data.get("tasks")
    if isinstance(tasks, list):
        for t in tasks:
            exe, args = _split_cmdline(t["exe"])
            if t.get("args"):
                args = (args + " " + t["args"]).strip()
            priv = (t.get("user") or "").lower() in _PRIV_USERS or t.get("lvl") == "Highest"
            items.append((f"task|{t['id'].lower()}", f"タスクスケジューラ: {t['id']}", t["id"] + (f"（{t.get('user') or 'SYSTEM'}）" if priv else ""),
                          _resolve(exe), args, priv))
    else:
        r.cov(M, "タスクスケジューラ", "error", short_err(data.get("tasks_err") or "取得できない"), blocks=[("タスクスケジューラ", "")])
    svcs = data.get("services")
    if isinstance(svcs, list):
        for s in svcs:
            if not s.get("path"):
                continue
            exe, args = _split_cmdline(s["path"])
            exe = _resolve(exe)
            if _in_windows_dir(exe):  # Windows 本体のサービス（svchost 等）は数が多いので棚卸しから外す
                continue
            priv = (s.get("user") or "").lower() in _PRIV_USERS
            items.append((f"svc|{s['n'].lower()}", f"サービス: {s.get('dn') or s['n']}", f"{s['n']}（{s.get('user') or 'LocalSystem'} / {s.get('mode')}）",
                          exe, args, priv, s["path"]))
    else:
        r.cov(M, "サービス", "error", short_err(data.get("services_err") or "取得できない"), blocks=[("サービス", "")])

    # 特権で動くもの＋怪しい場所から起動するもの（署名を見て正規ソフトか判断するため）の実行ファイル
    priv_paths = sorted({it[3] for it in items if re.match(r"(?i)^[a-z]:\\", it[3]) and not _in_windows_dir(it[3])
                         and (it[5] or _judge_launch(it[3], "")[0] == "high")})
    acl = {}
    if priv_paths and c.get("check_acl", True):
        res, err = powershell_json(_ACL, 600, {"paths": priv_paths})
        if res is None:
            r.cov(M, "特権で動く常駐の権限・署名", "error", err, blocks=[("書き換え", ""), ("署名", "")])
        else:
            acl = {o["p"]: o for o in res}
            r.cov(M, "特権で動く常駐の権限・署名", "ok", f"{len(acl)}ファイル")

    for it in items:
        key, title, target, exe, args, priv = it[:6]
        sev, note = _judge_launch(exe, args)
        a = acl.get(exe) or {}
        if sev == "high" and note.startswith("一時フォルダ") and a.get("sig") == "Valid" and a.get("signer"):
            sev, note = "medium", f"一時フォルダ等から起動している（署名は正規: {a['signer']}。展開して動く正規ソフトもあるが、提供元に心当たりがあるか確認）"
        if sev == "info" and priv and a:
            if a.get("wf") or a.get("wd"):
                who = _sid_name(a.get("wf") or a.get("wd"))
                sev, note = "high", f"SYSTEM/管理者権限で動くのに、起動するファイルを {who} が書き換えられる（すり替えで乗っ取られる）"
            elif a.get("wp"):
                sev, note = "medium", f"SYSTEM/管理者権限で動くのに、置き場のフォルダに {_sid_name(a['wp'])} がファイルを追加できる（DLLの植え込みに使われうる）"
            elif a.get("sig") and a["sig"] != "Valid" and a["sig"] != "?":
                sev, note = "medium", f"SYSTEM/管理者権限で動くプログラムに正式な署名がない（{a['sig']}）"
        if sev == "info" and len(it) > 6 and _unquoted_service_path(it[6]):
            sev, note = "low", "サービスのパスが引用符で囲まれておらず空白を含む（途中のフォルダに書き込めると別のプログラムを起動される）"
        signer = f" / 署名: {a['signer']}" if a.get("signer") else ""
        r.add(M, sev, title, target, (note + "\n" if note else "") + f"起動: {exe}{signer}（引数は秘密が入りうるので記録しない）",
              "心当たりがなければ、タスクマネージャーの「スタートアップ アプリ」・タスクスケジューラ・services.msc で無効にしてから、"
              "提供元を確認する。ファイルは削除せず隔離する" if sev != "info" else "", key=key)


def _unquoted_service_path(path: str) -> bool:
    p = path.strip()
    if p.startswith('"'):
        return False
    m = re.match(r"(?i)(.+?\.exe)", p)
    return bool(m and " " in m.group(1) and not _in_windows_dir(m.group(1)))
