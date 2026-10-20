# 毎週のスキャンをタスクスケジューラに登録する（既定: 月曜 8:00、ログオン中のみ・管理者権限なし）。
#   powershell -ExecutionPolicy Bypass -File scripts\install-schedule.ps1                     # 月曜 8:00
#   powershell -ExecutionPolicy Bypass -File scripts\install-schedule.ps1 -Day Sunday -At 21:00
#   powershell -ExecutionPolicy Bypass -File scripts\install-schedule.ps1 -Remove
param(
  [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
  [string]$Day = 'Monday',
  [ValidatePattern('^\d{1,2}:\d{2}$')]
  [string]$At = '8:00',
  [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$TaskName = 'security-scan'
$TaskPath = '\security-scan\'

if ($Remove) {
  Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host '解除しました'
  exit 0
}

$Root = Split-Path -Parent $PSScriptRoot
$Reports = Join-Path $Root 'reports'
New-Item -ItemType Directory -Force -Path $Reports | Out-Null
$Log = Join-Path $Reports 'schedule.log'

# 窓を出さない pythonw.exe を使う。py ランチャーしか無ければそこから実体の場所を調べる
$py = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $py) {
  $launcher = (Get-Command py.exe -ErrorAction SilentlyContinue).Source
  if ($launcher) {
    $exe = & $launcher -3 -c "import sys; print(sys.executable)"
    $cand = Join-Path (Split-Path -Parent $exe) 'pythonw.exe'
    if (Test-Path -LiteralPath $cand) { $py = $cand }
  }
}
if (-not $py -or $py -like '*\WindowsApps\*') { throw 'pythonw.exe が見つかりません（python.org の Python 3.11 以上を入れてください。Microsoft Store 版のエイリアスは不可）' }

$scan = Join-Path $Root 'scan.py'
# 引数はそれぞれ " で囲む（パスに空白があっても壊れない）。パスに " は入らない
$arg = '"{0}" --notify --log "{1}"' -f $scan, $Log
$action = New-ScheduledTaskAction -Execute $py -Argument $arg -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Day -At $At
# 電源につながっていなくても実行し、時刻に PC が寝ていたら起きたあとで実行する。最長2時間で打ち切り
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew -Priority 7
# ログオン中の本人として通常権限で動かす（gh / gcloud 等のログイン情報をそのまま使うため。パスワードは保存しない）
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Settings $settings `
  -Principal $principal -Description '読み取り専用のセキュリティスキャン（claude-security-scan）' -Force | Out-Null
Write-Host "登録しました: 毎週 $Day $At（タスクスケジューラ $TaskPath$TaskName）"
Write-Host "今すぐ1回: Start-ScheduledTask -TaskPath '$TaskPath' -TaskName '$TaskName'"
Write-Host "ログ: $Log"
