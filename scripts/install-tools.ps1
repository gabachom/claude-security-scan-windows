# gitleaks と osv-scanner を公式 GitHub リリースから bin\ に取得し、SHA256 を検証する。
# winget / scoop 等で既に入っていれば不要（PATH 上のものを使う）。
#   powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GitleaksVersion = '8.30.1'
$OsvVersion = '2.7.0'

$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root 'bin'
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("sscan-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null

switch ($env:PROCESSOR_ARCHITECTURE) {
  'ARM64' { $gl = 'arm64'; $osv = 'arm64' }
  'AMD64' { $gl = 'x64'; $osv = 'amd64' }
  default { throw "未対応のCPU: $env:PROCESSOR_ARCHITECTURE" }
}

function Get-File($url, $out) { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out }

function Test-Sum($file, $sums) {
  $name = Split-Path -Leaf $file
  $line = Get-Content -LiteralPath $sums | Where-Object { ($_ -split '\s+')[1] -in @($name, "*$name") } | Select-Object -First 1
  if (-not $line) { throw "チェックサムが見つからない: $name" }
  $expected = ($line -split '\s+')[0].ToLower()
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLower()
  if ($expected -ne $actual) { throw "チェックサム不一致: $name" }
  Write-Host "  OK $name の SHA256 を確認"
}

try {
  Write-Host "gitleaks v$GitleaksVersion (windows/$gl)"
  $zip = "gitleaks_${GitleaksVersion}_windows_${gl}.zip"
  $base = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion"
  Get-File "$base/$zip" (Join-Path $Tmp $zip)
  Get-File "$base/gitleaks_${GitleaksVersion}_checksums.txt" (Join-Path $Tmp 'gl_sums.txt')
  Test-Sum (Join-Path $Tmp $zip) (Join-Path $Tmp 'gl_sums.txt')
  Expand-Archive -LiteralPath (Join-Path $Tmp $zip) -DestinationPath (Join-Path $Tmp 'gl') -Force
  Copy-Item -LiteralPath (Join-Path $Tmp 'gl\gitleaks.exe') -Destination (Join-Path $Bin 'gitleaks.exe') -Force

  Write-Host "osv-scanner v$OsvVersion (windows/$osv)"
  $exe = "osv-scanner_windows_${osv}.exe"
  $base = "https://github.com/google/osv-scanner/releases/download/v$OsvVersion"
  Get-File "$base/$exe" (Join-Path $Tmp $exe)
  Get-File "$base/osv-scanner_SHA256SUMS" (Join-Path $Tmp 'osv_sums.txt')
  Test-Sum (Join-Path $Tmp $exe) (Join-Path $Tmp 'osv_sums.txt')
  Copy-Item -LiteralPath (Join-Path $Tmp $exe) -Destination (Join-Path $Bin 'osv-scanner.exe') -Force

  # インターネットから来た印（Zone.Identifier）を外して SmartScreen の確認を出さない（SHA256 は上で検証済み）
  Get-ChildItem -LiteralPath $Bin -Filter *.exe | Unblock-File
  & (Join-Path $Bin 'gitleaks.exe') version
  & (Join-Path $Bin 'osv-scanner.exe') --version | Select-Object -First 1
  Write-Host "完了: $Bin"
} finally {
  Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
