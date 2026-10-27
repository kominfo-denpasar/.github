<#
.SYNOPSIS
  php2shell-check.ps1 - Memeriksa PHP di server Windows terhadap PHP2Shell
  (CVE-2026-109618 / CVE-2026-109619).

.DESCRIPTION
  Hanya membaca. Skrip ini:
   1. mencari php.exe dan php-cgi.exe di disk lokal (dan yang terdaftar di IIS FastCGI),
   2. memeriksa versinya terhadap rilis yang diperbaiki
      (8.2.35, 8.3.36, 8.4.27, 8.5.12; build Windows resmi dari windows.php.net),
   3. memeriksa apakah proses php-cgi / php / httpd mulai SEBELUM rilis perbaikan
      (artinya masih memakai binary lama dan perlu restart),
   4. menampilkan service web yang terpasang dan pengaturan php.ini terkait.

  Catatan:
   - Build Windows resmi yang diperbaiki hanya ada untuk 8.2 ke atas. PHP 5.6, 7.4, 8.0 dan 8.1
     ditandai GAGAL karena tidak ada build Windows resmi yang sudah diperbaiki.
   - Skrip TIDAK menguji eksploitasi dan tidak membuktikan tidak ada celah lain.
   - Disusun untuk Windows PowerShell 5.1 ke atas. Belum diuji di semua kombinasi (IIS, Apache,
     XAMPP, Laragon); jalankan dulu di server non-produksi.

.PARAMETER Path
  Folder yang dipindai (default: semua disk lokal). Contoh: -Path C:\xampp,D:\php

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1
  powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1 -Path C:\php,C:\xampp
#>
[CmdletBinding()]
param(
  [string[]]$Path
)

$script:OkCount = 0
$script:WarnCount = 0
$script:FailCount = 0

function Write-Ok($m)  { $script:OkCount++;   Write-Host ("  [OK]    " + $m) -ForegroundColor Green }
function Write-Bad($m) { $script:FailCount++; Write-Host ("  [GAGAL] " + $m) -ForegroundColor Red }
function Write-Chk($m) { $script:WarnCount++; Write-Host ("  [CEK]   " + $m) -ForegroundColor Yellow }
function Write-Inf($m) { Write-Host ("  [INFO]  " + $m) }

# Versi upstream pertama yang diperbaiki per cabang
$Fixed = @{ '8.2' = '8.2.35'; '8.3' = '8.3.36'; '8.4' = '8.4.27'; '8.5' = '8.5.12' }

# Build Windows yang diperbaiki muncul 21 Okt 2026 sekitar 13:47 UTC. Proses yang mulai
# sebelum waktu ini pasti belum memakai build baru.
$FixRelease = New-Object DateTime 2026, 10, 21, 14, 0, 0, ([DateTimeKind]::Utc)

function Test-Version([string]$label, [string]$ver) {
  $parts = $ver -split '\.'
  $br = $parts[0] + '.' + $parts[1]
  if ($Fixed.ContainsKey($br)) {
    if ([version]$ver -ge [version]$Fixed[$br]) {
      Write-Ok "$label ($ver): versi >= $($Fixed[$br])"
    } else {
      Write-Bad "$label ($ver): di bawah $($Fixed[$br]). Ganti dengan build terbaru cabang $br dari windows.php.net."
    }
  } elseif ([version]($br + '.0') -gt [version]'8.5.0') {
    Write-Chk "$label ($ver): cabang lebih baru dari tabel skrip; verifikasi manual ke php.net."
  } else {
    Write-Bad "$label ($ver): cabang $br tidak punya build Windows resmi yang sudah diperbaiki. Pindah ke 8.3 atau 8.4, atau batasi akses dan terapkan mitigasi (SOP bagian 9)."
  }
}

function Get-PhpInfo([string]$exe) {
  try {
    $line = (& $exe -v 2>&1 | Select-Object -First 1 | Out-String).Trim()
  } catch {
    return $null
  }
  $ver = $null
  if ($line -match 'PHP\s+(\d+\.\d+\.\d+)') { $ver = $Matches[1] }
  if (-not $ver) { return $null }
  $ts = '?'
  if ($line -match '\((NTS|ZTS)') { $ts = $Matches[1] }
  $sapi = '?'
  if ($line -match '\((cli|cgi-fcgi|cgi)\)') { $sapi = $Matches[1] }
  return [pscustomobject]@{ Path = $exe; Version = $ver; Sapi = $sapi; Ts = $ts }
}

function Find-PhpBinaries {
  $roots = @()
  if ($Path) {
    $roots = $Path
  } else {
    $roots = [System.IO.DriveInfo]::GetDrives() |
      Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
      ForEach-Object { $_.RootDirectory.FullName }
  }
  foreach ($r in $roots) {
    Write-Inf "memindai $r (bisa memakan beberapa menit)..."
    Get-ChildItem -Path $r -Recurse -Force -File -Include 'php.exe', 'php-cgi.exe' -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch '\\\$Recycle\.Bin\\|\\Windows\\WinSxS\\' } |
      ForEach-Object { $_.FullName }
  }
}

function Get-IisFastCgiPhp {
  $cfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
  if (-not (Test-Path $cfg)) { return }
  try {
    $x = [xml](Get-Content $cfg -Raw)
    $apps = $x.configuration.'system.webServer'.fastCgi.application
    foreach ($a in $apps) {
      if ($a -and $a.fullPath) { $a.fullPath }
    }
  } catch { }
}

# ---------------- Main ----------------

Write-Host ("=== PHP2Shell (CVE-2026-109618 / CVE-2026-109619) - " + $env:COMPUTERNAME + " - " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + " ===")

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Chk "Bukan Administrator: waktu start dan modul proses mungkin tidak terbaca. Jalankan PowerShell sebagai Administrator."
}

Write-Host ""
Write-Host "== Pencarian PHP di server"
$iisPaths = @(Get-IisFastCgiPhp)
if ($iisPaths.Count -gt 0) {
  foreach ($p in $iisPaths) { Write-Inf "IIS FastCGI terdaftar memakai: $p" }
} elseif (Test-Path (Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config')) {
  Write-Inf "IIS terpasang, tetapi tidak ada aplikasi FastCGI terdaftar"
}

$found = @(Find-PhpBinaries)
$candidates = @($found) + @($iisPaths) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

if (@($candidates).Count -eq 0) {
  Write-Inf "tidak ditemukan php.exe atau php-cgi.exe di lokasi yang dipindai"
}

Write-Host ""
Write-Host "== Versi PHP yang ditemukan"
foreach ($exe in $candidates) {
  $info = Get-PhpInfo $exe
  if ($null -eq $info) {
    Write-Chk "$exe : versi tidak terbaca (berkas bukan PHP, atau tidak bisa dijalankan)"
    continue
  }
  Test-Version ("$exe [$($info.Sapi) $($info.Ts)]") $info.Version
}

Write-Host ""
Write-Host "== Pengaturan php.ini terkait (dari php.exe CLI; FastCGI/Apache bisa memakai php.ini lain)"
foreach ($exe in $candidates) {
  if ((Split-Path $exe -Leaf) -ne 'php.exe') { continue }
  try {
    $ini = (& $exe --ini 2>&1 | Select-String 'Loaded Configuration File' | Select-Object -First 1)
    $vals = (& $exe -r "echo ini_get('session.upload_progress.enabled') . ' | memory_limit=' . ini_get('memory_limit') . ' | post_max_size=' . ini_get('post_max_size');" 2>&1 | Out-String).Trim()
    Write-Inf ("$exe : " + ($ini.ToString().Trim()) + " ; upload_progress.enabled=" + $vals)
  } catch { }
}

Write-Host ""
Write-Host "== Proses yang berjalan (sudah memakai build baru?)"
$procNames = 'php-cgi', 'php', 'httpd'
$anyProc = $false
foreach ($n in $procNames) {
  foreach ($p in @(Get-Process -Name $n -ErrorAction SilentlyContinue)) {
    $anyProc = $true
    $start = $null
    try { $start = $p.StartTime } catch { }
    if ($null -eq $start) {
      Write-Chk "$n pid $($p.Id): waktu start tidak terbaca (jalankan sebagai Administrator)"
      continue
    }
    $startUtc = $start.ToUniversalTime()
    $pathTxt = ''
    try { $pathTxt = $p.Path } catch { }
    if ($startUtc -lt $FixRelease) {
      Write-Bad "$n pid $($p.Id): start $($start.ToString('yyyy-MM-dd HH:mm:ss')) lebih lama dari rilis perbaikan (21 Okt 2026). RESTART service. ($pathTxt)"
    } else {
      Write-Ok "$n pid $($p.Id): start $($start.ToString('yyyy-MM-dd HH:mm:ss')) ($pathTxt)"
    }
    # modul PHP yang dimuat oleh Apache (mod_php)
    if ($n -eq 'httpd') {
      try {
        foreach ($m in $p.Modules) {
          if ($m.ModuleName -match '^php') {
            $pv = $m.FileVersionInfo.ProductVersion
            if ($pv -match '^\d+\.\d+\.\d+') {
              Test-Version ("mod_php (httpd pid $($p.Id)) " + $m.FileName) $Matches[0]
            } else {
              Write-Chk ("mod_php (httpd pid $($p.Id)) " + $m.FileName + " : versi tidak terbaca")
            }
          }
        }
      } catch { }
    }
  }
}
if (-not $anyProc) { Write-Inf "tidak ada proses php-cgi, php atau httpd yang sedang berjalan" }

Write-Host ""
Write-Host "== Service web (info)"
try {
  Get-CimInstance Win32_Service |
    Where-Object { $_.Name -match '^(W3SVC|Apache|httpd|nginx)' -or $_.DisplayName -match 'Apache|nginx' } |
    ForEach-Object { Write-Inf ("{0} : {1} ; {2}" -f $_.Name, $_.State, $_.PathName) }
} catch { }

Write-Host ""
Write-Host ("=== Ringkasan: OK=" + $script:OkCount + "  CEK=" + $script:WarnCount + "  GAGAL=" + $script:FailCount + " ===")
if ($script:FailCount -gt 0) { exit 1 }
exit 0
