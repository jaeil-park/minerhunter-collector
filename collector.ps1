#requires -Version 5.1
<#
  MinerHunter Collector v1.1.0  —  읽기 전용 수집기

  이 스크립트는 아무것도 판정하지 않고, 아무것도 바꾸지 않는다.
  프로세스·서비스·예약작업·자동실행·Defender 설정·파일 목록·DNS 캐시를 있는 그대로
  JSON 한 파일로 저장할 뿐이다. 무엇이 위험한지는 서버의 판정 엔진이 결정한다.

  PC 에 쓰는 것은 -OutFile 하나뿐이다 (기본: %TEMP%\minerhunter_collect_<시각>.json).
  관리자 권한으로 실행해야 다른 사용자 프로세스의 명령줄·Defender 예외 목록이 보인다.

  -Upload : 웹(infralog 도구)에서 받은 연결 코드로 결과를 서버에 올리고 리포트를 연다.
            -OutFile 을 주지 않았으면 올린 뒤 임시 파일을 지운다 (서버도 원본을 저장하지 않는다).
#>
param([string]$OutFile, [switch]$Upload, [string]$Code, [string]$Server = 'https://license.infralog.kr')

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$CollectorVersion = '1.1.0'
$Schema           = 'minerhunter.collect/1'
$Now              = Get-Date

function Iso($d) {
    if ($null -eq $d) { return $null }
    try { return ([datetime]$d).ToString('o') } catch { return $null }
}
function Str($v) { if ($null -eq $v) { return $null } return [string]$v }

# 실행 파일 경로 추출 — 서명 여부를 확인할 대상 경로를 정하기 위한 파싱일 뿐 판정이 아니다
function Get-ExePath([string]$cmd) {
    if (-not $cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim()) -replace '^\\\\\?\\', '' -replace '^\\\?\?\\', ''
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { return $c.Substring(1, $e - 1) } }
    $m = [regex]::Match($c, '(?i)^(.+?\.(exe|com|bat|cmd|vbs|js|ps1|dll|scr))(\s|,|$)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# 서명·존재 확인 대상 (경로 → 결과). 같은 경로는 한 번만 확인한다
$SigTargets = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
function Add-SigTarget([string]$p) { if ($p) { [void]$SigTargets.Add($p) } }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---- 환경 변수 (경로 확장 재현용 — 경로 관련 표준 변수만) ----
$envNames = 'windir', 'SystemRoot', 'SystemDrive', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
            'CommonProgramFiles', 'CommonProgramFiles(x86)', 'CommonProgramW6432', 'ALLUSERSPROFILE', 'PUBLIC',
            'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'USERPROFILE', 'USERNAME', 'USERDOMAIN', 'HOMEDRIVE', 'HOMEPATH',
            'COMPUTERNAME', 'OneDrive', 'DriverData', 'ComSpec'
$envMap = [ordered]@{}
foreach ($n in $envNames) { $v = [Environment]::GetEnvironmentVariable($n); if ($null -ne $v) { $envMap[$n] = $v } }

# ---- 시스템 개요 ----
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$cnt = Get-Counter '\Memory\Committed Bytes', '\Memory\Commit Limit', '\Processor(_Total)\% Processor Time'
$cooked = @(); if ($cnt) { $cooked = @($cnt.CounterSamples | ForEach-Object { [double]$_.CookedValue }) }
$system = [ordered]@{
    os_caption = Str $os.Caption; display_version = Str $cv.DisplayVersion; current_build = Str $cv.CurrentBuild; ubr = Str $cv.UBR
    manufacturer = Str $cs.Manufacturer; model = Str $cs.Model; total_physical_memory = $cs.TotalPhysicalMemory
    last_boot = Iso $os.LastBootUpTime
    counters = [ordered]@{ committed_bytes = $cooked[0]; commit_limit = $cooked[1]; cpu_pct = $cooked[2] }
}

# ---- 이벤트 로그 ----
function Get-Events($filter) {
    @(Get-WinEvent -FilterHashtable $filter | ForEach-Object { [ordered]@{ time = Iso $_.TimeCreated; id = $_.Id; message = Str $_.Message } })
}
$events = [ordered]@{
    resource_exhaustion = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004; StartTime = $Now.AddDays(-30) }
    application_popup   = Get-Events @{ LogName = 'System'; ProviderName = 'Application Popup'; StartTime = $Now.AddDays(-30) }
    scm_7000            = Get-Events @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000; StartTime = $Now.AddDays(-30) }
}

# ---- 프로세스 ----
$processes = @(Get-CimInstance Win32_Process | ForEach-Object {
    Add-SigTarget ([string]$_.ExecutablePath)
    [ordered]@{ pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = Str $_.Name; path = Str $_.ExecutablePath
                cmdline = Str $_.CommandLine; private_page_count = [int64]$_.PrivatePageCount; created = Iso $_.CreationDate }
})

# ---- 서비스 / 드라이버 ----
$services = @(Get-CimInstance Win32_Service | ForEach-Object {
    Add-SigTarget (Get-ExePath ([string]$_.PathName))
    [ordered]@{ name = Str $_.Name; display_name = Str $_.DisplayName; state = Str $_.State; start_mode = Str $_.StartMode
                path_name = Str $_.PathName; pid = [int]$_.ProcessId }
})
$serviceDlls = @(foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services') {
    $dll = (Get-ItemProperty (Join-Path $k.PSPath 'Parameters')).ServiceDll
    if ($dll) {
        Add-SigTarget ([Environment]::ExpandEnvironmentVariables([string]$dll))
        [ordered]@{ name = Str $k.PSChildName; service_dll = [string]$dll }
    }
})
$drivers = @(Get-CimInstance Win32_SystemDriver | ForEach-Object { [ordered]@{ name = Str $_.Name; path_name = Str $_.PathName } })

# ---- 예약 작업 ----
$tasks = @(Get-ScheduledTask | ForEach-Object {
    $acts = @(foreach ($a in $_.Actions) {
        $exec = Str $a.Execute
        if ($exec) { $p = Get-ExePath $exec; Add-SigTarget $p }
        [ordered]@{ execute = $exec; arguments = Str $a.Arguments }
    })
    [ordered]@{ path = Str $_.TaskPath; name = Str $_.TaskName; author = Str $_.Author; state = Str $_.State; actions = $acts }
})

# ---- 자동 실행 ----
$providerProps = 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider'
$runKeys = @(foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce') {
    $ip = Get-ItemProperty $k
    if ($null -eq $ip) { continue }
    $vals = @(foreach ($pr in $ip.PSObject.Properties) {
        if ($providerProps -contains $pr.Name) { continue }
        $v = [string]$pr.Value; Add-SigTarget (Get-ExePath $v)
        [ordered]@{ name = $pr.Name; value = $v }
    })
    [ordered]@{ key = $k; values = $vals }
})

$userDirs = @(Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object { [ordered]@{ name = $_.Name; full_name = $_.FullName } })
$startupDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
foreach ($u in $userDirs) { $startupDirs += Join-Path $u.full_name 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
$startup = @(foreach ($d in $startupDirs) {
    $files = @(Get-ChildItem -LiteralPath $d -File -Force | ForEach-Object {
        $content = $null
        if ($_.Length -lt 200KB -and $_.Extension -match '(?i)^\.(bat|cmd|vbs|js|ps1|hta)$') { $content = Get-Content -LiteralPath $_.FullName -Raw }
        Add-SigTarget $_.FullName
        [ordered]@{ name = $_.Name; full_name = $_.FullName; extension = $_.Extension; length = [int64]$_.Length; created = Iso $_.CreationTime; content = Str $content }
    })
    [ordered]@{ dir = $d; files = $files }
})

$wmi = [ordered]@{
    command_line_consumers = @(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object {
        [ordered]@{ name = Str $_.Name; command_line_template = Str $_.CommandLineTemplate; executable_path = Str $_.ExecutablePath } })
    script_consumers = @(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object {
        [ordered]@{ name = Str $_.Name; script_text = Str $_.ScriptText } })
}
$ifeo = @(foreach ($k in Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
    $dbg = (Get-ItemProperty $k.PSPath).Debugger
    if ($dbg) { [ordered]@{ name = Str $k.PSChildName; debugger = [string]$dbg } }
})
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$winlogon = [ordered]@{ shell = Str $wl.Shell; userinit = Str $wl.Userinit }

# 주요 설치 폴더의 최상위 항목 이름 (특정 프로그램 설치 흔적 확인용)
$topLevel = [ordered]@{}
foreach ($n in 'windir', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)') {
    $p = [Environment]::GetEnvironmentVariable($n)
    if ($p) { $topLevel[$p] = @(Get-ChildItem -LiteralPath $p -Force | ForEach-Object { $_.Name }) }
}

# ---- Defender ----
$mp = Get-MpPreference; $st = Get-MpComputerStatus
$defender = [ordered]@{
    status = $(if ($st) { [ordered]@{ am_running_mode = Str $st.AMRunningMode; real_time_protection_enabled = [bool]$st.RealTimeProtectionEnabled
                                      is_tamper_protected = [bool]$st.IsTamperProtected; signature_last_updated = Iso $st.AntivirusSignatureLastUpdated } } else { $null })
    exclusion_process   = @(@($mp.ExclusionProcess) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    exclusion_path      = @(@($mp.ExclusionPath) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    exclusion_extension = @(@($mp.ExclusionExtension) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    av_products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
        [ordered]@{ display_name = Str $_.displayName; product_state = [int64]$_.productState } })
    detections = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10 | ForEach-Object {
        [ordered]@{ time = Iso $_.InitialDetectionTime; threat_id = Str $_.ThreatID; action_success = [bool]$_.ActionSuccess; resources = @($_.Resources | ForEach-Object { [string]$_ }) } })
}

# ---- 파일 목록 ----
$refFiles = @(foreach ($r in "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe", "$env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
                             "$env:windir\System32\cmd.exe", "$env:windir\SysWOW64\cmd.exe") {
    if (Test-Path -LiteralPath $r) { $i = Get-Item -LiteralPath $r; [ordered]@{ path = $r; name = $i.Name; length = [int64]$i.Length; sha256 = (Get-FileHash -LiteralPath $r).Hash } }
})
$refSizes = @($refFiles | ForEach-Object { $_.length })
$roots = @(@{ P = 'C:\ProgramData'; D = 3 }, @{ P = $env:windir; D = 0 }, @{ P = 'C:\Users\Public'; D = 3 })
foreach ($u in $userDirs | Where-Object { $_.name -notmatch '^(Public|Default|Default User|All Users)$' }) {
    $roots += @{ P = (Join-Path $u.full_name 'AppData\Roaming'); D = 2 }
    $roots += @{ P = (Join-Path $u.full_name 'AppData\Local\Temp'); D = 2 }
}
# 시스템 저장소·패키지 캐시처럼 양이 많고 사용자가 손대지 않는 폴더는 건너뛴다
$skip = '(?i)\\(WinSxS|servicing|SoftwareDistribution|Installer|assembly|Microsoft\.NET|DriverStore|Package Cache|Packages|WindowsApps|MinerHunter|IR_Quarantine)(\\|$)'
$hashes = [ordered]@{}
$fileRoots = @(foreach ($r in $roots) {
    $exists = [bool](Test-Path -LiteralPath $r.P)
    $list = @()
    if ($exists) {
        $list = @(Get-ChildItem -LiteralPath $r.P -Recurse -Depth $r.D -File -Force | Where-Object { $_.FullName -notmatch $skip } | ForEach-Object {
            # 시스템 셸과 크기가 같은 실행 파일만 해시 — 복사본 위장 확인용, 전체 해시는 너무 느리다
            if ($_.Extension -eq '.exe' -and $refSizes -contains $_.Length -and -not $hashes.Contains($_.FullName)) { $hashes[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName).Hash }
            [ordered]@{ full_name = $_.FullName; name = $_.Name; extension = $_.Extension; length = [int64]$_.Length; created = Iso $_.CreationTime }
        })
    }
    [ordered]@{ path = $r.P; depth = $r.D; exists = $exists; files = $list }
})

# ---- 네트워크 ----
$network = [ordered]@{
    dns_cache = @(Get-DnsClientCache | ForEach-Object { [ordered]@{ entry = Str $_.Entry; data = Str $_.Data } })
    tcp_established = @(Get-NetTCPConnection -State Established | ForEach-Object {
        [ordered]@{ pid = [int]$_.OwningProcess; local_port = [int]$_.LocalPort; remote_address = Str $_.RemoteAddress; remote_port = [int]$_.RemotePort } })
    hosts_lines = @(Get-Content "$env:windir\System32\drivers\etc\hosts" -Encoding UTF8 | ForEach-Object { [string]$_ })
}

# ---- 서명·존재 확인 ----
$signatures = [ordered]@{}
foreach ($p in $SigTargets) {
    $exists = [bool](Test-Path -LiteralPath $p)
    $status = $null
    if ($exists) { $status = [string](Get-AuthenticodeSignature -LiteralPath $p).Status }
    $signatures[$p] = [ordered]@{ exists = $exists; status = $status }
}

$doc = [ordered]@{
    schema = $Schema; collector_version = $CollectorVersion; collected_at = $Now.ToString('o')
    is_admin = $isAdmin; self_pid = $PID; computer = $env:COMPUTERNAME
    env = $envMap; system = $system; events = $events
    processes = $processes; services = $services; service_dlls = $serviceDlls; drivers = $drivers; tasks = $tasks
    run_keys = $runKeys; user_dirs = $userDirs; startup = $startup; wmi = $wmi; ifeo = $ifeo; winlogon = $winlogon
    top_level = $topLevel; defender = $defender
    files = [ordered]@{ ref_files = $refFiles; roots = $fileRoots; hashes = $hashes }
    network = $network; signatures = $signatures
}

$keepFile = [bool]$OutFile
if (-not $OutFile) { $OutFile = Join-Path $env:TEMP ("minerhunter_collect_{0}.json" -f $Now.ToString('yyyyMMdd_HHmmss')) }
$json = $doc | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host "수집 완료: $OutFile ($([int]((Get-Item -LiteralPath $OutFile).Length / 1KB)) KB, $([int]((Get-Date) - $Now).TotalSeconds)초)"
if (-not $isAdmin) { Write-Host '※ 관리자 권한이 아니어서 일부 정보(다른 사용자 프로세스·Defender 예외)가 빠졌습니다.' -ForegroundColor Yellow }

if (-not $Upload) { return }

# ---- 업로드: 연결 코드 → 서버 판정 → 리포트 ----
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$raw = [Text.Encoding]::UTF8.GetBytes($json)
$ms = New-Object IO.MemoryStream
$gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
$gz.Write($raw, 0, $raw.Length); $gz.Close()
$body = $ms.ToArray()

$result = $null
for ($try = 1; $try -le 3 -and -not $result; $try++) {
    while (-not $Code) { $Code = ([string](Read-Host '웹 페이지에 표시된 연결 코드(8자리)를 입력하세요')).Trim() }
    Write-Host '서버로 보내 판정하는 중...'
    try {
        $result = Invoke-RestMethod -Uri ($Server.TrimEnd('/') + '/v1/tools/scans') -Method Post -Body $body -ContentType 'application/json' `
                    -Headers @{ 'Content-Encoding' = 'gzip'; 'X-Link-Code' = $Code } -TimeoutSec 300 -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        try { $d = ($_.ErrorDetails.Message | ConvertFrom-Json).detail; if ($d) { $msg = [string]$d } } catch {}
        Write-Host "업로드 실패: $msg" -ForegroundColor Red
        $status = 0; try { $status = [int]$_.Exception.Response.StatusCode } catch {}
        if ($status -ne 401) { break }
        $Code = $null   # 코드가 틀렸거나 만료 — 다시 입력받는다
    }
}
if (-not $result) { Write-Host "결과 파일은 남겨 두었습니다: $OutFile"; return }

$s = $result.summary
$verdictText = @{ infected = '감염 확정'; suspicious = '감염 의심'; clean = '이상 징후 없음' }[[string]$s.verdict]
Write-Host ''
Write-Host ("판정: {0}   (CRITICAL {1} / HIGH {2} / MEDIUM {3} / INFO {4})" -f $verdictText, $s.critical, $s.high, $s.medium, $s.info) -ForegroundColor Cyan
Write-Host "리포트: $($result.url)"
if (-not $keepFile) { Remove-Item -LiteralPath $OutFile -Force }
Start-Process $result.url
