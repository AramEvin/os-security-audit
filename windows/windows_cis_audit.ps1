<#
.SYNOPSIS
    IT Security LLC - windows_cis_audit.ps1 (v3.0)
    Technical security audit for Windows 10 / Windows 11 / Windows Server 2016-2025.

.DESCRIPTION
    Windows counterpart of debian_cis_audit.sh. Aligned with ISO/IEC 27001 technical
    controls (Annex A: A.8, A.12, A.13) and CIS Benchmarks methodology (Level 1 / Level 2).

    This script ONLY READS system state (read-only audit). The only artefacts it writes are
    its own report files and short-lived temp files (secedit export), which are removed.
      [PASS] - Control satisfied
      [WARN] - Deviation / Level 2 / requires attention
      [FAIL] - Critical non-compliance (Level 1)
      [INFO] - Informational entry, does not affect score

    Output:
      - Console (colored)
      - <OutputDir>\windows_cis_audit_report.log    (text report, cumulative)
      - <OutputDir>\windows_cis_audit_report.html   (interactive web report)
      - <OutputDir>\windows_cis_audit_results.json  (machine-readable, latest run)

    Exit codes: 0 = all passed, 1 = warnings only, 2 = at least one FAIL, 3 = not run (no admin / wrong OS)

.PARAMETER OutputDir
    Report directory. Default: %ProgramData%\ITSecurity

.PARAMETER DeepScan
    Also run 'sfc /verifyonly' (system file integrity). Slow: can take 10+ minutes.

.PARAMETER SkipUpdateSearch
    Skip the Windows Update Agent search for pending updates (use on hosts without WU/WSUS reachability).

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows_cis_audit.ps1
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $env:ProgramData 'ITSecurity'),
    [switch]$DeepScan,
    [switch]$SkipUpdateSearch
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ============================================================================
# 0. GLOBAL PARAMETERS & INITIALIZATION
# ============================================================================

$script:Version     = '3.0'
$script:AuditorName = 'IT Security LLC'
$ReportFile         = Join-Path $OutputDir 'windows_cis_audit_report.log'
$HtmlReportFile     = Join-Path $OutputDir 'windows_cis_audit_report.html'
$JsonReportFile     = Join-Path $OutputDir 'windows_cis_audit_results.json'
$RunTs              = Get-Date
$RunTsText          = $RunTs.ToString('yyyy-MM-dd HH:mm:ss zzz')

$script:CountPass = 0
$script:CountWarn = 0
$script:CountFail = 0
$script:CountInfo = 0
$script:Findings      = New-Object System.Collections.Generic.List[object]
$script:ReportLines   = New-Object System.Collections.Generic.List[string]
$script:CurrentSection = '1. INITIALIZATION AND OS INFORMATION'

function Write-Raw {
    param([string]$Text = '', [string]$Color = '')
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
    [void]$script:ReportLines.Add($Text)
}

function Write-Section {
    param([string]$Title)
    $script:CurrentSection = $Title
    Write-Raw ''
    Write-Raw ('=' * 66) 'Cyan'
    Write-Raw " $Title" 'Cyan'
    Write-Raw ('=' * 66) 'Cyan'
}

function Write-Tagged {
    param([string]$Tag, [string]$Color, [string]$Msg, [string]$Rem = '')
    Write-Host '  ' -NoNewline
    Write-Host "[$Tag]" -ForegroundColor $Color -NoNewline
    Write-Host " $Msg"
    [void]$script:ReportLines.Add("  [$Tag] $Msg")
    if ($Rem) {
        $line = "         -> Recommendation: $Rem"
        Write-Host $line
        [void]$script:ReportLines.Add($line)
    }
    [void]$script:Findings.Add([pscustomobject]@{
        Level = $Tag; Section = $script:CurrentSection; Message = $Msg; Remediation = $Rem })
}

function Add-Pass { param([string]$Msg)                    $script:CountPass++; Write-Tagged 'PASS' 'Green'  $Msg '' }
function Add-Warn { param([string]$Msg, [string]$Rem = '') $script:CountWarn++; Write-Tagged 'WARN' 'Yellow' $Msg $Rem }
function Add-Fail { param([string]$Msg, [string]$Rem = '') $script:CountFail++; Write-Tagged 'FAIL' 'Red'    $Msg $Rem }
function Add-Info { param([string]$Msg)                    $script:CountInfo++; Write-Tagged 'INFO' 'White'  $Msg '' }

function Add-Result {
    param([string]$Sev, [string]$Msg, [string]$Rem = '')
    if ($Sev -eq 'FAIL') { Add-Fail $Msg $Rem } else { Add-Warn $Msg $Rem }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function New-RegFix {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    "New-Item -Path '$Path' -Force | Out-Null; New-ItemProperty -Path '$Path' -Name '$Name' -Value $Value -PropertyType $Type -Force | Out-Null"
}

function Test-Cmp {
    param($Actual, [string]$Op, $Value)
    try {
        switch ($Op) {
            'eq'    { return ([string]$Actual -eq [string]$Value) }
            'le'    { return ([int64]$Actual -le [int64]$Value) }
            'ge'    { return ([int64]$Actual -ge [int64]$Value) }
    'gem1'  { return ([int64]$Actual -eq -1 -or [int64]$Actual -ge [int64]$Value) }   # -1 = never auto-unlock (compliant)
            'range' { return ([int64]$Actual -ge [int64]$Value[0] -and [int64]$Actual -le [int64]$Value[1]) }
        }
    } catch { return $false }
    return $false
}

# Registry-driven checks (equivalent of the SYSCTL_EXPECTED table in the Linux script).
# Entry keys: Path, Name, Value, Desc, [Op=eq|le|ge|range] [Sev=FAIL|WARN] [Default=$true -> missing value is compliant]
function Test-RegTable {
    param([object[]]$Table)
    foreach ($t in $Table) {
        $op  = if ($t.Op)  { $t.Op }  else { 'eq' }
        $sev = if ($t.Sev) { $t.Sev } else { 'FAIL' }
        $expTxt = if ($op -eq 'range') { "$($t.Value[0])-$($t.Value[1])" } elseif ($op -eq 'le') { "<= $($t.Value)" } elseif ($op -eq 'ge') { ">= $($t.Value)" } else { "$($t.Value)" }
        $fixVal = if ($op -eq 'range') { $t.Value[1] } else { $t.Value }
        $fix = New-RegFix $t.Path $t.Name $fixVal
        $actual = Get-RegValue $t.Path $t.Name
        if ($null -eq $actual) {
            if ($t.Default) { Add-Pass "$($t.Desc): not configured - OS default is compliant ($($t.Name))" }
            else            { Add-Result $sev "$($t.Desc): not configured (expected: $expTxt) [$($t.Name)]" $fix }
        }
        elseif (Test-Cmp $actual $op $t.Value) { Add-Pass "$($t.Desc): $($t.Name) = $actual (expected: $expTxt)" }
        else { Add-Result $sev "$($t.Desc): $($t.Name) = $actual (expected: $expTxt)" $fix }
    }
}

function Get-SidString {
    param($Identity)
    try {
        if ($Identity -is [System.Security.Principal.SecurityIdentifier]) { return $Identity.Value }
        return (New-Object System.Security.Principal.NTAccount([string]$Identity)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

# ============================================================================
# 1. ADMIN CHECK AND OS INFORMATION
# ============================================================================

Write-Section '1. INITIALIZATION AND OS INFORMATION'

if ($env:OS -ne 'Windows_NT') {
    Write-Host '[FAIL] This script targets Windows only.' -ForegroundColor Red
    exit 3
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host '[FAIL] Script must be run from an elevated session (Run as Administrator).' -ForegroundColor Red
    Write-Host "Current user: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Red
    Write-Host 'Re-run using: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows_cis_audit.ps1' -ForegroundColor Red
    exit 3
}

$OsCim  = Get-CimInstance Win32_OperatingSystem
$CsCim  = Get-CimInstance Win32_ComputerSystem
$NtKey  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$Build  = [int]$OsCim.BuildNumber
$Ubr    = Get-RegValue $NtKey 'UBR'
$DispVer   = Get-RegValue $NtKey 'DisplayVersion'
$EditionId = [string](Get-RegValue $NtKey 'EditionID')
$ProductType = [int]$OsCim.ProductType            # 1 = workstation, 2 = domain controller, 3 = server
$IsServer = ($ProductType -ne 1)
$IsDC     = ($ProductType -eq 2)
$IsDomainJoined = [bool]$CsCim.PartOfDomain
$DomainRoleText = switch ([int]$CsCim.DomainRole) {
    0 { 'Standalone workstation' } 1 { 'Member workstation' } 2 { 'Standalone server' }
    3 { 'Member server' } 4 { 'Backup domain controller' } 5 { 'Primary domain controller' } default { 'Unknown' } }

$HostFqdn = if ($IsDomainJoined -and $CsCim.DNSHostName) { "$($CsCim.DNSHostName).$($CsCim.Domain)" } else { $env:COMPUTERNAME }
$OsInfo   = "$($OsCim.Caption.Trim())" + $(if ($DispVer) { " $DispVer" } else { '' })
$BuildInfo = "$($OsCim.BuildNumber)" + $(if ($null -ne $Ubr) { ".$Ubr" } else { '' })
$Up = $RunTs - $OsCim.LastBootUpTime
$UptimeInfo = '{0} days, {1} hours, {2} minutes' -f $Up.Days, $Up.Hours, $Up.Minutes

Write-Raw 'Technical Security Audit (CIS / ISO 27001) - Windows 10 / 11 / Server'
Write-Raw "Script Version : $script:Version"
Write-Raw "Host           : $HostFqdn"
Write-Raw "Date/Time      : $RunTsText"
Write-Raw "Report File    : $ReportFile"
Write-Raw "OS             : $OsInfo"
Write-Raw "OS Build       : $BuildInfo   (edition: $EditionId)"
Write-Raw "Role           : $DomainRoleText   (ProductType=$ProductType)"
Write-Raw "PowerShell     : $($PSVersionTable.PSVersion)"

if ($OsCim.Caption -match 'Windows (10|11|Server)') {
    Add-Pass "Detected supported Windows family: $OsInfo (build $BuildInfo)"
} else {
    Add-Warn "OS not recognized as Windows 10/11/Server ($($OsCim.Caption)); some checks might not apply" `
             'Run this audit on Windows 10/11 or Windows Server 2016+'
}
if ($PSVersionTable.PSVersion.Major -ge 5) { } else { Add-Warn 'Windows PowerShell older than 5.1 detected' 'Install WMF 5.1' }

# ============================================================================
# 2. LOGGING & AUDIT SUBSYSTEM (Event Log / Advanced Audit Policy / PowerShell)
# ============================================================================

Write-Section '2. LOGGING AND AUDIT SUBSYSTEM (Event Log / Advanced Audit Policy / PowerShell logging)'

$svc = Get-Service -Name EventLog
if ($svc -and $svc.Status -eq 'Running') { Add-Pass 'Windows Event Log service is running' }
else { Add-Fail 'Windows Event Log service is NOT running' 'Set-Service EventLog -StartupType Automatic; Start-Service EventLog' }

foreach ($l in @(@{ N = 'Security'; KB = 196608 }, @{ N = 'System'; KB = 32768 }, @{ N = 'Application'; KB = 32768 })) {
    $log = Get-WinEvent -ListLog $l.N -ErrorAction SilentlyContinue
    if (-not $log) { Add-Warn "Event log '$($l.N)' could not be queried"; continue }
    $kb = [math]::Round($log.MaximumSizeInBytes / 1KB)
    if ($kb -ge $l.KB) { Add-Pass "$($l.N) log max size $kb KB (>= $($l.KB) KB), mode: $($log.LogMode)" }
    else { Add-Warn "$($l.N) log max size $kb KB (recommended >= $($l.KB) KB)" "wevtutil sl $($l.N) /ms:$($l.KB * 1024)" }
}

# Advanced Audit Policy (auditpol, keyed by subcategory GUID = locale independent)
$AuditPol = @{}
try {
    $raw = & auditpol.exe /get /category:* /r 2>$null
    if ($LASTEXITCODE -eq 0 -and $raw) {
        $raw | Where-Object { $_ -and $_.Trim() } | Select-Object -Skip 1 |
            ConvertFrom-Csv -Header 'Machine', 'Target', 'Subcategory', 'GUID', 'Inclusion', 'Exclusion' |
            ForEach-Object { $AuditPol[$_.GUID.Trim('{}').ToUpper()] = [string]$_.Inclusion }
    }
} catch { }

$AuditExpect = @(
    @{ G = '0CCE923F-69AE-11D9-BED3-505054503030'; N = 'Credential Validation';           R = 'SF' },
    @{ G = '0CCE9237-69AE-11D9-BED3-505054503030'; N = 'Security Group Management';       R = 'S'  },
    @{ G = '0CCE9235-69AE-11D9-BED3-505054503030'; N = 'User Account Management';         R = 'SF' },
    @{ G = '0CCE922B-69AE-11D9-BED3-505054503030'; N = 'Process Creation';                R = 'S'  },
    @{ G = '0CCE9215-69AE-11D9-BED3-505054503030'; N = 'Logon';                           R = 'SF' },
    @{ G = '0CCE9216-69AE-11D9-BED3-505054503030'; N = 'Logoff';                          R = 'S'  },
    @{ G = '0CCE9217-69AE-11D9-BED3-505054503030'; N = 'Account Lockout';                 R = 'F'  },
    @{ G = '0CCE921B-69AE-11D9-BED3-505054503030'; N = 'Special Logon';                   R = 'S'  },
    @{ G = '0CCE922F-69AE-11D9-BED3-505054503030'; N = 'Audit Policy Change';             R = 'S'  },
    @{ G = '0CCE9230-69AE-11D9-BED3-505054503030'; N = 'Authentication Policy Change';    R = 'S'  },
    @{ G = '0CCE9228-69AE-11D9-BED3-505054503030'; N = 'Sensitive Privilege Use';         R = 'SF' },
    @{ G = '0CCE9210-69AE-11D9-BED3-505054503030'; N = 'Security State Change';           R = 'S'  },
    @{ G = '0CCE9211-69AE-11D9-BED3-505054503030'; N = 'Security System Extension';       R = 'S'  },
    @{ G = '0CCE9212-69AE-11D9-BED3-505054503030'; N = 'System Integrity';                R = 'SF' },
    @{ G = '0CCE9245-69AE-11D9-BED3-505054503030'; N = 'Removable Storage';               R = 'SF' },
    @{ G = '0CCE9236-69AE-11D9-BED3-505054503030'; N = 'Computer Account Management';     R = 'S';  DC = $true },
    @{ G = '0CCE923C-69AE-11D9-BED3-505054503030'; N = 'Directory Service Changes';       R = 'S';  DC = $true },
    @{ G = '0CCE9242-69AE-11D9-BED3-505054503030'; N = 'Kerberos Authentication Service'; R = 'SF'; DC = $true },
    @{ G = '0CCE9240-69AE-11D9-BED3-505054503030'; N = 'Kerberos Service Ticket Operations'; R = 'SF'; DC = $true }
)

if ($AuditPol.Count -eq 0) {
    Add-Warn 'auditpol returned no data - Advanced Audit Policy could not be verified' 'Run: auditpol /get /category:*'
} else {
    $auditLocaleWarned = $false
    foreach ($a in $AuditExpect) {
        if ($a.DC -and -not $IsDC) { continue }
        $cur = $AuditPol[$a.G]
        if ($null -eq $cur) { Add-Info "Audit subcategory '$($a.N)': not present on this OS build - skipped"; continue }
        if ($cur -notmatch 'Success|Failure|No Auditing') {
            if (-not $auditLocaleWarned) { Add-Info "auditpol output is not in English ('$cur') - audit subcategory values cannot be interpreted"; $auditLocaleWarned = $true }
            continue
        }
        $hasS = $cur -match 'Success'; $hasF = $cur -match 'Failure'
        $needS = $a.R -match 'S';      $needF = $a.R -match 'F'
        $okS = (-not $needS) -or $hasS;  $okF = (-not $needF) -or $hasF
        $expTxt = @(@(if ($needS) { 'Success' }) + @(if ($needF) { 'Failure' })) -join ' and '
        if ($okS -and $okF) { Add-Pass "Audit '$($a.N)': $cur (required: $expTxt)" }
        else {
            $fixArgs = "$(if ($needS) { ' /success:enable' })$(if ($needF) { ' /failure:enable' })"
            Add-Fail "Audit '$($a.N)': $cur (required: $expTxt)" "auditpol /set /subcategory:`"{$($a.G)}`"$fixArgs"
        }
    }
}

$LogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Test-RegTable @(
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Value = 1; Desc = 'Force audit policy subcategory settings to override legacy category settings' },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1; Desc = 'Include command line in process creation events (4688)' },
    @{ Path = "$LogPath\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Value = 1; Desc = 'PowerShell Script Block Logging' },
    @{ Path = "$LogPath\ModuleLogging";      Name = 'EnableModuleLogging';      Value = 1; Desc = 'PowerShell Module Logging'; Sev = 'WARN' },
    @{ Path = "$LogPath\Transcription";      Name = 'EnableTranscripting';      Value = 1; Desc = 'PowerShell Transcription'; Sev = 'WARN' }
)

$w32 = Get-Service -Name W32Time
if ($w32 -and $w32.Status -eq 'Running') {
    Add-Pass 'Windows Time service (W32Time) is running'
    $tsrc = (& w32tm.exe /query /source 2>$null | Out-String).Trim()
    if ($tsrc) { Add-Info "Time source: $tsrc" }
} else { Add-Warn 'Windows Time service (W32Time) is not running - log timestamps may drift' 'Set-Service W32Time -StartupType Automatic; Start-Service W32Time' }

$sysmon = @(Get-Service | Where-Object { $_.Name -match '^Sysmon' -and $_.Status -eq 'Running' })
if ($sysmon.Count -gt 0) { Add-Pass "Sysmon is running ($($sysmon[0].Name))" }
else { Add-Warn 'Sysmon is not installed/running - reduced endpoint telemetry (Level 2)' 'Deploy Sysmon with a maintained config (e.g. SwiftOnSecurity / Olaf Hartong modular)' }

$wazuh = @(Get-Service -Name WazuhSvc, OssecSvc -ErrorAction SilentlyContinue)
if ($wazuh.Count -gt 0 -and $wazuh[0].Status -eq 'Running') { Add-Pass "Wazuh agent service is running ($($wazuh[0].Name))" }
elseif ($wazuh.Count -gt 0) { Add-Fail "Wazuh agent service is installed but $($wazuh[0].Status)" "Start-Service $($wazuh[0].Name)" }
else { Add-Info 'Wazuh agent service not found on this host' }

# ============================================================================
# 3. NETWORK SECURITY, OPEN PORTS, AND FIREWALL
# ============================================================================

Write-Section '3. NETWORK SECURITY, PROTOCOLS AND FIREWALL'

$procMap = @{}
Get-Process | ForEach-Object { $procMap[[int]$_.Id] = $_.ProcessName }
$tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort)
$udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Sort-Object LocalPort)
if ($tcp.Count -gt 0 -or $udp.Count -gt 0) {
    Add-Info "Gathering listening endpoints via Get-NetTCPConnection / Get-NetUDPEndpoint"
    foreach ($c in $tcp) { Write-Raw ('         tcp  {0,-40} pid={1} ({2})' -f "$($c.LocalAddress):$($c.LocalPort)", $c.OwningProcess, $procMap[[int]$c.OwningProcess]) }
    foreach ($c in $udp) { Write-Raw ('         udp  {0,-40} pid={1} ({2})' -f "$($c.LocalAddress):$($c.LocalPort)", $c.OwningProcess, $procMap[[int]$c.OwningProcess]) }
    Add-Info "Total listening sockets (TCP LISTEN / UDP): $($tcp.Count + $udp.Count)"
    $wild = @($tcp | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' } | Select-Object -ExpandProperty LocalPort -Unique)
    if ($wild.Count -gt 0) {
        Add-Warn "Detected $($wild.Count) TCP ports listening on all interfaces (0.0.0.0/::): $($wild -join ', ')" `
                 'Restrict service bind addresses; close unused ports with Windows Firewall inbound rules'
    }
} else {
    Add-Info 'Get-NetTCPConnection unavailable, falling back to netstat -ano'
    & netstat.exe -ano 2>$null | Select-String 'LISTENING|UDP' | ForEach-Object { Write-Raw "         $($_.Line.Trim())" }
}

$fwp = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
if ($fwp.Count -eq 0) {
    Add-Fail 'Windows Firewall state could not be queried (MpsSvc stopped or third-party firewall only)' 'Set-Service MpsSvc -StartupType Automatic; Start-Service MpsSvc'
} else {
    foreach ($p in $fwp) {
        $n = $p.Name
        if ("$($p.Enabled)" -eq 'True') { Add-Pass "Windows Firewall ($n profile) is enabled" }
        else { Add-Fail "Windows Firewall ($n profile) is DISABLED" "Set-NetFirewallProfile -Profile $n -Enabled True" }
        if ("$($p.DefaultInboundAction)" -eq 'Block') { Add-Pass "Firewall ($n): default inbound action = Block (implicit deny)" }
        else { Add-Fail "Firewall ($n): default inbound action = $($p.DefaultInboundAction)" "Set-NetFirewallProfile -Profile $n -DefaultInboundAction Block" }
        if ("$($p.LogBlocked)" -eq 'True' -and [int]$p.LogMaxSizeKilobytes -ge 16384) { Add-Pass "Firewall ($n): dropped packets logged, max log size $($p.LogMaxSizeKilobytes) KB" }
        else { Add-Warn "Firewall ($n): logging of dropped packets off or log size < 16384 KB (LogBlocked=$($p.LogBlocked), size=$($p.LogMaxSizeKilobytes))" "Set-NetFirewallProfile -Profile $n -LogBlocked True -LogMaxSizeKilobytes 16384" }
    }
}

# SMB
$smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smb) {
    if (-not $smb.EnableSMB1Protocol) { Add-Pass 'SMBv1 server protocol is disabled' }
    else { Add-Fail 'SMBv1 server protocol is ENABLED' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' }
    if ($smb.EnableSMB2Protocol) { Add-Pass 'SMBv2/v3 is enabled' } else { Add-Fail 'SMBv2/v3 is disabled' 'Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force' }
    Add-Info "SMB encryption (EncryptData) = $($smb.EncryptData); RejectUnencryptedAccess = $($smb.RejectUnencryptedAccess)"
} else { Add-Warn 'Get-SmbServerConfiguration unavailable - SMB configuration could not be verified' }

$shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special })
if ($shares.Count -gt 0) {
    Add-Info "Non-administrative SMB shares: $(($shares | ForEach-Object { $_.Name }) -join ', ')"
    foreach ($sh in $shares) {
        foreach ($ace in @(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue)) {
            if ("$($ace.AccessControlType)" -eq 'Allow' -and "$($ace.AccessRight)" -in 'Full', 'Change' -and (Get-SidString $ace.AccountName) -in 'S-1-1-0', 'S-1-5-7') {
                Add-Warn "Share '$($sh.Name)' grants $($ace.AccessRight) to $($ace.AccountName)" "Revoke-SmbShareAccess -Name '$($sh.Name)' -AccountName '$($ace.AccountName)' -Force"
            }
        }
    }
} else { Add-Pass 'No non-administrative SMB shares exposed' }

# NetBIOS over TCP/IP
foreach ($nic in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE')) {
    if ($nic.TcpipNetbiosOptions -eq 2) { Add-Pass "NetBIOS over TCP/IP disabled on '$($nic.Description)'" }
    else { Add-Warn "NetBIOS over TCP/IP not disabled on '$($nic.Description)' (option=$($nic.TcpipNetbiosOptions))" "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'Index=$($nic.Index)' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2}" }
}

# Remote Desktop
$TsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
if ((Get-RegValue $TsKey 'fDenyTSConnections') -eq 0) {
    Add-Info "Remote Desktop is ENABLED (port $(Get-RegValue "$TsKey\WinStations\RDP-Tcp" 'PortNumber'))"
    Test-RegTable @(
        @{ Path = "$TsKey\WinStations\RDP-Tcp"; Name = 'UserAuthentication'; Value = 1; Desc = 'RDP requires Network Level Authentication (NLA)' },
        @{ Path = "$TsKey\WinStations\RDP-Tcp"; Name = 'SecurityLayer';      Value = 2; Desc = 'RDP security layer = TLS'; Sev = 'WARN' },
        @{ Path = "$TsKey\WinStations\RDP-Tcp"; Name = 'MinEncryptionLevel'; Value = 3; Desc = 'RDP encryption level = High'; Sev = 'WARN' }
    )
} else { Add-Pass 'Remote Desktop is disabled' }

# WinRM
$wr = Get-Service -Name WinRM
if ($wr -and $wr.Status -eq 'Running') {
    Add-Info 'WinRM service is running'
    $basic = try { (Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction Stop).Value } catch { $null }
    $unenc = try { (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction Stop).Value } catch { $null }
    if ($null -ne $basic) { if ("$basic" -eq 'false') { Add-Pass 'WinRM service: Basic authentication disabled' } else { Add-Fail 'WinRM service: Basic authentication ENABLED' 'Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false' } }
    if ($null -eq $basic -and $null -eq $unenc) { Add-Warn 'WinRM is running but WSMan configuration could not be read' 'Run: winrm get winrm/config/service' }
    if ($null -ne $unenc) { if ("$unenc" -eq 'false') { Add-Pass 'WinRM service: unencrypted traffic not allowed' } else { Add-Fail 'WinRM service: AllowUnencrypted = true' 'Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false' } }
} else { Add-Pass 'WinRM service is not running' }

# SCHANNEL protocols (server side)
foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
    $en = Get-RegValue $base 'Enabled'; $dis = Get-RegValue $base 'DisabledByDefault'
    $legacy = $proto -like 'SSL*'
    $fix = "$(New-RegFix $base 'Enabled' 0); $(New-RegFix $base 'DisabledByDefault' 1)"
    if ($null -ne $en -and [int64]$en -eq 0) { Add-Pass "$proto (server) is disabled" }
    elseif ($null -ne $en) { Add-Result $(if ($legacy) { 'FAIL' } else { 'WARN' }) "$proto (server) is explicitly ENABLED (Enabled=$en)" $fix }
    elseif ($dis -eq 1) { Add-Pass "$proto (server) is disabled by default (DisabledByDefault=1)" }
    elseif ($legacy)   { Add-Pass "$proto (server) not enabled (OS default: disabled)" }
    else               { Add-Warn "$proto (server) is not explicitly disabled (OS default depends on build)" $fix }
}

Test-RegTable @(
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters';  Name = 'DisableIPSourceRouting'; Value = 2; Desc = 'IPv4 source routing disabled' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name = 'DisableIPSourceRouting'; Value = 2; Desc = 'IPv6 source routing disabled' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters';  Name = 'EnableICMPRedirect';     Value = 0; Desc = 'ICMP redirects cannot override OSPF routes' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters';  Name = 'NoNameReleaseOnDemand';  Value = 1; Desc = 'NetBIOS ignores name-release requests'; Sev = 'WARN' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient';    Name = 'EnableMulticast';        Value = 0; Desc = 'LLMNR (multicast name resolution) disabled' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'; Name = 'EnableMDNS';          Value = 0; Desc = 'mDNS disabled'; Sev = 'WARN' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';      Name = 'RequireSecuritySignature'; Value = 1; Desc = 'SMB server: digitally sign communications (always)' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';      Name = 'RestrictNullSessAccess';   Value = 1; Desc = 'Restrict anonymous access to named pipes and shares'; Default = $true },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; Value = 1; Desc = 'SMB client: digitally sign communications (always)' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation';          Name = 'AllowInsecureGuestAuth';   Value = 0; Desc = 'SMB insecure guest logons disabled'; Default = $IsServer },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319';              Name = 'SchUseStrongCrypto'; Value = 1; Desc = '.NET 4 strong crypto (64-bit)'; Sev = 'WARN' },
    @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319';  Name = 'SchUseStrongCrypto'; Value = 1; Desc = '.NET 4 strong crypto (32-bit)'; Sev = 'WARN' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; Name = 'RestrictDriverInstallationToAdministrators'; Value = 1; Desc = 'Point and Print: driver installation restricted to administrators (PrintNightmare)'; Default = $true }
)

# ============================================================================
# 4. USERS, PERMISSIONS, LOCAL POLICY, AND REMOTE ACCESS
# ============================================================================

Write-Section '4. USER ACCOUNTS, PASSWORD POLICY, PERMISSIONS, AND REMOTE ACCESS'

if (-not $IsDC) {
    $users = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=TRUE')
    if ($users.Count -eq 0) { Add-Warn 'Local account list could not be read (Win32_UserAccount)' }
    else {
        $adm = $users | Where-Object { $_.SID -like '*-500' } | Select-Object -First 1
        $gst = $users | Where-Object { $_.SID -like '*-501' } | Select-Object -First 1
        if ($adm) {
            if ($adm.Disabled) { Add-Pass "Built-in Administrator account ($($adm.Name)) is disabled" }
            else { Add-Result $(if ($IsServer) { 'WARN' } else { 'FAIL' }) "Built-in Administrator account ($($adm.Name)) is ENABLED" "Disable-LocalUser -SID $($adm.SID)   # or keep it disabled and use named admin accounts" }
            if ($adm.Name -ieq 'Administrator') { Add-Warn "Built-in Administrator account (RID 500) has not been renamed" "Rename-LocalUser -Name 'Administrator' -NewName '<new_name>'" }
            else { Add-Pass "Built-in Administrator account (RID 500) renamed to '$($adm.Name)'" }
        }
        if ($gst) {
            if ($gst.Disabled) { Add-Pass 'Guest account is disabled' } else { Add-Fail 'Guest account is ENABLED' "Disable-LocalUser -SID $($gst.SID)" }
        }
        $enabled = @($users | Where-Object { -not $_.Disabled })
        Add-Info "Enabled local accounts: $($enabled.Count) ($(($enabled | ForEach-Object { $_.Name }) -join ', '))"
        $nopw = @($enabled | Where-Object { -not $_.PasswordRequired })
        if ($nopw.Count -eq 0) { Add-Pass 'No enabled local accounts with "password not required"' }
        else { Add-Fail "Enabled accounts that do NOT require a password: $(($nopw | ForEach-Object { $_.Name }) -join ', ')" "net user <user> /passwordreq:yes   # or: Set-LocalUser -Name '<user>' -Password (Read-Host -AsSecureString)" }
        $noexp = @($enabled | Where-Object { -not $_.PasswordExpires })
        if ($noexp.Count -eq 0) { Add-Pass 'No enabled local accounts with non-expiring passwords' }
        else { Add-Warn "Enabled accounts with password set to never expire: $(($noexp | ForEach-Object { $_.Name }) -join ', ')" "Set-LocalUser -Name '<user>' -PasswordNeverExpires `$false   # service accounts: use gMSA/LAPS instead" }
    }
} else { Add-Info 'Domain Controller: local SAM account checks skipped (domain accounts must be audited via Active Directory)' }

# Local Administrators group membership
function Get-LocalAdminMembers {
    try { return @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name }) } catch { }
    try {
        $grp = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $lines = @(& net.exe localgroup $grp 2>$null)
        $idx = 0
        for ($k = 0; $k -lt $lines.Count; $k++) { if ($lines[$k] -match '^-{5,}') { $idx = $k + 1; break } }
        return @($lines[$idx..($lines.Count - 1)] | Where-Object { $_.Trim() -and $_ -notmatch 'completed successfully|command completed' } | ForEach-Object { $_.Trim() })
    } catch { return @() }
}
$admins = Get-LocalAdminMembers
if ($admins.Count -gt 0) {
    Add-Info "Administrators group members ($($admins.Count)): $($admins -join ', ')"
    if ($admins.Count -gt 4) { Add-Warn "Administrators group has $($admins.Count) members (more than 4)" 'Review membership; apply least privilege / LAPS / tiered admin model' }
    else { Add-Pass "Administrators group membership is small ($($admins.Count))" }
} else { Add-Warn 'Administrators group membership could not be enumerated' }

# Effective local security policy via secedit (temp export, deleted afterwards)
$SecPol = @{}
$tmpInf = Join-Path $env:TEMP ('secpol_{0}.inf' -f [guid]::NewGuid().ToString('N'))
try {
    & secedit.exe /export /cfg $tmpInf /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    if (Test-Path -LiteralPath $tmpInf) {
        Get-Content -LiteralPath $tmpInf -Encoding Unicode | ForEach-Object {
            if ($_ -match '^\s*([^=\[;]+?)\s*=\s*(.*?)\s*$') { $SecPol[$Matches[1]] = $Matches[2] }
        }
    }
} catch { } finally { Remove-Item -LiteralPath $tmpInf -Force -ErrorAction SilentlyContinue }

function Test-SecPol {
    param([string]$Key, [string]$Op, $Value, [string]$Desc, [string]$Sev = 'FAIL', [string]$Fix = '')
    $raw = $SecPol[$Key]
    if ($null -eq $raw -or $raw -eq '') { Add-Result $Sev "$Desc : $Key not present in effective policy" $Fix; return }
    $expTxt = if ($Op -eq 'range') { "$($Value[0])-$($Value[1])" } elseif ($Op -eq 'le') { "<= $Value" } elseif ($Op -eq 'ge') { ">= $Value" } elseif ($Op -eq 'gem1') { ">= $Value or -1" } else { "$Value" }
    if (Test-Cmp $raw $Op $Value) { Add-Pass "$Desc : $raw (expected: $expTxt)" } else { Add-Result $Sev "$Desc : $raw (expected: $expTxt)" $Fix }
}

if ($SecPol.Count -eq 0) {
    Add-Warn 'secedit export failed - password/lockout policy and user rights could not be verified' 'Run: secedit /export /cfg C:\Temp\secpol.inf'
} else {
    $gpoNote = '(or via GPO: Computer Configuration > Windows Settings > Security Settings > Account Policies)'
    Test-SecPol 'MinimumPasswordLength' 'ge' 14 'Minimum password length'                    'FAIL' "net accounts /minpwlen:14 $gpoNote"
    Test-SecPol 'PasswordComplexity'    'eq' 1  'Password must meet complexity requirements' 'FAIL' "GPO: Password Policy > Password must meet complexity requirements = Enabled"
    Test-SecPol 'MaximumPasswordAge'    'range' @(1, 365) 'Maximum password age (days)'     'WARN' "net accounts /maxpwage:365 $gpoNote"
    Test-SecPol 'MinimumPasswordAge'    'ge' 1  'Minimum password age (days)'               'WARN' "net accounts /minpwage:1 $gpoNote"
    Test-SecPol 'PasswordHistorySize'   'ge' 24 'Password history remembered'               'WARN' "net accounts /uniquepw:24 $gpoNote"
    Test-SecPol 'ClearTextPassword'     'eq' 0  'Store passwords using reversible encryption (must be 0)' 'FAIL' "GPO: Password Policy > Store passwords using reversible encryption = Disabled"
    Test-SecPol 'LockoutBadCount'       'range' @(1, 5) 'Account lockout threshold'         'FAIL' "net accounts /lockoutthreshold:5 $gpoNote"
    Test-SecPol 'ResetLockoutCount'     'ge' 15 'Reset account lockout counter after (min)' 'WARN' "net accounts /lockoutwindow:15 $gpoNote"
    Test-SecPol 'LockoutDuration'       'gem1' 15 'Account lockout duration (min; -1 = admin unlock)' 'WARN' "net accounts /lockoutduration:15 $gpoNote"
    Test-SecPol 'LSAAnonymousNameLookup' 'eq' 0 'Allow anonymous SID/name translation (must be 0)' 'FAIL' 'GPO: Security Options > Network access: Allow anonymous SID/Name translation = Disabled'

    function Get-Right { param([string]$Key) $v = $SecPol[$Key]; if ($v) { @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @() } }
    $dbg = @(Get-Right 'SeDebugPrivilege')
    if (($dbg | Where-Object { $_ -ne '*S-1-5-32-544' }).Count -eq 0) { Add-Pass 'SeDebugPrivilege (debug programs) limited to Administrators' }
    else { Add-Fail "SeDebugPrivilege granted to: $($dbg -join ', ')" 'GPO: User Rights Assignment > Debug programs = Administrators' }
    $tcb = @(Get-Right 'SeTcbPrivilege')
    if ($tcb.Count -eq 0) { Add-Pass 'SeTcbPrivilege (act as part of the OS) granted to no one' } else { Add-Fail "SeTcbPrivilege granted to: $($tcb -join ', ')" 'GPO: User Rights Assignment > Act as part of the operating system = (empty)' }
    $net = @(Get-Right 'SeNetworkLogonRight')
    if (($net | Where-Object { $_ -in '*S-1-1-0', '*S-1-5-32-546' }).Count -eq 0) { Add-Pass 'Network logon right does not include Everyone/Guests' }
    else { Add-Fail "Network logon right includes Everyone/Guests: $($net -join ', ')" 'GPO: User Rights Assignment > Access this computer from the network = Administrators, Authenticated Users' }
    $rdp = @(Get-Right 'SeRemoteInteractiveLogonRight')
    if (($rdp | Where-Object { $_ -in '*S-1-1-0', '*S-1-5-32-546', '*S-1-5-32-545', '*S-1-5-11' }).Count -eq 0) { Add-Pass 'RDP logon right limited to administrative/RDP groups' }
    else { Add-Fail "RDP logon right too broad: $($rdp -join ', ')" 'GPO: User Rights Assignment > Allow log on through Remote Desktop Services = Administrators, Remote Desktop Users' }
    $deny = @(Get-Right 'SeDenyNetworkLogonRight')
    if ($deny -contains '*S-1-5-32-546') { Add-Pass 'Guests are denied network logon' } else { Add-Warn 'Guests are not in "Deny access to this computer from the network"' 'GPO: User Rights Assignment > Deny access to this computer from the network = Guests' }
}

# Security options (registry)
$PolSys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Lsa    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Test-RegTable @(
    @{ Path = $PolSys; Name = 'EnableLUA';                   Value = 1; Desc = 'UAC: Run all administrators in Admin Approval Mode'; Default = $true },
    @{ Path = $PolSys; Name = 'ConsentPromptBehaviorAdmin';  Value = 2; Desc = 'UAC: elevation prompt for admins = consent on secure desktop'; Sev = 'WARN' },
    @{ Path = $PolSys; Name = 'ConsentPromptBehaviorUser';   Value = 0; Desc = 'UAC: elevation prompt for standard users = automatically deny'; Sev = 'WARN' },
    @{ Path = $PolSys; Name = 'PromptOnSecureDesktop';       Value = 1; Desc = 'UAC: switch to the secure desktop when prompting'; Default = $true },
    @{ Path = $PolSys; Name = 'FilterAdministratorToken';    Value = 1; Desc = 'UAC: Admin Approval Mode for built-in Administrator'; Sev = 'WARN' },
    @{ Path = $PolSys; Name = 'LocalAccountTokenFilterPolicy'; Value = 0; Desc = 'Remote UAC token filtering for local accounts (pass-the-hash mitigation)'; Default = $true },
    @{ Path = $PolSys; Name = 'DontDisplayLastUserName';     Value = 1; Desc = 'Interactive logon: do not display last signed-in user' },
    @{ Path = $PolSys; Name = 'InactivityTimeoutSecs';       Value = @(1, 900); Op = 'range'; Desc = 'Interactive logon: machine inactivity limit (sec)' },
    @{ Path = $Lsa; Name = 'LimitBlankPasswordUse';  Value = 1; Desc = 'Accounts: limit local blank-password use to console logon'; Default = $true },
    @{ Path = $Lsa; Name = 'NoLMHash';               Value = 1; Desc = 'Do not store LAN Manager hash'; Default = $true },
    @{ Path = $Lsa; Name = 'LmCompatibilityLevel';   Value = 5; Desc = 'LAN Manager authentication level = NTLMv2 only, refuse LM/NTLM' },
    @{ Path = $Lsa; Name = 'RestrictAnonymousSAM';   Value = 1; Desc = 'Do not allow anonymous enumeration of SAM accounts'; Default = $true },
    @{ Path = $Lsa; Name = 'RestrictAnonymous';      Value = 1; Desc = 'Do not allow anonymous enumeration of SAM accounts and shares'; Sev = 'WARN' },
    @{ Path = $Lsa; Name = 'EveryoneIncludesAnonymous'; Value = 0; Desc = 'Let Everyone permissions apply to anonymous users (must be 0)'; Default = $true },
    @{ Path = "$Lsa\MSV1_0"; Name = 'NTLMMinClientSec'; Value = 537395200; Desc = 'NTLM SSP client minimum session security (NTLMv2 + 128-bit)'; Sev = 'WARN' },
    @{ Path = "$Lsa\MSV1_0"; Name = 'NTLMMinServerSec'; Value = 537395200; Desc = 'NTLM SSP server minimum session security (NTLMv2 + 128-bit)'; Sev = 'WARN' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal';     Value = 1; Desc = 'Secure channel: always encrypt or sign'; Default = $true },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel';     Value = 1; Desc = 'Secure channel: encrypt when possible'; Default = $true },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel';     Value = 1; Desc = 'Secure channel: sign when possible'; Default = $true },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey';      Value = 1; Desc = 'Secure channel: require strong (Windows 2000+) session key'; Default = $true },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'DisablePasswordChange'; Value = 0; Desc = 'Machine account password changes are not disabled'; Default = $true },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun';          Value = 1;   Desc = 'AutoRun: default behaviour = do not execute autorun commands' },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; Value = 255; Desc = 'AutoRun disabled on all drives' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Value = 0; Desc = 'Windows Installer: Always install with elevated privileges must be off'; Default = $true },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'AutoAdminLogon'; Value = 0; Desc = 'Automatic administrative logon disabled'; Default = $true }
)
if ($IsDomainJoined -and -not $IsServer) {
    Test-RegTable @( @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'CachedLogonsCount'; Value = 4; Op = 'le'; Desc = 'Interactive logon: cached domain logons'; Sev = 'WARN' } )
}

if ($null -ne (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword')) {
    Add-Fail 'Plaintext DefaultPassword is stored in Winlogon registry key (autologon credential)' "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword"
} else { Add-Pass 'No plaintext DefaultPassword in Winlogon registry key' }

$legalText = Get-RegValue $PolSys 'legalnoticetext'
if ([string]::IsNullOrWhiteSpace([string]$legalText)) { Add-Warn 'Interactive logon: no legal notice (message text) configured' (New-RegFix $PolSys 'legalnoticetext' '"Authorized use only. Activity is monitored."' 'String') }
else { Add-Pass 'Interactive logon: legal notice text is configured' }

# Domain Controller specific
if ($IsDC) {
    $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    Test-RegTable @(
        @{ Path = $ntds; Name = 'LDAPServerIntegrity'; Value = 2; Desc = 'DC: LDAP server signing requirements = Require signing' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LdapEnforceChannelBinding'; Value = 1; Op = 'ge'; Desc = 'DC: LDAP channel binding token policy (1 = when supported, 2 = always)'; Sev = 'WARN' }
    )
    if ($null -ne (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'VulnerableChannelAllowList')) {
        Add-Fail 'DC: Netlogon VulnerableChannelAllowList is configured (Zerologon exceptions)' "Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name VulnerableChannelAllowList"
    } else { Add-Pass 'DC: no Netlogon vulnerable-channel allow list configured' }
}

# File system ACL hygiene (equivalent of the permission checks in the Linux script)
function Test-WeakAcl {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $weak = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')     # Everyone, Authenticated Users, BUILTIN\Users
    $mask = [int][System.Security.AccessControl.FileSystemRights]'WriteData,AppendData,Delete,ChangePermissions,TakeOwnership'
    $bad = @()
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($r in $acl.Access) {
            if ("$($r.AccessControlType)" -ne 'Allow') { continue }
            if ($r.InheritanceFlags -ne 'None' -and "$($r.PropagationFlags)" -match 'InheritOnly') { continue }
            $sid = Get-SidString $r.IdentityReference
            if ($weak -notcontains $sid) { continue }
            if (([int]$r.FileSystemRights -band $mask) -ne 0) { $bad += "$($r.IdentityReference):$($r.FileSystemRights)" }
        }
    } catch { return $null }
    return , $bad
}
$sr = $env:SystemRoot
foreach ($p in @($sr, "$sr\System32", "$sr\System32\config", "$sr\System32\config\SAM", "$sr\System32\drivers\etc\hosts", $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if (-not $p) { continue }
    $r = Test-WeakAcl $p
    if ($null -eq $r) { if (Test-Path -LiteralPath $p) { Add-Warn "${p}: ACL could not be read" }; continue }
    if ($r.Count -eq 0) { Add-Pass "${p}: no write/modify rights for Everyone / Users / Authenticated Users" }
    else { Add-Fail "${p}: weak ACL - $($r -join '; ')" "icacls `"$p`" /remove:g *S-1-1-0 *S-1-5-11 *S-1-5-32-545   # then re-grant Read & Execute where required" }
}

# OpenSSH server (if present) - same checks as the Linux sshd audit
$sshdCfg = Join-Path $env:ProgramData 'ssh\sshd_config'
if (Test-Path -LiteralPath $sshdCfg) {
    Add-Info "OpenSSH server configuration found: $sshdCfg"
    $cfgLines = @(Get-Content -LiteralPath $sshdCfg | Where-Object { $_ -match '^\s*[A-Za-z]' })
    function Get-SshdOpt { param([string]$Key) $m = $cfgLines | Where-Object { $_ -match "^\s*$Key\s+(.+?)\s*$" } | Select-Object -First 1; if ($m) { ($m -replace "^\s*$Key\s+", '').Trim() } else { $null } }
    $pa = Get-SshdOpt 'PasswordAuthentication'
    if ($pa -eq 'no') { Add-Pass 'sshd: PasswordAuthentication no' } else { Add-Warn "sshd: PasswordAuthentication is not 'no' (current: $(if ($pa) { $pa } else { 'default yes' }))" "(Get-Content '$sshdCfg') -replace '^#?PasswordAuthentication.*','PasswordAuthentication no' | Set-Content '$sshdCfg'; Restart-Service sshd" }
    $pe = Get-SshdOpt 'PermitEmptyPasswords'
    if (-not $pe -or $pe -eq 'no') { Add-Pass 'sshd: PermitEmptyPasswords no / unset' } else { Add-Fail "sshd: PermitEmptyPasswords = $pe" 'Set PermitEmptyPasswords no in sshd_config' }
    $mt = Get-SshdOpt 'MaxAuthTries'
    if ($mt -and [int]$mt -le 4) { Add-Pass "sshd: MaxAuthTries = $mt (<=4)" } else { Add-Warn "sshd: MaxAuthTries = '$(if ($mt) { $mt } else { 'unset (default 6)' })'" 'Set MaxAuthTries 4 in sshd_config' }
    $ci = Get-SshdOpt 'Ciphers'
    if ($ci) { if ($ci -match '3des|arcfour|blowfish|cbc') { Add-Fail "sshd: weak ciphers enabled: $ci" 'Use Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' } else { Add-Pass "sshd: ciphers defined explicitly, no weak algorithms: $ci" } }
}

# ============================================================================
# 5. SERVICES, UPDATES, AND SYSTEM INTEGRITY
# ============================================================================

Write-Section '5. SERVICES, UPDATES, OS LIFECYCLE, AND SYSTEM INTEGRITY'

# OS lifecycle (end-of-support dates - edit here when Microsoft publishes changes)
# build -> @(Home/Pro end date, Enterprise/Education end date)
$LcClient = @{
    19045 = @('2025-10-14', '2025-10-14'); 22000 = @('2023-10-10', '2024-10-08'); 22621 = @('2024-10-08', '2025-10-14')
    22631 = @('2025-11-11', '2026-11-10'); 26100 = @('2026-10-13', '2027-10-12'); 26200 = @('2027-10-12', '2028-10-10') }
$LcServer = @{
    7601 = '2020-01-14'; 9200 = '2023-10-10'; 9600 = '2023-10-10'; 14393 = '2027-01-12'
    17763 = '2029-01-09'; 20348 = '2031-10-14'; 26100 = '2034-10-10' }
$isLtsc = $EditionId -match 'EnterpriseS|IoTEnterpriseS'
$eosText = $null; $eosNote = ''
if ($isLtsc) { Add-Info "LTSC/LTSB edition ($EditionId, build $Build) - verify lifecycle at https://learn.microsoft.com/lifecycle" }
elseif ($IsServer -and $LcServer.ContainsKey($Build)) { $eosText = $LcServer[$Build] }
elseif (-not $IsServer -and $LcClient.ContainsKey($Build)) {
    $isEnt = $EditionId -match 'Enterprise|Education'
    $eosText = $LcClient[$Build][[int]$isEnt]
    if ($Build -eq 19045) { $eosNote = ' (Windows 10 - only devices enrolled in Extended Security Updates still receive patches)' }
} elseif (-not $IsServer -and $Build -lt 19045) { $eosText = '2000-01-01' }
elseif ($Build -lt 7601 -or ($IsServer -and $Build -lt 14393)) { $eosText = '2000-01-01' }
else { Add-Info "OS build $Build is not in the lifecycle table - verify support status manually" }
if ($eosText) {
    $eos = [datetime]::ParseExact($eosText, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $days = [int](($eos - $RunTs.Date).TotalDays)
    if ($days -lt 0) { Add-Fail "OS build $Build reached end of support on $eosText$eosNote" 'Upgrade to a supported Windows release' }
    elseif ($days -le 180) { Add-Warn "OS build $Build end of support in $days days ($eosText)" 'Plan upgrade to a supported Windows release' }
    else { Add-Pass "OS build $Build is in support until $eosText" }
}

# Legacy / insecure services
$svcChecks = @(
    @{ N = 'TlntSvr';    D = 'Telnet Server';               S = 'FAIL' },
    @{ N = 'simptcp';    D = 'Simple TCP/IP Services';      S = 'FAIL' },
    @{ N = 'ftpsvc';     D = 'IIS FTP Server';              S = 'WARN' },
    @{ N = 'SNMP';       D = 'SNMP Service';                S = 'WARN' },
    @{ N = 'RemoteRegistry'; D = 'Remote Registry';         S = 'WARN' },
    @{ N = 'SSDPSRV';    D = 'SSDP Discovery';              S = 'WARN' },
    @{ N = 'upnphost';   D = 'UPnP Device Host';            S = 'WARN' },
    @{ N = 'WebClient';  D = 'WebClient (WebDAV)';          S = 'WARN' },
    @{ N = 'lltdsvc';    D = 'Link-Layer Topology Discovery Mapper'; S = 'WARN' },
    @{ N = 'RpcLocator'; D = 'Remote Procedure Call Locator'; S = 'WARN' },
    @{ N = 'icssvc';     D = 'Windows Mobile Hotspot Service'; S = 'WARN' }
)
if ($IsServer) { $svcChecks += @{ N = 'Spooler'; D = 'Print Spooler'; S = $(if ($IsDC) { 'FAIL' } else { 'WARN' }) } }
else { foreach ($x in 'XblAuthManager', 'XblGameSave', 'XboxGipSvc', 'XboxNetApiSvc') { $svcChecks += @{ N = $x; D = "Xbox service ($x)"; S = 'WARN' } } }
$foundInsecure = 0
foreach ($c in $svcChecks) {
    $s = Get-Service -Name $c.N -ErrorAction SilentlyContinue
    if ($s -and ($s.Status -eq 'Running' -or "$($s.StartType)" -eq 'Automatic')) {
        $foundInsecure++
        Add-Result $c.S "Insecure/unnecessary service active: $($c.D) (status=$($s.Status), start=$($s.StartType))" "Stop-Service $($c.N) -Force; Set-Service $($c.N) -StartupType Disabled"
    }
}
if ($foundInsecure -eq 0) { Add-Pass 'No active insecure/legacy services (Telnet/SNMP/RemoteRegistry/SSDP/WebClient/...) detected' }

# Unquoted service paths
$unq = @()
foreach ($sv in @(Get-CimInstance Win32_Service)) {
    $pn = [string]$sv.PathName
    if ($pn -and $pn -notmatch '^\s*"' -and $pn -match '^\s*(?<exe>.+?\.exe)(\s|$)') { if ($Matches['exe'] -match '\s') { $unq += "$($sv.Name) => $pn" } }
}
if ($unq.Count -eq 0) { Add-Pass 'No services with unquoted executable paths containing spaces' }
else { Add-Fail "Services with unquoted paths (privilege-escalation risk): $($unq -join ' | ')" 'sc.exe config <service> binPath= "\"C:\Full Path\service.exe\" <args>"' }

# Optional Windows features
foreach ($f in @(@{ N = 'SMB1Protocol'; S = 'FAIL' }, @{ N = 'TelnetClient'; S = 'WARN' }, @{ N = 'TFTP'; S = 'WARN' },
                 @{ N = 'MicrosoftWindowsPowerShellV2Root'; S = 'WARN' })) {
    $feat = Get-WindowsOptionalFeature -Online -FeatureName $f.N -ErrorAction SilentlyContinue
    if ($feat -and "$($feat.State)" -eq 'Enabled') { Add-Result $f.S "Legacy Windows feature enabled: $($f.N)" "Disable-WindowsOptionalFeature -Online -FeatureName $($f.N) -NoRestart" }
    elseif ($feat) { Add-Pass "Legacy Windows feature not enabled: $($f.N)" }
}

# System integrity (equivalent of debsums)
$health = Repair-WindowsImage -Online -CheckHealth -ErrorAction SilentlyContinue
if ($health) {
    if ("$($health.ImageHealthState)" -eq 'Healthy') { Add-Pass 'Component store health (DISM CheckHealth): Healthy' }
    else { Add-Fail "Component store health (DISM CheckHealth): $($health.ImageHealthState)" 'DISM /Online /Cleanup-Image /RestoreHealth' }
} else { Add-Warn 'DISM CheckHealth could not be executed' 'Run: DISM /Online /Cleanup-Image /CheckHealth' }
if ($DeepScan) {
    Add-Info 'Running sfc /verifyonly (this may take several minutes)...'
    $sfc = (& sfc.exe /verifyonly 2>&1 | Out-String) -replace "`0", ''
    if ($sfc -match 'did not find any integrity violations') { Add-Pass 'System File Checker: no integrity violations' }
    elseif ($sfc -match 'found integrity violations') { Add-Fail 'System File Checker found integrity violations' 'sfc /scannow   # then DISM /Online /Cleanup-Image /RestoreHealth; review CBS.log' }
    else { Add-Warn 'System File Checker result could not be interpreted' 'Review %windir%\Logs\CBS\CBS.log' }
} else { Add-Info 'sfc /verifyonly skipped (use -DeepScan for full system file verification)' }

# Updates
$wu = Get-Service -Name wuauserv
if ($wu -and "$($wu.StartType)" -eq 'Disabled') { Add-Fail 'Windows Update service (wuauserv) is DISABLED' 'Set-Service wuauserv -StartupType Manual' }
else { Add-Pass 'Windows Update service is not disabled' }
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$lastUpdId = $null; $lastUpdDate = $null
if ($hf) { $lastUpdId = $hf.HotFixID; $lastUpdDate = [datetime]$hf.InstalledOn }
else {
    # Fallback: Windows Update Agent history (Operation=1 installation, ResultCode=2 succeeded)
    try {
        $hs = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $hist = @($hs.QueryHistory(0, [int]$hs.GetTotalHistoryCount()) | Where-Object { $_.Operation -eq 1 -and $_.ResultCode -eq 2 } | Sort-Object Date -Descending | Select-Object -First 1)
        if ($hist.Count -gt 0) { $lastUpdId = ($hist[0].Title -replace '^(.{0,60}).*$', '$1'); $lastUpdDate = [datetime]$hist[0].Date }
    } catch { }
}
if ($lastUpdDate) {
    $age = [int]($RunTs - $lastUpdDate).TotalDays
    if ($age -le 45) { Add-Pass "Latest installed update $lastUpdId is $age days old" }
    elseif ($age -le 90) { Add-Warn "Latest installed update $lastUpdId is $age days old (> 45)" 'Install the latest cumulative update (Windows Update / WSUS / Intune)' }
    else { Add-Fail "Latest installed update $lastUpdId is $age days old (> 90)" 'Install the latest cumulative update immediately' }
} else { Add-Warn 'No installed hotfix date could be determined (Get-HotFix)' }
if (-not $SkipUpdateSearch) {
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $res  = $sess.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $cnt  = [int]$res.Updates.Count
        $sec  = @($res.Updates | Where-Object { $_.MsrcSeverity -in 'Critical', 'Important' }).Count
        if ($cnt -eq 0) { Add-Pass 'System is fully updated (Windows Update Agent search)' }
        else { Add-Warn "Pending updates available: $cnt (Critical/Important: $sec)" 'Install-WindowsUpdate (PSWindowsUpdate) or Settings > Windows Update' }
    } catch { Add-Warn 'Windows Update Agent search failed (no WU/WSUS connectivity?)' 'Re-run with -SkipUpdateSearch or check update source' }
} else { Add-Info 'Pending update search skipped (-SkipUpdateSearch)' }
$pend = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pend += 'CBS' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pend += 'WindowsUpdate' }
if ($pend.Count -gt 0) { Add-Warn "Pending reboot detected ($($pend -join ', '))" 'Restart the system to complete pending updates' } else { Add-Pass 'No pending reboot' }

# ============================================================================
# 6. BOOT SECURITY, DISK ENCRYPTION, ANTI-MALWARE, AND APPLICATION CONTROL
# ============================================================================

Write-Section '6. SECURE BOOT, TPM, BITLOCKER, DEFENDER, AND APPLICATION CONTROL'

try {
    if (Confirm-SecureBootUEFI -ErrorAction Stop) { Add-Pass 'Secure Boot is enabled' }
    else { Add-Fail 'Secure Boot is DISABLED' 'Enable Secure Boot in UEFI firmware setup' }
} catch { Add-Warn 'Secure Boot state cannot be determined (Legacy BIOS boot or unsupported platform)' 'Convert to UEFI/GPT (mbr2gpt /convert /allowFullOS) and enable Secure Boot' }

$tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($tpm -and $tpm.TpmPresent) {
    $tv = (Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
    if ($tpm.TpmReady) { Add-Pass "TPM present and ready (spec: $tv)" } else { Add-Warn "TPM present but not ready (spec: $tv)" 'Initialize-Tpm' }
    if ($tv -and $tv -match '^1\.2') { Add-Warn 'TPM 1.2 detected - TPM 2.0 recommended' }
} else { Add-Result $(if ($IsServer) { 'WARN' } else { 'FAIL' }) 'No TPM detected (or TPM disabled in firmware)' 'Enable TPM/PTT in firmware; for VMs use vTPM' }

$sysDrive = $env:SystemDrive
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    $bl = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction SilentlyContinue
    if ($bl -and "$($bl.ProtectionStatus)" -in 'On', '1') { Add-Pass "BitLocker protection is ON for $sysDrive ($($bl.EncryptionMethod), $($bl.VolumeStatus))" }
    else { Add-Result $(if ($IsServer) { 'WARN' } else { 'FAIL' }) "BitLocker protection is not active on $sysDrive (status: $(if ($bl) { $bl.ProtectionStatus } else { 'unknown' }))" "Enable-BitLocker -MountPoint $sysDrive -EncryptionMethod XtsAes256 -TpmProtector" }
} else { Add-Result $(if ($IsServer) { 'WARN' } else { 'FAIL' }) 'BitLocker cmdlets unavailable (feature not installed)' 'Install-WindowsFeature BitLocker (Server) / enable BitLocker (client)' }

$bcd = (& bcdedit.exe /enum '{current}' 2>$null | Out-String)
if ($bcd) {
    $bad = 0
    foreach ($k in 'testsigning', 'nointegritychecks', 'debug') {
        if ($bcd -match "(?im)^\s*$k\s+Yes") { $bad++; Add-Fail "Boot configuration: $k is ENABLED" "bcdedit /set '{current}' $k off" }
    }
    if ($bad -eq 0) { Add-Pass 'Boot configuration: test-signing / integrity-check bypass / kernel debug are off' }
} else { Add-Warn 'bcdedit output unavailable - boot configuration not verified' }

# Microsoft Defender / anti-malware
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) {
    if ("$($mp.AMRunningMode)" -match 'Passive') { Add-Info "Microsoft Defender runs in $($mp.AMRunningMode) (third-party AV primary)" }
    elseif ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) { Add-Pass 'Microsoft Defender antivirus and real-time protection are enabled' }
    else { Add-Fail "Microsoft Defender not fully active (AV=$($mp.AntivirusEnabled), RealTime=$($mp.RealTimeProtectionEnabled))" 'Set-MpPreference -DisableRealtimeMonitoring $false; Start-Service WinDefend' }
    if ($mp.AntivirusSignatureAge -le 7) { Add-Pass "Defender signatures are $($mp.AntivirusSignatureAge) days old" }
    else { Add-Warn "Defender signatures are $($mp.AntivirusSignatureAge) days old (> 7)" 'Update-MpSignature' }
    if ($null -ne $mp.IsTamperProtected) { if ($mp.IsTamperProtected) { Add-Pass 'Defender Tamper Protection is enabled' } else { Add-Warn 'Defender Tamper Protection is disabled' 'Enable Tamper Protection in Windows Security or Intune/MDE' } }
    if ($mp.BehaviorMonitorEnabled) { Add-Pass 'Defender behavior monitoring is enabled' } else { Add-Warn 'Defender behavior monitoring is disabled' 'Set-MpPreference -DisableBehaviorMonitoring $false' }
    if ($mp.IoavProtectionEnabled)  { Add-Pass 'Defender download/attachment scanning (IOAV) is enabled' } else { Add-Warn 'Defender IOAV protection is disabled' 'Set-MpPreference -DisableIOAVProtection $false' }
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($pref) {
        if ($pref.PUAProtection -eq 1) { Add-Pass 'Defender PUA protection is enabled' } else { Add-Warn "Defender PUA protection = $($pref.PUAProtection) (expected 1)" 'Set-MpPreference -PUAProtection Enabled' }
        if ($pref.EnableNetworkProtection -eq 1) { Add-Pass 'Defender Network Protection is in block mode' } else { Add-Warn "Defender Network Protection = $($pref.EnableNetworkProtection) (expected 1)" 'Set-MpPreference -EnableNetworkProtection Enabled' }
        $asrIds = @($pref.AttackSurfaceReductionRules_Ids); $asrAct = @($pref.AttackSurfaceReductionRules_Actions)
        $asrBlock = 0; for ($i = 0; $i -lt $asrIds.Count; $i++) { if ($asrAct[$i] -eq 1) { $asrBlock++ } }
        if ($asrBlock -gt 0) { Add-Pass "Attack Surface Reduction: $asrBlock rules in Block mode" } else { Add-Warn 'Attack Surface Reduction: no rules in Block mode (Level 2)' "Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled" }
        $exN = @($pref.ExclusionPath).Count + @($pref.ExclusionProcess).Count + @($pref.ExclusionExtension).Count
        Add-Info "Defender exclusions configured: paths=$(@($pref.ExclusionPath).Count), processes=$(@($pref.ExclusionProcess).Count), extensions=$(@($pref.ExclusionExtension).Count)"
        $wide = @($pref.ExclusionPath | Where-Object { $_ -match '^[A-Za-z]:\\?\*?$' })
        if ($wide.Count -gt 0) { Add-Fail "Defender exclusion covers an entire drive: $($wide -join ', ')" 'Remove-MpPreference -ExclusionPath <path>' }
    }
} else {
    $av = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { $_.displayName })
    if ($av.Count -gt 0) { Add-Info "Microsoft Defender cmdlets unavailable; registered AV product(s): $($av -join ', ')" }
    else { Add-Fail 'No active anti-malware product detected (Defender unavailable, no third-party AV registered)' 'Install-WindowsFeature Windows-Defender (Server) / enable Microsoft Defender or deploy an EDR' }
}

# Application control (equivalent of AppArmor / SELinux)
$dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$wdac = if ($dg) { [int]$dg.CodeIntegrityPolicyEnforcementStatus } else { 0 }
$alRules = 0
try { $ap = Get-AppLockerPolicy -Effective -ErrorAction Stop; foreach ($rc in $ap.RuleCollections) { $alRules += @($rc).Count } } catch { }
$appId = Get-Service -Name AppIDSvc
if ($wdac -eq 2) { Add-Pass 'WDAC (App Control for Business) policy is enforced' }
elseif ($alRules -gt 0 -and $appId -and $appId.Status -eq 'Running') { Add-Pass "AppLocker is active ($alRules effective rules, AppIDSvc running)" }
elseif ($wdac -eq 1 -or $alRules -gt 0) { Add-Warn 'Application control is configured but only in audit mode / AppIDSvc not running' 'Move WDAC/AppLocker policy to enforced mode and start AppIDSvc' }
else { Add-Warn 'No application control (WDAC / AppLocker) enforced (Level 2)' 'Deploy WDAC or AppLocker policy (start in audit mode)' }

# ============================================================================
# 7. EXPLOIT MITIGATIONS AND CREDENTIAL PROTECTION
# ============================================================================

Write-Section '7. EXPLOIT MITIGATIONS, VBS/HVCI, AND CREDENTIAL PROTECTION'

switch ([int]$OsCim.DataExecutionPrevention_SupportPolicy) {
    0 { Add-Fail 'DEP is fully disabled (AlwaysOff)' "bcdedit /set nx OptOut" }
    1 { Add-Pass 'DEP policy: AlwaysOn' }
    2 { Add-Warn 'DEP policy: OptIn (protects essential Windows programs only)' "bcdedit /set nx OptOut" }
    3 { Add-Pass 'DEP policy: OptOut (all programs except exclusions)' }
}
$mi = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'MoveImages'
if ($mi -eq 0) { Add-Fail 'ASLR image relocation is disabled (MoveImages = 0)' (New-RegFix 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'MoveImages' 4294967295) }
else { Add-Pass 'ASLR image relocation is not disabled' }
if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation') -eq 1) { Add-Fail 'SEHOP is disabled (DisableExceptionChainValidation = 1)' (New-RegFix 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 0) }
else { Add-Pass 'SEHOP is not disabled' }

$pm = $null
try { $pm = Get-ProcessMitigation -System -ErrorAction Stop } catch { }
if ($pm) {
    foreach ($m in @(@{ N = 'DEP'; V = "$($pm.DEP.Enable)" }, @{ N = 'SEHOP'; V = "$($pm.SEHOP.Enable)" }, @{ N = 'ASLR BottomUp'; V = "$($pm.ASLR.BottomUp)" },
                     @{ N = 'ASLR HighEntropy'; V = "$($pm.ASLR.HighEntropy)" }, @{ N = 'Control Flow Guard'; V = "$($pm.CFG.Enable)" })) {
        switch ($m.V) {
            'ON'  { Add-Pass "System exploit mitigation $($m.N): ON" }
            'OFF' { Add-Fail "System exploit mitigation $($m.N): OFF" "Set-ProcessMitigation -System -Enable $(($m.N -replace 'ASLR ', '' -replace 'Control Flow Guard', 'CFG' -replace ' ', ''))" }
            default { Add-Info "System exploit mitigation $($m.N): $($m.V) (OS default)" }
        }
    }
} else { Add-Info 'Get-ProcessMitigation unavailable on this OS build - exploit mitigation settings not enumerated' }

if ($dg) {
    $running = @($dg.SecurityServicesRunning)
    if ([int]$dg.VirtualizationBasedSecurityStatus -eq 2) { Add-Pass 'Virtualization-based security (VBS) is running' }
    else { Add-Warn 'Virtualization-based security (VBS) is not running (Level 2)' 'Enable VBS via GPO: Computer Configuration > Administrative Templates > System > Device Guard' }
    if ($running -contains 2) { Add-Pass 'HVCI (memory integrity) is running' } else { Add-Warn 'HVCI (memory integrity) is not running (Level 2)' 'Enable Memory integrity in Windows Security > Device security > Core isolation' }
    if ($running -contains 1) { Add-Pass 'Credential Guard is running' } else { Add-Warn 'Credential Guard is not running (Level 2)' 'Enable via GPO: Turn On Virtualization Based Security > Credential Guard Configuration' }
} else { Add-Info 'Win32_DeviceGuard not available - VBS/HVCI/Credential Guard state unknown' }

Test-RegTable @(
    @{ Path = $Lsa; Name = 'RunAsPPL'; Value = 1; Op = 'ge'; Desc = 'LSA protection (LSASS as Protected Process Light)'; Sev = 'WARN' },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Value = 0; Desc = 'WDigest does not cache cleartext credentials'; Default = $true },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'; Name = 'VulnerableDriverBlocklistEnable'; Value = 1; Desc = 'Microsoft vulnerable driver blocklist'; Sev = 'WARN'; Default = ($Build -ge 22621) }
)

# ============================================================================
# 8. AUDIT SUMMARY
# ============================================================================

Write-Section '8. AUDIT SUMMARY'

$TotalChecks = $script:CountPass + $script:CountWarn + $script:CountFail
Write-Raw "  PASS : $($script:CountPass)" 'Green'
Write-Raw "  WARN : $($script:CountWarn)" 'Yellow'
Write-Raw "  FAIL : $($script:CountFail)" 'Red'
Write-Raw "  INFO : $($script:CountInfo)"
Write-Raw "  Total classified checks: $TotalChecks"
Write-Raw ''
if ($script:CountFail -gt 0) {
    Write-Raw '  RESULT: Critical non-compliances detected (FAIL). Remediation required.' 'Red'; $ExitCode = 2
} elseif ($script:CountWarn -gt 0) {
    Write-Raw '  RESULT: No critical non-compliances, but warnings exist (WARN).' 'Yellow'; $ExitCode = 1
} else {
    Write-Raw '  RESULT: All checks passed successfully.' 'Green'; $ExitCode = 0
}

# ============================================================================
# 9. SAVE TEXT / JSON REPORTS
# ============================================================================

$saveOk = $true
try {
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction Stop | Out-Null }
    $hdr = @('===================================================================',
             ' Security Audit Report (CIS / ISO 27001) - Windows',
             " Host: $HostFqdn  Date: $RunTsText",
             '===================================================================')
    Add-Content -LiteralPath $ReportFile -Value ($hdr + $script:ReportLines) -Encoding UTF8 -ErrorAction Stop
    Write-Raw ''
    Write-Raw "Text report saved/updated : $ReportFile"
} catch { $saveOk = $false; Write-Raw "[WARN] Failed to write to ${ReportFile}: $($_.Exception.Message)" 'Yellow' }

try {
    [pscustomobject]@{
        host = $HostFqdn; os = $OsInfo; build = $BuildInfo; timestamp = $RunTs.ToString('o'); version = $script:Version
        summary = [pscustomobject]@{ pass = $script:CountPass; warn = $script:CountWarn; fail = $script:CountFail; info = $script:CountInfo }
        findings = @($script:Findings)
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $JsonReportFile -Encoding UTF8 -ErrorAction Stop
    Write-Raw "JSON results saved        : $JsonReportFile"
} catch { Write-Raw "[WARN] Failed to write JSON results: $($_.Exception.Message)" 'Yellow' }

# ============================================================================
# 10. GENERATE HTML REPORT
# ============================================================================

function New-HtmlReport {
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $total = $script:CountPass + $script:CountWarn + $script:CountFail
    $score = 0
    if ($total -gt 0) { $score = [int][math]::Floor(($script:CountPass * 100) / $total) }

    $statusClass = 'status-pass'; $statusText = 'Compliant'
    if ($script:CountFail -gt 0)     { $statusClass = 'status-fail'; $statusText = 'Immediate Remediation Required' }
    elseif ($script:CountWarn -gt 0) { $statusClass = 'status-warn'; $statusText = 'Requires Attention' }

    $hostEsc = & $enc $HostFqdn; $osEsc = & $enc $OsInfo; $buildEsc = & $enc $BuildInfo
    $uptimeEsc = & $enc $UptimeInfo; $tsEsc = & $enc $RunTsText; $auditorEsc = & $enc $script:AuditorName

    $head = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit &mdash; $hostEsc</title>
<style>
:root {
  --bg-main: #0b0f19;
  --bg-card: #151c2c;
  --bg-hover: #1e293b;
  --border-color: #2e3a52;
  --text-main: #f1f5f9;
  --text-muted: #94a3b8;

  --pass-color: #10b981;
  --pass-bg: rgba(16, 185, 129, 0.12);
  --warn-color: #f59e0b;
  --warn-bg: rgba(245, 158, 11, 0.12);
  --fail-color: #ef4444;
  --fail-bg: rgba(239, 68, 68, 0.12);
  --info-color: #3b82f6;
  --info-bg: rgba(59, 130, 246, 0.12);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background-color: var(--bg-main);
  color: var(--text-main);
  line-height: 1.5;
  padding: 30px 20px;
}

.container {
  max-width: 1280px;
  margin: 0 auto;
}

/* Header UI */
.header-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 28px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 20px;
}

.header-title h1 {
  font-size: 24px;
  font-weight: 700;
  margin-bottom: 6px;
  letter-spacing: -0.02em;
}

.header-title p {
  color: var(--text-muted);
  font-size: 14px;
}

.status-tag {
  display: inline-block;
  padding: 6px 14px;
  border-radius: 9999px;
  font-size: 13px;
  font-weight: 600;
}
.status-pass { background: var(--pass-bg); color: var(--pass-color); border: 1px solid var(--pass-color); }
.status-warn { background: var(--warn-bg); color: var(--warn-color); border: 1px solid var(--warn-color); }
.status-fail { background: var(--fail-bg); color: var(--fail-color); border: 1px solid var(--fail-color); }

/* Executive Grid & Score Ring */
.dashboard-grid {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 24px;
  margin-bottom: 24px;
}

@media (max-width: 900px) {
  .dashboard-grid { grid-template-columns: 1fr; }
}

.score-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
}

.score-ring {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  background: conic-gradient(var(--pass-color) $($score)%, var(--border-color) 0);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 12px;
  position: relative;
}

.score-ring-inner {
  width: 96px;
  height: 96px;
  border-radius: 50%;
  background: var(--bg-card);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 26px;
  font-weight: 800;
}

.kpi-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
}

.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  flex-direction: column;
}

.kpi-title {
  color: var(--text-muted);
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 8px;
  text-transform: uppercase;
}

.kpi-value {
  font-size: 32px;
  font-weight: 700;
}

.kpi-card.pass .kpi-value { color: var(--pass-color); }
.kpi-card.warn .kpi-value { color: var(--warn-color); }
.kpi-card.fail .kpi-value { color: var(--fail-color); }
.kpi-card.info .kpi-value { color: var(--info-color); }

/* System Metadata Box */
.meta-grid {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 24px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  font-size: 13px;
}

.meta-item strong {
  display: block;
  color: var(--text-muted);
  font-size: 11px;
  text-transform: uppercase;
  margin-bottom: 2px;
}

/* Controls & Filter Bar */
.filter-bar {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
}

.filter-chips {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.chip {
  background: var(--bg-main);
  border: 1px solid var(--border-color);
  color: var(--text-muted);
  padding: 6px 14px;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.chip:hover, .chip.active {
  background: var(--bg-hover);
  color: var(--text-main);
  border-color: var(--text-muted);
}

.search-input {
  background: var(--bg-main);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 13px;
  outline: none;
  min-width: 240px;
}

/* Audit Results Table */
.results-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  overflow: hidden;
}

table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}

th {
  background: #0f1523;
  color: var(--text-muted);
  font-size: 12px;
  text-transform: uppercase;
  padding: 14px 18px;
  border-bottom: 1px solid var(--border-color);
}

th:first-child,
td:first-child {
  text-align: center;
  width: 110px;
}

td {
  padding: 16px 18px;
  border-bottom: 1px solid var(--border-color);
  font-size: 14px;
  vertical-align: middle;
}

tr:last-child td { border-bottom: none; }
tr:hover { background: var(--bg-hover); }

.badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  line-height: 1;
}

.badge-PASS { background: var(--pass-bg); color: var(--pass-color); border: 1px solid var(--pass-color); }
.badge-WARN { background: var(--warn-bg); color: var(--warn-color); border: 1px solid var(--warn-color); }
.badge-FAIL { background: var(--fail-bg); color: var(--fail-color); border: 1px solid var(--fail-color); }
.badge-INFO { background: var(--info-bg); color: var(--info-color); border: 1px solid var(--info-color); }

.remediation-block {
  margin-top: 10px;
  background: #0b0f19;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 10px 12px;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 12px;
  color: #a5b4fc;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.copy-btn {
  background: var(--border-color);
  color: var(--text-main);
  border: none;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 11px;
  cursor: pointer;
}
.copy-btn:hover { background: var(--text-muted); }

footer {
  margin-top: 40px;
  text-align: center;
  color: var(--text-muted);
  font-size: 13px;
}

@media print {
  body { background: #fff; color: #000; padding: 0; }
  .filter-bar, .copy-btn { display: none; }
  .header-card, .score-card, .kpi-card, .meta-grid, .results-card {
    border: 1px solid #ccc;
    background: #fff;
    color: #000;
  }
}
</style>
</head>
<body>

<div class="container">
  <!-- Header Section -->
  <div class="header-card">
    <div class="header-title">
      <h1>Windows Security Audit Report (CIS / ISO 27001)</h1>
      <p>Automated technical system compliance verification</p>
    </div>
    <span class="status-tag $statusClass">$statusText</span>
  </div>

  <!-- Executive Summary Section -->
  <div class="dashboard-grid">
    <div class="score-card">
      <div class="score-ring">
        <div class="score-ring-inner">$($score)%</div>
      </div>
      <div style="font-size:14px; font-weight:600;">Compliance Index</div>
      <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">Based on CIS Benchmarks checks</div>
    </div>

    <div class="kpi-cards">
      <div class="kpi-card pass">
        <span class="kpi-title">Passed (PASS)</span>
        <span class="kpi-value">$($script:CountPass)</span>
      </div>
      <div class="kpi-card warn">
        <span class="kpi-title">Warnings (WARN)</span>
        <span class="kpi-value">$($script:CountWarn)</span>
      </div>
      <div class="kpi-card fail">
        <span class="kpi-title">Failures (FAIL)</span>
        <span class="kpi-value">$($script:CountFail)</span>
      </div>
      <div class="kpi-card info">
        <span class="kpi-title">Information (INFO)</span>
        <span class="kpi-value">$($script:CountInfo)</span>
      </div>
    </div>
  </div>

  <!-- Metadata System Box -->
  <div class="meta-grid">
    <div class="meta-item"><strong>Target Host</strong>$hostEsc</div>
    <div class="meta-item"><strong>Operating System</strong>$osEsc</div>
    <div class="meta-item"><strong>OS Build</strong>$buildEsc</div>
    <div class="meta-item"><strong>Uptime</strong>$uptimeEsc</div>
    <div class="meta-item"><strong>Scan Date</strong>$tsEsc</div>
    <div class="meta-item"><strong>Auditor</strong>$auditorEsc (v$($script:Version))</div>
  </div>

  <!-- Interactive Controls Bar -->
  <div class="filter-bar">
    <div class="filter-chips">
      <button class="chip active" onclick="filterResults('ALL', this)">All Results</button>
      <button class="chip" onclick="filterResults('FAIL', this)">FAIL ($($script:CountFail))</button>
      <button class="chip" onclick="filterResults('WARN', this)">WARN ($($script:CountWarn))</button>
      <button class="chip" onclick="filterResults('PASS', this)">PASS ($($script:CountPass))</button>
      <button class="chip" onclick="filterResults('INFO', this)">INFO ($($script:CountInfo))</button>
    </div>
    <input type="text" id="searchInput" class="search-input" placeholder="Search checks or sections..." onkeyup="searchTable()">
  </div>

  <!-- Results Table -->
  <div class="results-card">
    <table id="auditTable">
      <thead>
        <tr>
          <th style="width: 110px; text-align: center;">Status</th>
          <th style="width: 280px;">Section</th>
          <th>Audit Finding / Actionable Remediation</th>
        </tr>
      </thead>
      <tbody>
"@

    $rows = New-Object System.Text.StringBuilder
    foreach ($f in $script:Findings) {
        $lvl = & $enc $f.Level; $sec = & $enc $(if ($f.Section) { $f.Section } else { '-' }); $msg = & $enc $f.Message
        [void]$rows.AppendLine("<tr class=`"audit-row`" data-status=`"$lvl`">")
        [void]$rows.AppendLine("  <td style=`"text-align: center;`"><span class=`"badge badge-$lvl`">$lvl</span></td>")
        [void]$rows.AppendLine("  <td><strong style=`"font-size:13px; color:var(--text-main);`">$sec</strong></td>")
        [void]$rows.AppendLine('  <td>')
        [void]$rows.AppendLine("    <div>$msg</div>")
        if ($f.Remediation) {
            $remHtml = & $enc $f.Remediation
            $remJs = & $enc ($f.Remediation.Replace('\', '\\').Replace("'", "\'").Replace("`r", '').Replace("`n", '\n'))
            [void]$rows.AppendLine('    <div class="remediation-block">')
            [void]$rows.AppendLine("      <span><strong>Fix:</strong> <code>$remHtml</code></span>")
            [void]$rows.AppendLine("      <button class=`"copy-btn`" onclick=`"navigator.clipboard.writeText('$remJs')`">Copy</button>")
            [void]$rows.AppendLine('    </div>')
        }
        [void]$rows.AppendLine('  </td>')
        [void]$rows.AppendLine('</tr>')
    }

    $foot = @"
      </tbody>
    </table>
  </div>

  <footer>
    Generated automatically by <code>windows_cis_audit.ps1</code> (v$($script:Version)) &copy; $auditorEsc
  </footer>
</div>

<script>
function filterResults(status, btn) {
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');

  const rows = document.querySelectorAll('.audit-row');
  rows.forEach(row => {
    if (status === 'ALL' || row.getAttribute('data-status') === status) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}

function searchTable() {
  const query = document.getElementById('searchInput').value.toLowerCase();
  const rows = document.querySelectorAll('.audit-row');

  rows.forEach(row => {
    const text = row.innerText.toLowerCase();
    row.style.display = text.includes(query) ? '' : 'none';
  });
}
</script>

</body>
</html>
"@

    return ($head + $rows.ToString() + $foot)
}

try {
    $html = New-HtmlReport
    [System.IO.File]::WriteAllText($HtmlReportFile, $html, (New-Object System.Text.UTF8Encoding($true)))
    Write-Raw "HTML report saved         : $HtmlReportFile"
} catch { Write-Raw "[WARN] Failed to write HTML report to ${HtmlReportFile}: $($_.Exception.Message)" 'Yellow' }

exit $ExitCode
