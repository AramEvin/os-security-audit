<#
.SYNOPSIS
    windows_cis_audit.ps1 (v1.0) - технический аудит безопасности Windows
    Server 2016+/Windows 10-11 (read-only).

.DESCRIPTION
    Windows-аналог redos_cis_audit.sh v1.1. Ориентирован на технические
    контроли ISO/IEC 27001 (Annex A: A.8, A.12, A.13) и методологию
    CIS Benchmarks for Microsoft Windows (Level 1 / Level 2).

    Скрипт только ЧИТАЕТ состояние системы. Единственная запись вне отчётов -
    временный файл secedit в %TEMP% (удаляется в конце).
      [PASS] - контроль выполнен
      [WARN] - отклонение от рекомендации / Level 2 / требует внимания
      [FAIL] - критическое несоответствие (Level 1)
      [INFO] - информационная строка, не влияет на итоговую оценку

    Вывод:
      - консоль (цветной)
      - <OutputDir>\windows_cis_audit_report.log   (текстовый, накопительно)
      - <OutputDir>\windows_cis_audit_report.html  (веб-версия, перезаписывается)

    Коды возврата: 0 = всё PASS, 1 = есть WARN, 2 = есть FAIL, 3 = не admin.

.PARAMETER OutputDir
    Каталог отчётов. По умолчанию C:\ProgramData\SecurityAudit
    (при создании доступ ограничивается SYSTEM + Administrators).

.PARAMETER SkipUpdateSearch
    Не искать доступные обновления через Windows Update Agent (быстрее,
    полезно для изолированных серверов без доступа к WSUS/WU).

.PARAMETER DeepScan
    Дополнительно: DISM ScanHealth и sfc /verifyonly (аналог rpm -Va).
    Занимает 5-20 минут.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows_cis_audit.ps1

.EXAMPLE
    .\windows_cis_audit.ps1 -SkipUpdateSearch -OutputDir D:\audit
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $env:ProgramData 'SecurityAudit'),
    [switch]$SkipUpdateSearch,
    [switch]$DeepScan
)

$ErrorActionPreference = 'SilentlyContinue'   # аналог 2>/dev/null; ошибки обрабатываются явно
$ProgressPreference    = 'SilentlyContinue'

# ============================================================================
# 0. ГЛОБАЛЬНЫЕ ПАРАМЕТРЫ И ИНИЦИАЛИЗАЦИЯ
# ============================================================================

$script:ScriptVersion = '1.0'
$script:AuditorName   = 'IT Security LLC'
$script:ReportFile    = Join-Path $OutputDir 'windows_cis_audit_report.log'
$script:HtmlFile      = Join-Path $OutputDir 'windows_cis_audit_report.html'
$script:RunTs         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'

$script:CountPass = 0
$script:CountWarn = 0
$script:CountFail = 0
$script:CountInfo = 0
$script:Findings      = New-Object System.Collections.Generic.List[object]
$script:TextBuffer    = New-Object System.Collections.Generic.List[string]
$script:CurrentSection = ''

function Write-Log {
    param([string]$Text = '', [string]$Color = '')
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
    [void]$script:TextBuffer.Add($Text)
}

function Write-Tagged {
    param([string]$Tag, [string]$Color, [string]$Msg)
    Write-Host '  ' -NoNewline
    Write-Host "[$Tag]" -ForegroundColor $Color -NoNewline
    Write-Host " $Msg"
    [void]$script:TextBuffer.Add("  [$Tag] $Msg")
}

function Add-Finding {
    param([string]$Level, [string]$Msg, [string]$Rem)
    [void]$script:Findings.Add([pscustomobject]@{
        Level = $Level; Section = $script:CurrentSection; Message = $Msg; Remediation = $Rem })
}

function Start-Section {
    param([string]$Title)
    $script:CurrentSection = $Title
    Write-Log ''
    Write-Log ('=' * 66) 'Cyan'
    Write-Log " $Title" 'Cyan'
    Write-Log ('=' * 66) 'Cyan'
}

function Add-Pass { param([string]$Msg)
    $script:CountPass++
    Write-Tagged 'PASS' 'Green' $Msg
    Add-Finding 'PASS' $Msg ''
}
function Add-Warn { param([string]$Msg, [string]$Rem = '')
    $script:CountWarn++
    Write-Tagged 'WARN' 'Yellow' $Msg
    if ($Rem) { Write-Log "         -> Рекомендация: $Rem" }
    Add-Finding 'WARN' $Msg $Rem
}
function Add-Fail { param([string]$Msg, [string]$Rem = '')
    $script:CountFail++
    Write-Tagged 'FAIL' 'Red' $Msg
    if ($Rem) { Write-Log "         -> Рекомендация: $Rem" }
    Add-Finding 'FAIL' $Msg $Rem
}
function Add-Info { param([string]$Msg)
    $script:CountInfo++
    Write-Tagged 'INFO' 'Cyan' $Msg
    Add-Finding 'INFO' $Msg ''
}
function Add-Sev { param([string]$Sev, [string]$Msg, [string]$Rem = '')
    if ($Sev -eq 'FAIL') { Add-Fail $Msg $Rem } else { Add-Warn $Msg $Rem }
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

# Универсальная проверка DWORD-параметра реестра (аналог цикла по SYSCTL_EXPECTED).
# DefaultIfMissing: значение, которое ОС применяет, если параметр не задан
# (ключевой урок v1.1 Linux-скрипта: "не задано" != "небезопасно", если default безопасный).
function Test-RegSetting {
    param(
        [string]$Path, [string]$Name, [int64]$Expected, [string]$Desc,
        [ValidateSet('eq', 'ge', 'le')][string]$Op = 'eq',
        [ValidateSet('FAIL', 'WARN')][string]$Severity = 'WARN',
        $DefaultIfMissing = $null,
        [string]$Rem = ''
    )
    if (-not $Rem) {
        $Rem = "New-Item -Path '$Path' -Force | Out-Null; New-ItemProperty -Path '$Path' -Name '$Name' -Value $Expected -PropertyType DWord -Force"
    }
    $val = Get-RegValue $Path $Name
    $src = ''
    if ($null -eq $val -and $null -ne $DefaultIfMissing) { $val = $DefaultIfMissing; $src = ' [default ОС]' }
    if ($null -eq $val) {
        Add-Sev $Severity "${Desc}: параметр ${Name} не задан" $Rem
        return
    }
    $ok = switch ($Op) {
        'eq' { [int64]$val -eq $Expected }
        'ge' { [int64]$val -ge $Expected }
        'le' { [int64]$val -le $Expected }
    }
    $opText = @{ eq = '='; ge = '>='; le = '<=' }[$Op]
    if ($ok) { Add-Pass "${Desc}: ${Name} = ${val}${src}" }
    else     { Add-Sev $Severity "${Desc}: ${Name} = ${val}${src} (ожидается ${opText} ${Expected})" $Rem }
}

# Проверка прав на файл/каталог: Everyone / Authenticated Users / Users
# не должны иметь запись/удаление/смену прав (аналог check_perm).
# Сравнение по SID, а не по имени - не зависит от локализации ОС.
function Test-WeakAcl {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Add-Info "${Path} не существует - пропущено"; return }
    $weak = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-545' = 'Users' }
    $mask = 0x500D0046   # WriteData|AppendData|DeleteSubdirs|Delete|ChangePerms|TakeOwner|GenericWrite|GenericAll
    $bad = @()
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl) { Add-Warn "${Path}: не удалось прочитать ACL"; return }
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { continue }
        if ($weak.ContainsKey($sid) -and (([int]$ace.FileSystemRights -band $mask) -ne 0)) {
            $bad += ('{0}:{1}' -f $weak[$sid], $ace.FileSystemRights)
        }
    }
    if ($bad.Count -eq 0) { Add-Pass "${Path}: нет прав записи у Everyone/Users/Authenticated Users" }
    else {
        Add-Fail "${Path}: избыточные права: $($bad -join '; ')" `
                 "icacls `"$Path`" /remove:g *S-1-1-0 *S-1-5-11 *S-1-5-32-545 (затем выдать только Read/Execute группе Users)"
    }
}

function Get-SecPolicy {
    $cfg = Join-Path $env:TEMP ('secpol_{0}.inf' -f [guid]::NewGuid().ToString('N'))
    $map = @{}
    try {
        & secedit.exe /export /cfg $cfg /areas SECURITYPOLICY USER_RIGHTS 2>&1 | Out-Null
        if (Test-Path -LiteralPath $cfg) {
            foreach ($line in (Get-Content -LiteralPath $cfg)) {
                if ($line -match '^\s*([^=\[;]+?)\s*=\s*(.*?)\s*$') { $map[$Matches[1]] = $Matches[2] }
            }
        }
    } finally { Remove-Item -LiteralPath $cfg -Force -ErrorAction SilentlyContinue }
    return $map
}

# ============================================================================
# 1. ПРОВЕРКА ЗАПУСКА ОТ ADMINISTRATOR
# ============================================================================

if (-not (Test-IsAdmin)) {
    Write-Host '[FAIL] Скрипт должен быть запущен от имени Администратора (elevated PowerShell).' -ForegroundColor Red
    Write-Host "Текущий пользователь: $env:USERNAME"
    Write-Host 'Повторите запуск: правый клик по PowerShell -> "Запуск от имени администратора".'
    exit 3
}

$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$HostFqdn = $env:COMPUTERNAME
if ($cs -and $cs.PartOfDomain -and $cs.DNSHostName) { $HostFqdn = "$($cs.DNSHostName).$($cs.Domain)" }
$OsInfo = 'неизвестно'
if ($os) { $OsInfo = '{0} (build {1}, {2})' -f $os.Caption.Trim(), $os.BuildNumber, $os.OSArchitecture }
$IsDC     = [bool]($os -and $os.ProductType -eq 2)
$IsServer = [bool]($os -and $os.ProductType -ne 1)

Write-Log 'Технический аудит безопасности (CIS / ISO 27001) - Windows' 'White'
Write-Log "Версия скрипта : $script:ScriptVersion"
Write-Log "Хост           : $HostFqdn"
Write-Log "Дата/время     : $script:RunTs"
Write-Log "ОС             : $OsInfo"
$OsRole = if ($IsDC) { 'Контроллер домена' } elseif ($IsServer) { 'Сервер' } else { 'Рабочая станция' }
Write-Log "Роль ОС        : $OsRole"
Write-Log "PowerShell     : $($PSVersionTable.PSVersion)"
Write-Log "Файл отчёта    : $script:ReportFile"
if (-not $os -or $os.Caption -notmatch 'Windows') {
    Add-Info 'Не удалось определить ОС через CIM (Win32_OperatingSystem) - часть проверок может быть пропущена'
}
if ($IsDC) { Add-Info 'Обнаружен контроллер домена: проверки локальных учётных записей неприменимы (используйте AD-специфичные CIS-бенчмарки)' }

# ============================================================================
# 2. АУДИТ ПОДСИСТЕМЫ ЛОГИРОВАНИЯ (EventLog / Advanced Audit Policy / PowerShell / Sysmon / Wazuh)
# ============================================================================

Start-Section '2. АУДИТ ПОДСИСТЕМЫ ЛОГИРОВАНИЯ (EventLog / Audit Policy / PowerShell / Sysmon)'

$evt = Get-Service -Name EventLog
if ($evt -and $evt.Status -eq 'Running') { Add-Pass 'Служба Windows Event Log (EventLog) запущена' }
else { Add-Fail 'Служба EventLog не запущена' 'Set-Service EventLog -StartupType Automatic; Start-Service EventLog' }

# Размеры журналов (CIS 18.10.x): Security >= 196608 KB, Application/System >= 32768 KB
foreach ($r in @(
        @{ N = 'Security';    KB = 196608; Sev = 'FAIL' },
        @{ N = 'Application'; KB = 32768;  Sev = 'WARN' },
        @{ N = 'System';      KB = 32768;  Sev = 'WARN' })) {
    $l = Get-WinEvent -ListLog $r.N
    if (-not $l) { Add-Warn "Журнал $($r.N) недоступен"; continue }
    $kb = [math]::Floor($l.MaximumSizeInBytes / 1KB)
    if ($kb -ge $r.KB) { Add-Pass "Журнал $($r.N): максимальный размер ${kb} KB (>= $($r.KB) KB)" }
    else {
        Add-Sev $r.Sev "Журнал $($r.N): максимальный размер ${kb} KB (рекомендуется >= $($r.KB) KB)" `
                "wevtutil sl $($r.N) /ms:$($r.KB * 1024)"
    }
    Add-Info "Журнал $($r.N): режим $($l.LogMode), включён: $($l.IsEnabled)"
}

# Advanced Audit Policy. Сопоставление по GUID подкатегории и разбор
# Inclusion Setting с учётом RU/EN локали (auditpol локализует и заголовки, и значения).
Test-RegSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' `
    -Expected 1 -Severity WARN -Desc 'Advanced Audit Policy имеет приоритет над legacy-категориями (CIS 2.3.2.1)'

if (Get-Command auditpol.exe -ErrorAction SilentlyContinue) {
    $rows = @(& auditpol.exe /get /category:* /r 2>$null |
              Where-Object { $_ -match '\{[0-9A-Fa-f-]{36}\}' } |
              ConvertFrom-Csv -Header m, t, sub, guid, inc, exc)
    if ($rows.Count -eq 0) {
        Add-Warn 'auditpol не вернул данных о подкатегориях аудита' 'Проверить вручную: auditpol /get /category:*'
    } else {
        $auditMap = @{}
        foreach ($r in $rows) { $auditMap[$r.guid.Trim('{', '}').ToUpper()] = $r }
        $base = '-69AE-11D9-BED3-505054503030'
        # ID|Имя|Need(S/F/SF)|Severity
        $expected = @(
            '0CCE923F|Credential Validation|SF|FAIL',
            '0CCE9235|User Account Management|SF|FAIL',
            '0CCE9237|Security Group Management|S|FAIL',
            '0CCE922B|Process Creation|S|FAIL',
            '0CCE9215|Logon|SF|FAIL',
            '0CCE9216|Logoff|S|WARN',
            '0CCE9217|Account Lockout|F|FAIL',
            '0CCE921C|Other Logon/Logoff Events|SF|WARN',
            '0CCE921B|Special Logon|S|FAIL',
            '0CCE9249|Group Membership|S|WARN',
            '0CCE9224|File Share|SF|WARN',
            '0CCE9244|Detailed File Share|F|WARN',
            '0CCE9245|Removable Storage|SF|WARN',
            '0CCE922F|Audit Policy Change|S|FAIL',
            '0CCE9230|Authentication Policy Change|S|WARN',
            '0CCE9231|Authorization Policy Change|S|WARN',
            '0CCE9232|MPSSVC Rule-Level Policy Change|SF|WARN',
            '0CCE9234|Other Policy Change Events|F|WARN',
            '0CCE9228|Sensitive Privilege Use|SF|FAIL',
            '0CCE9213|IPsec Driver|SF|WARN',
            '0CCE9214|Other System Events|SF|WARN',
            '0CCE9210|Security State Change|S|FAIL',
            '0CCE9211|Security System Extension|S|FAIL',
            '0CCE9212|System Integrity|SF|FAIL'
        )
        foreach ($e in $expected) {
            $p = $e.Split('|'); $guid = $p[0] + $base; $name = $p[1]; $need = $p[2]; $sev = $p[3]
            $row = $auditMap[$guid]
            if (-not $row) { Add-Info "Подкатегория аудита '${name}' не найдена в выводе auditpol - пропущено"; continue }
            $inc  = "$($row.inc)"
            $hasS = $inc -match 'Success|Успех|Успешн'
            $hasF = $inc -match 'Failure|Сбой|Отказ|Ошибк'
            $needS = $need.Contains('S'); $needF = $need.Contains('F')
            $okS = (-not $needS) -or $hasS
            $okF = (-not $needF) -or $hasF
            $needTxt = @(@('Success') * [int]$needS + @('Failure') * [int]$needF) -join '+'
            if ($okS -and $okF) { Add-Pass "Аудит '${name}': '${inc}' (требуется: ${needTxt})" }
            else {
                $flags = ''
                if ($needS) { $flags += ' /success:enable' }
                if ($needF) { $flags += ' /failure:enable' }
                Add-Sev $sev "Аудит '${name}': '${inc}' (требуется: ${needTxt})" `
                        "auditpol /set /subcategory:`"{$guid}`"$flags"
            }
        }
    }
} else {
    Add-Warn 'auditpol.exe не найден - политика аудита не проверена'
}

# Командная строка процессов в событии 4688 + PowerShell logging (критично для SIEM / Wazuh)
Test-RegSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name 'ProcessCreationIncludeCmdLine_Enabled' -Expected 1 -Severity WARN `
    -Desc 'Включение командной строки в события создания процесса (4688)'
Test-RegSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name 'EnableScriptBlockLogging' -Expected 1 -Severity WARN -Desc 'PowerShell Script Block Logging (CIS 18.10.87.1)'
Test-RegSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
    -Name 'EnableModuleLogging' -Expected 1 -Severity WARN -Desc 'PowerShell Module Logging'
Test-RegSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
    -Name 'EnableTranscripting' -Expected 1 -Severity WARN -Desc 'PowerShell Transcription'

# Агент SIEM и Sysmon
$wz = Get-Service -Name 'WazuhSvc', 'OssecSvc' | Select-Object -First 1
if ($wz) {
    if ($wz.Status -eq 'Running') { Add-Pass "Агент Wazuh ($($wz.Name)) запущен" }
    else { Add-Fail "Агент Wazuh ($($wz.Name)) не запущен (состояние: $($wz.Status))" "Start-Service $($wz.Name)" }
    if ($wz.StartType -ne 'Automatic') {
        Add-Warn "Агент Wazuh: тип запуска $($wz.StartType) (ожидается Automatic)" "Set-Service $($wz.Name) -StartupType Automatic"
    }
} else {
    Add-Warn 'Агент Wazuh (WazuhSvc) не найден - события не передаются в SIEM' 'Установить wazuh-agent и зарегистрировать на менеджере кластера'
}
$sm = Get-Service -Name 'Sysmon64', 'Sysmon' | Select-Object -First 1
if ($sm -and $sm.Status -eq 'Running') { Add-Pass "Sysmon ($($sm.Name)) запущен" }
elseif ($sm) { Add-Warn "Sysmon ($($sm.Name)) установлен, но не запущен" "Start-Service $($sm.Name)" }
else { Add-Warn 'Sysmon не установлен (рекомендуется для детектирования: process/network/registry events)' 'sysmon64 -accepteula -i <sysmonconfig.xml>' }

# ============================================================================
# 3. СЕТЬ, ОТКРЫТЫЕ ПОРТЫ, МЕЖСЕТЕВОЙ ЭКРАН, СЕТЕВОЙ HARDENING
# ============================================================================

Start-Section '3. СЕТЬ, ОТКРЫТЫЕ ПОРТЫ, МЕЖСЕТЕВОЙ ЭКРАН И СЕТЕВОЙ HARDENING'

if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    Add-Info "Сбор данных через Get-NetTCPConnection / Get-NetUDPEndpoint"
    $procMap = @{}
    Get-Process | ForEach-Object { $procMap[[int]$_.Id] = $_.ProcessName }
    $tcp = @(Get-NetTCPConnection -State Listen | Sort-Object LocalPort)
    foreach ($c in $tcp) {
        Write-Log ('         tcp LISTEN {0}:{1}  pid={2} ({3})' -f $c.LocalAddress, $c.LocalPort, $c.OwningProcess, $procMap[[int]$c.OwningProcess])
    }
    $udp = @(Get-NetUDPEndpoint | Sort-Object LocalPort)
    foreach ($c in $udp) {
        Write-Log ('         udp        {0}:{1}  pid={2} ({3})' -f $c.LocalAddress, $c.LocalPort, $c.OwningProcess, $procMap[[int]$c.OwningProcess])
    }
    Add-Info "Всего слушающих сокетов: TCP LISTEN=$($tcp.Count), UDP=$($udp.Count)"
    $wild = @($tcp | Where-Object { $_.LocalAddress -in @('0.0.0.0', '::') } |
              Select-Object -ExpandProperty LocalPort -Unique)
    if ($wild.Count -gt 0) {
        Add-Warn "Обнаружено $($wild.Count) уникальных TCP-портов, слушающих на всех интерфейсах (0.0.0.0/::)" `
                 'Ограничить доступ к управляющим портам (RDP 3389, WinRM 5985/5986, SMB 445, exporters 9100/9182) через Windows Firewall scope (RemoteAddress) либо bind на конкретный интерфейс'
    }
    $risky = @{ 21 = 'FTP'; 23 = 'Telnet'; 69 = 'TFTP'; 5900 = 'VNC' }
    $riskyHit = @($tcp | Where-Object { $risky.ContainsKey([int]$_.LocalPort) } |
                  ForEach-Object { '{0}/{1}' -f $_.LocalPort, $risky[[int]$_.LocalPort] } | Select-Object -Unique)
    if ($riskyHit.Count -gt 0) {
        Add-Warn "Слушаются небезопасные/устаревшие сервисы: $($riskyHit -join ', ')" 'Отключить службу и закрыть порт в firewall; использовать SFTP/RDP с NLA/SSH'
    }
} else {
    Add-Warn 'Get-NetTCPConnection недоступен - список портов не собран' 'Проверить вручную: netstat -ano | findstr LISTENING'
}

# Windows Defender Firewall. Enabled/DefaultInboundAction = NotConfigured - штатные
# безопасные значения по умолчанию (inbound Block), поэтому оцениваем только явный Allow / Off.
$fwOk = $false
$mps = Get-Service -Name MpsSvc
if ($mps -and $mps.Status -eq 'Running' -and (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
    $fwOk = $true
    Add-Pass 'Служба Windows Defender Firewall (MpsSvc) запущена'
    foreach ($p in @(Get-NetFirewallProfile)) {
        $pn = "$($p.Name)"; $en = "$($p.Enabled)"; $inb = "$($p.DefaultInboundAction)"
        if ($en -eq 'False') {
            Add-Fail "Профиль firewall '${pn}' ОТКЛЮЧЁН" "Set-NetFirewallProfile -Profile ${pn} -Enabled True"
        } else { Add-Pass "Профиль firewall '${pn}' включён (Enabled=${en})" }
        if ($inb -eq 'Allow') {
            Add-Fail "Профиль '${pn}': DefaultInboundAction=Allow - весь непереченный входящий трафик разрешён" `
                     "Set-NetFirewallProfile -Profile ${pn} -DefaultInboundAction Block"
        } else { Add-Pass "Профиль '${pn}': DefaultInboundAction=${inb} (implicit deny, безопасно)" }
        if ("$($p.LogBlocked)" -eq 'True') { Add-Pass "Профиль '${pn}': логирование заблокированных пакетов включено" }
        else {
            Add-Warn "Профиль '${pn}': логирование заблокированных пакетов не включено (CIS 9.x.6)" `
                     "Set-NetFirewallProfile -Profile ${pn} -LogBlocked True -LogMaxSizeKilobytes 16384"
        }
    }
    $allowCnt = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -PolicyStore ActiveStore).Count
    Add-Info "Включённых входящих allow-правил в активной политике: ${allowCnt}"
}
if (-not $fwOk) {
    Add-Fail 'Windows Defender Firewall не активен (служба MpsSvc остановлена или NetSecurity недоступен)' `
             'Set-Service MpsSvc -StartupType Automatic; Start-Service MpsSvc; Set-NetFirewallProfile -All -Enabled True'
}

# Аналог блока sysctl: сетевые параметры ОС
Test-RegSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' `
    -Expected 0 -Severity WARN -Desc 'Отключение LLMNR (CIS 18.6.4.x)'

$nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE')
$nbBad = @($nics | Where-Object { $_.TcpipNetbiosOptions -ne 2 } | ForEach-Object { $_.Description })
if ($nics.Count -eq 0) { Add-Info 'Активных IP-адаптеров не найдено - проверка NetBIOS пропущена' }
elseif ($nbBad.Count -eq 0) { Add-Pass 'NetBIOS over TCP/IP отключён на всех активных адаптерах' }
else {
    Add-Warn "NetBIOS over TCP/IP не отключён на адаптерах: $($nbBad -join '; ')" `
             'Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2}'
}

$smb = Get-SmbServerConfiguration
if ($smb) {
    if (-not $smb.EnableSMB1Protocol) { Add-Pass 'SMBv1 (сервер) отключён' }
    else { Add-Fail 'SMBv1 (сервер) ВКЛЮЧЁН' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' }
    if ($smb.RequireSecuritySignature) { Add-Pass 'SMB-сервер: подпись пакетов обязательна (RequireSecuritySignature)' }
    else { Add-Fail 'SMB-сервер: подпись пакетов не является обязательной (CIS 2.3.9.2)' 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force' }
} else { Add-Info 'Get-SmbServerConfiguration недоступен (служба LanmanServer остановлена?) - проверки SMB-сервера пропущены' }
Test-RegSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' `
    -Expected 1 -Severity WARN -Desc 'SMB-клиент: обязательная подпись (CIS 2.3.8.1)'

if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
    $shares = @(Get-SmbShare | Where-Object { -not $_.Special })
    if ($shares.Count -eq 0) { Add-Pass 'Пользовательских SMB-шар нет (только административные)' }
    foreach ($sh in $shares) {
        $everyone = @(Get-SmbShareAccess -Name $sh.Name | Where-Object {
            $_.AccessRight -in @('Full', 'Change') -and $_.AccountName -match '^(Everyone|Все)$' })
        if ($everyone.Count -gt 0) {
            Add-Warn "SMB-шара '$($sh.Name)' ($($sh.Path)): Everyone имеет Full/Change" "Revoke-SmbShareAccess -Name '$($sh.Name)' -AccountName Everyone -Force"
        } else { Add-Info "SMB-шара '$($sh.Name)' ($($sh.Path)): Everyone не имеет Full/Change" }
    }
}

# WinRM
Test-RegSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' `
    -Expected 0 -DefaultIfMissing 0 -Severity WARN -Desc 'WinRM-сервис: Basic-аутентификация отключена (CIS 18.10.89.2.3)'
Test-RegSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' `
    -Expected 0 -DefaultIfMissing 0 -Severity FAIL -Desc 'WinRM-сервис: незашифрованный трафик запрещён (CIS 18.10.89.2.4)'

# RDP
$rdpDeny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
if ($rdpDeny -eq 1) { Add-Pass 'RDP отключён (fDenyTSConnections=1)' }
else {
    Add-Info 'RDP включён - проверяются параметры безопасности сессии'
    $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    Test-RegSetting -Path $rdp -Name 'UserAuthentication' -Expected 1 -DefaultIfMissing 1 -Severity FAIL -Desc 'RDP: Network Level Authentication (NLA)'
    Test-RegSetting -Path $rdp -Name 'SecurityLayer'      -Expected 2 -Op ge -DefaultIfMissing 1 -Severity WARN -Desc 'RDP: SecurityLayer (2 = TLS)'
    Test-RegSetting -Path $rdp -Name 'MinEncryptionLevel' -Expected 3 -Op ge -DefaultIfMissing 2 -Severity WARN -Desc 'RDP: минимальный уровень шифрования (3 = High)'
}

# ============================================================================
# 4. ПОЛЬЗОВАТЕЛИ, ПАРОЛЬНАЯ ПОЛИТИКА, ПРАВА ДОСТУПА И ACL
# ============================================================================

Start-Section '4. ПОЛЬЗОВАТЕЛИ, ПАРОЛЬНАЯ ПОЛИТИКА, ПРАВА ДОСТУПА И ACL'

if ((Get-Command Get-LocalUser -ErrorAction SilentlyContinue) -and -not $IsDC) {
    $users = @(Get-LocalUser)
    if ($users.Count -gt 0) {
        $guest = $users | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
        if ($guest -and $guest.Enabled) { Add-Fail "Учётная запись Guest ВКЛЮЧЕНА ($($guest.Name))" "Disable-LocalUser -SID $($guest.SID.Value)" }
        else { Add-Pass 'Учётная запись Guest отключена' }

        $adm = $users | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
        if ($adm) {
            if ($adm.Name -in @('Administrator', 'Администратор')) {
                Add-Warn "Встроенная учётная запись Administrator (RID 500) не переименована (Enabled=$($adm.Enabled)) (CIS 2.3.1.5)" `
                         "Rename-LocalUser -SID $($adm.SID.Value) -NewName '<новое_имя>'"
            } else { Add-Pass "Встроенная учётная запись RID 500 переименована ($($adm.Name))" }
        }

        $noPw = @($users | Where-Object { $_.Enabled -and -not $_.PasswordRequired } | ForEach-Object { $_.Name })
        if ($noPw.Count -eq 0) { Add-Pass 'Включённых учётных записей без обязательного пароля не обнаружено' }
        else {
            Add-Fail "Включённые учётные записи БЕЗ обязательного пароля: $($noPw -join ', ')" `
                     "Set-LocalUser -Name '<пользователь>' -PasswordNotRequired `$false; затем задать пароль либо Disable-LocalUser"
        }

        $neverExp = @($users | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null } | ForEach-Object { $_.Name })
        if ($neverExp.Count -gt 0) {
            Add-Warn "Включённые учётные записи с паролем без срока действия: $($neverExp -join ', ')" `
                     'Для сервисных учётных записей использовать gMSA / vault; для людей - политику смены пароля либо MFA'
        }
        Add-Info "Локальных учётных записей: $($users.Count), включённых: $(@($users | Where-Object { $_.Enabled }).Count)"
    }

    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
    if ($admins.Count -gt 0) {
        Add-Info "Члены локальной группы Administrators ($($admins.Count)): $(($admins | ForEach-Object { $_.Name }) -join ', ')"
        if ($admins.Count -gt 5) { Add-Warn "В локальной группе Administrators $($admins.Count) участников - проверить необходимость (least privilege)" }
    }
} elseif (-not $IsDC) {
    Add-Warn 'Модуль Microsoft.PowerShell.LocalAccounts недоступен - проверка локальных пользователей пропущена'
}

# Парольная политика и права (secedit, ключи не локализуются)
$sec = Get-SecPolicy
if ($sec.Count -eq 0) {
    Add-Warn 'secedit не вернул политику безопасности - парольная политика не проверена' 'Проверить вручную: secedit /export /cfg C:\secpol.inf'
} else {
    $n = { param($k) if ($sec.ContainsKey($k) -and $sec[$k] -match '^-?\d+$') { [int64]$sec[$k] } else { $null } }
    $v = & $n 'MinimumPasswordLength'
    if ($null -eq $v) { Add-Warn 'MinimumPasswordLength не определён' }
    elseif ($v -ge 14) { Add-Pass "Минимальная длина пароля: ${v} (>= 14)" }
    elseif ($v -ge 8)  { Add-Warn "Минимальная длина пароля: ${v} (CIS L1: >= 14)" 'net accounts /minpwlen:14 (либо GPO: Computer Configuration > Windows Settings > Security Settings > Account Policies)' }
    else               { Add-Fail "Минимальная длина пароля: ${v} (слишком мала)" 'net accounts /minpwlen:14' }

    $v = & $n 'PasswordComplexity'
    if ($v -eq 1) { Add-Pass 'Требования сложности пароля включены' }
    else { Add-Fail "Требования сложности пароля не включены (PasswordComplexity=${v})" 'GPO: Password must meet complexity requirements = Enabled' }

    $v = & $n 'MaximumPasswordAge'
    if ($null -ne $v -and $v -ge 1 -and $v -le 365) { Add-Pass "Максимальный срок действия пароля: ${v} дн." }
    else { Add-Warn "Максимальный срок действия пароля: ${v} (CIS: 1..365 дней; -1/0 = бессрочный)" 'net accounts /maxpwage:365' }

    $v = & $n 'MinimumPasswordAge'
    if ($null -ne $v -and $v -ge 1) { Add-Pass "Минимальный срок действия пароля: ${v} дн." }
    else { Add-Warn "Минимальный срок действия пароля: ${v} (рекомендуется >= 1)" 'net accounts /minpwage:1' }

    $v = & $n 'PasswordHistorySize'
    if ($null -ne $v -and $v -ge 24) { Add-Pass "История паролей: ${v} (>= 24)" }
    else { Add-Warn "История паролей: ${v} (CIS: >= 24)" 'net accounts /uniquepw:24' }

    $v = & $n 'ClearTextPassword'
    if ($v -eq 0) { Add-Pass 'Хранение паролей в обратимом виде отключено' }
    else { Add-Fail "Хранение паролей в обратимом шифровании: ClearTextPassword=${v}" 'GPO: Store passwords using reversible encryption = Disabled' }

    $lb = & $n 'LockoutBadCount'
    if ($lb -ge 1 -and $lb -le 5) { Add-Pass "Порог блокировки учётной записи: ${lb} (<= 5)" }
    elseif ($lb -eq 0) { Add-Fail 'Блокировка учётных записей отключена (LockoutBadCount=0)' 'net accounts /lockoutthreshold:5' }
    else { Add-Warn "Порог блокировки: ${lb} (CIS: 1..5)" 'net accounts /lockoutthreshold:5' }
    if ($lb -ge 1) {
        $d = & $n 'LockoutDuration'
        if ($d -eq -1 -or $d -ge 15) { Add-Pass "Длительность блокировки: ${d} мин. (-1 = до разблокировки админом)" }
        else { Add-Warn "Длительность блокировки: ${d} мин. (CIS: >= 15)" 'net accounts /lockoutduration:15' }
        $d = & $n 'ResetLockoutCount'
        if ($d -ge 15) { Add-Pass "Сброс счётчика блокировки через ${d} мин. (>= 15)" }
        else { Add-Warn "Сброс счётчика блокировки через ${d} мин. (CIS: >= 15)" 'net accounts /lockoutwindow:15' }
    }

    if ($sec.ContainsKey('SeDebugPrivilege')) {
        if ($sec['SeDebugPrivilege'] -eq '*S-1-5-32-544') { Add-Pass 'SeDebugPrivilege выдана только Administrators' }
        else { Add-Warn "SeDebugPrivilege выдана: $($sec['SeDebugPrivilege']) (CIS 2.2.x: только Administrators)" 'GPO: Debug programs = Administrators' }
    }
}

# Права на критичные объекты ФС (аналог check_perm)
$sr = $env:SystemRoot
foreach ($pth in @($sr, "$sr\System32", "$sr\System32\config", "$sr\System32\drivers\etc\hosts",
                   "$sr\System32\winevt\Logs", $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if ($pth) { Test-WeakAcl $pth }
}

# ============================================================================
# 5. СЛУЖБЫ, ЦЕЛОСТНОСТЬ ФАЙЛОВ И ОБНОВЛЕНИЯ
# ============================================================================

Start-Section '5. СЛУЖБЫ, ЦЕЛОСТНОСТЬ ФАЙЛОВ И ОБНОВЛЕНИЯ'

$insecure = @('TlntSvr', 'FTPSVC', 'SNMP', 'SNMPTRAP', 'RemoteRegistry', 'SSDPSRV', 'upnphost', 'Browser', 'simptcp', 'W3SVC')
$foundInsecure = $false
foreach ($sn in $insecure) {
    $s = Get-Service -Name $sn
    if (-not $s) { continue }
    if ($s.Status -eq 'Running' -or $s.StartType -eq 'Automatic') {
        Add-Fail "Небезопасная/лишняя служба активна или в автозагрузке: $sn ($($s.DisplayName); Status=$($s.Status), Start=$($s.StartType))" `
                 "Stop-Service $sn -Force; Set-Service $sn -StartupType Disabled"
        $foundInsecure = $true
    } else { Add-Info "Служба $sn установлена, но остановлена и не в автозагрузке" }
}
if (-not $foundInsecure) { Add-Pass 'Активных небезопасных служб (Telnet/FTP/SNMP/RemoteRegistry/SSDP/UPnP/Browser) не обнаружено' }

$spool = Get-Service -Name Spooler
if ($spool -and $spool.Status -eq 'Running') {
    if ($IsServer) {
        Add-Warn 'Служба Print Spooler запущена на сервере (вектор PrintNightmare; CIS L2 для member server)' `
                 'Если сервер не печатающий: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled'
    } else {
        Add-Info 'Служба Print Spooler запущена (штатно для рабочей станции; на серверах оценивается как WARN)'
    }
} else { Add-Pass 'Print Spooler не запущен' }

$allRunning = @(Get-Service | Where-Object { $_.Status -eq 'Running' }).Count
Add-Info "Всего запущенных служб: ${allRunning}"

# Unquoted service path (классический вектор повышения привилегий)
$badSvc = @()
foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '^[A-Za-z]:\\' })) {
    $p = $s.PathName.Trim()
    if ($p.StartsWith('"')) { continue }
    if ($p -match '^(?<exe>.+?\.exe)(\s|$)') { if ($Matches['exe'] -match '\s') { $badSvc += "$($s.Name) [$p]" } }
}
if ($badSvc.Count -eq 0) { Add-Pass 'Служб с неквотированными путями к исполняемым файлам (unquoted service path) не обнаружено' }
else {
    Add-Fail "Обнаружены службы с unquoted service path: $($badSvc.Count)" `
             'sc.exe config <имя_службы> binPath= "\"<полный_путь>\" <аргументы>" (или правка ImagePath в HKLM\SYSTEM\CurrentControlSet\Services\<имя>)'
    $badSvc | Select-Object -First 20 | ForEach-Object { Write-Log "         $_" }
}

# Целостность: подписи ключевых бинарников (быстрый аналог rpm -Va по критичным файлам)
$sys32 = "$env:SystemRoot\System32"
$keyBins = @("$sys32\cmd.exe", "$sys32\lsass.exe", "$sys32\services.exe", "$sys32\winlogon.exe", "$sys32\svchost.exe",
             "$sys32\ntoskrnl.exe", "$sys32\kernel32.dll", "$sys32\ntdll.dll", "$sys32\WindowsPowerShell\v1.0\powershell.exe")
$sigBad = @(); $sigChecked = 0
foreach ($f in $keyBins) {
    if (-not (Test-Path -LiteralPath $f)) { continue }
    $sigChecked++
    $sig = Get-AuthenticodeSignature -FilePath $f
    if (-not $sig -or "$($sig.Status)" -ne 'Valid') { $sigBad += "$f ($($sig.Status))" }
}
if ($sigChecked -eq 0) { Add-Warn 'Ключевые системные бинарники не найдены для проверки подписи' }
elseif ($sigBad.Count -eq 0) { Add-Pass "Цифровые подписи ключевых системных файлов валидны (проверено: ${sigChecked})" }
else {
    Add-Fail "Невалидная подпись системных файлов: $($sigBad -join '; ')" `
             'Сверить хэш с эталоном; при подозрении на компрометацию: sfc /scannow; DISM /Online /Cleanup-Image /RestoreHealth'
}

if ($DeepScan) {
    Add-Info 'DeepScan: запуск DISM ScanHealth и sfc /verifyonly (может занять 5-20 минут)...'
    $img = Repair-WindowsImage -Online -ScanHealth
    if ($img) {
        if ("$($img.ImageHealthState)" -eq 'Healthy') { Add-Pass 'DISM ScanHealth: хранилище компонентов не повреждено (Healthy)' }
        else { Add-Fail "DISM ScanHealth: состояние $($img.ImageHealthState)" 'DISM /Online /Cleanup-Image /RestoreHealth' }
    } else { Add-Warn 'DISM ScanHealth не удалось выполнить (Repair-WindowsImage недоступен)' }
    $sfcOut = (& sfc.exe /verifyonly 2>&1 | Out-String) -replace "`0", ''
    if ($sfcOut -match 'did not find any integrity violations|не обнаружила нарушений целостности|не обнаружено нарушений целостности') {
        Add-Pass 'sfc /verifyonly: нарушений целостности не обнаружено'
    } elseif ($sfcOut -match 'found integrity violations|обнаружила поврежденные|обнаружены поврежденные|обнаружила нарушения') {
        Add-Fail 'sfc /verifyonly: обнаружены нарушения целостности системных файлов' 'sfc /scannow (детали: %windir%\Logs\CBS\CBS.log)'
    } else { Add-Info 'sfc /verifyonly: результат не распознан - проверьте вручную (sfc /verifyonly)' }
} else {
    Add-Info 'Глубокая проверка целостности (DISM/sfc) пропущена - запустите с -DeepScan'
}

# Обновления
$hf = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object { [datetime]$_.InstalledOn } -Descending) | Select-Object -First 1
if ($hf) {
    $days = (New-TimeSpan -Start ([datetime]$hf.InstalledOn) -End (Get-Date)).Days
    if ($days -le 35) { Add-Pass "Последнее обновление установлено ${days} дн. назад ($($hf.HotFixID))" }
    else { Add-Warn "Последнее обновление установлено ${days} дн. назад ($($hf.HotFixID)) - давно" 'Проверить Windows Update / WSUS; установить накопительные обновления (сначала в стейджинге)' }
} else { Add-Warn 'Не удалось определить дату последнего установленного обновления (Get-HotFix пуст)' }

if (-not $SkipUpdateSearch) {
    Add-Info 'Поиск доступных обновлений через Windows Update Agent (может занять до нескольких минут)...'
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $res  = $sess.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $cnt = $res.Updates.Count
        if ($cnt -eq 0) { Add-Pass 'Доступных неустановленных обновлений нет' }
        else {
            $crit = 0
            foreach ($u in $res.Updates) { if ($u.MsrcSeverity -in @('Critical', 'Important')) { $crit++ } }
            Add-Warn "Доступны обновления: ${cnt} (Critical/Important: ${crit})" `
                     'Установить через Windows Update/WSUS (PSWindowsUpdate: Install-WindowsUpdate -AcceptAll); протестировать в стейджинге перед прод-раскаткой'
        }
    } catch { Add-Warn "Не удалось выполнить поиск обновлений: $($_.Exception.Message)" 'Проверить доступ к WSUS/Windows Update или запускать с -SkipUpdateSearch' }
} else { Add-Info 'Поиск обновлений пропущен (-SkipUpdateSearch)' }

$pendReboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
              (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
              ($null -ne (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'))
if ($pendReboot) { Add-Warn 'Ожидается перезагрузка для завершения установки обновлений/изменений' 'Запланировать окно обслуживания и перезагрузить хост' }
else { Add-Pass 'Отложенной перезагрузки нет' }

# ============================================================================
# 6. HARDENING ОС (UAC / LSA / NTLM / Defender / шифрование / TLS)
# ============================================================================

Start-Section '6. HARDENING ОС (UAC / LSA / NTLM / Defender / шифрование / TLS)'

$pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Test-RegSetting -Path $pol -Name 'EnableLUA' -Expected 1 -DefaultIfMissing 1 -Severity FAIL -Desc 'UAC включён (CIS 2.3.17.6)'
$cp = Get-RegValue $pol 'ConsentPromptBehaviorAdmin'
if ($null -eq $cp) { $cp = 5 }
if ($cp -in @(1, 2)) { Add-Pass "UAC: запрос для администраторов на защищённом рабочем столе (ConsentPromptBehaviorAdmin=${cp})" }
elseif ($cp -eq 0)   { Add-Fail 'UAC: повышение прав администраторов без запроса (ConsentPromptBehaviorAdmin=0)' "Set-ItemProperty '$pol' ConsentPromptBehaviorAdmin 2" }
else                 { Add-Warn "UAC: ConsentPromptBehaviorAdmin=${cp} (CIS: 2 - consent на secure desktop)" "Set-ItemProperty '$pol' ConsentPromptBehaviorAdmin 2" }
Test-RegSetting -Path $pol -Name 'LocalAccountTokenFilterPolicy' -Expected 0 -DefaultIfMissing 0 -Severity WARN `
    -Desc 'UAC-ограничения для локальных учётных записей при сетевом входе (защита от pass-the-hash)'

$it = Get-RegValue $pol 'InactivityTimeoutSecs'
if ($null -ne $it -and $it -ge 1 -and $it -le 900) { Add-Pass "Блокировка экрана по неактивности: ${it} с (<= 900)" }
else { Add-Warn "Блокировка по неактивности не настроена или > 900 с (текущее: $(if ($null -eq $it) { 'не задано' } else { $it })) (CIS 2.3.7.3)" "Set-ItemProperty '$pol' InactivityTimeoutSecs 900" }
Test-RegSetting -Path $pol -Name 'DontDisplayLastUserName' -Expected 1 -Severity WARN -Desc 'Не показывать имя последнего пользователя на экране входа (CIS 2.3.7.2)'
$ln = Get-RegValue $pol 'LegalNoticeText'
if ($ln) { Add-Pass 'Задан юридический баннер при входе (LegalNoticeText)' }
else { Add-Warn 'Юридический баннер при входе не задан (CIS 2.3.7.4/2.3.7.5, ISO 27001 A.5.10)' "Set-ItemProperty '$pol' LegalNoticeCaption 'Warning'; Set-ItemProperty '$pol' LegalNoticeText 'Authorized use only. Activity is monitored.'" }

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lm = Get-RegValue $lsa 'LmCompatibilityLevel'
if ($null -eq $lm) { $lm = 3; $lmSrc = ' [default ОС]' } else { $lmSrc = '' }
if ($lm -ge 5) { Add-Pass "NTLM: LmCompatibilityLevel = ${lm}${lmSrc} (только NTLMv2)" }
elseif ($lm -ge 3) { Add-Warn "NTLM: LmCompatibilityLevel = ${lm}${lmSrc} (CIS 2.3.11.7: 5 - отказ от LM и NTLMv1)" "Set-ItemProperty '$lsa' LmCompatibilityLevel 5 -Type DWord" }
else { Add-Fail "NTLM: LmCompatibilityLevel = ${lm}${lmSrc} - разрешены LM/NTLMv1" "Set-ItemProperty '$lsa' LmCompatibilityLevel 5 -Type DWord" }
Test-RegSetting -Path $lsa -Name 'NoLMHash'           -Expected 1 -DefaultIfMissing 1 -Severity FAIL -Desc 'Запрет хранения LM-хэшей паролей (CIS 2.3.11.5)'
Test-RegSetting -Path $lsa -Name 'RestrictAnonymousSAM' -Expected 1 -DefaultIfMissing 1 -Severity FAIL -Desc 'Запрет анонимного перечисления SAM (CIS 2.3.10.2)'
Test-RegSetting -Path $lsa -Name 'RestrictAnonymous'  -Expected 1 -Op ge -DefaultIfMissing 0 -Severity WARN -Desc 'Запрет анонимного перечисления SAM и шар (CIS 2.3.10.3)'
Test-RegSetting -Path $lsa -Name 'EveryoneIncludesAnonymous' -Expected 0 -DefaultIfMissing 0 -Severity FAIL -Desc 'Everyone не включает анонимных пользователей (CIS 2.3.10.5)'
Test-RegSetting -Path $lsa -Name 'RunAsPPL'           -Expected 1 -Op ge -Severity WARN -Desc 'LSA Protection (LSASS как protected process, CIS L2)'
Test-RegSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' `
    -Expected 0 -DefaultIfMissing 0 -Severity FAIL -Desc 'WDigest: пароли в открытом виде в памяти отключены (CIS 18.4.7)'

Test-RegSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' `
    -Expected 255 -Severity WARN -Desc 'AutoPlay отключён для всех типов дисков (CIS 18.10.8.3)'
Test-RegSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' `
    -Expected 1 -Severity WARN -Desc 'AutoRun: команды autorun.inf не выполняются (CIS 18.10.8.2)'

# TLS/SSL (SCHANNEL) - ISO 27001 A.8.24
foreach ($proto in 'SSL 2.0', 'SSL 3.0') {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
    $en = Get-RegValue $k 'Enabled'
    if ($en -eq 1) { Add-Fail "SCHANNEL: протокол ${proto} (сервер) явно ВКЛЮЧЁН" "New-ItemProperty -Path '$k' -Name Enabled -Value 0 -PropertyType DWord -Force" }
    else { Add-Pass "SCHANNEL: протокол ${proto} (сервер) отключён (Enabled=$(if ($null -eq $en) { 'не задан, default ОС = выключен' } else { $en }))" }
}
foreach ($proto in 'TLS 1.0', 'TLS 1.1') {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
    $en = Get-RegValue $k 'Enabled'
    $remTls = "New-Item -Path '$k' -Force | Out-Null; New-ItemProperty -Path '$k' -Name Enabled -Value 0 -PropertyType DWord -Force; New-ItemProperty -Path '$k' -Name DisabledByDefault -Value 1 -PropertyType DWord -Force (проверить совместимость приложений)"
    if ($en -eq 0) { Add-Pass "SCHANNEL: протокол ${proto} (сервер) явно отключён" }
    elseif ($en -eq 1) { Add-Warn "SCHANNEL: протокол ${proto} (сервер) явно ВКЛЮЧЁН" $remTls }
    else { Add-Warn "SCHANNEL: протокол ${proto} (сервер) не отключён явно (поведение зависит от версии ОС)" $remTls }
}

# Антивирус / EDR
$mp = Get-MpComputerStatus
if ($mp -and $null -ne $mp.AMServiceEnabled) {
    if ($mp.AMServiceEnabled) { Add-Pass 'Microsoft Defender Antivirus: служба включена' }
    else { Add-Fail 'Microsoft Defender Antivirus: служба отключена' 'Set-Service WinDefend -StartupType Automatic; Start-Service WinDefend (проверить GPO/стороннее AV)' }
    if ($mp.RealTimeProtectionEnabled) { Add-Pass 'Defender: защита в реальном времени включена' }
    else { Add-Fail 'Defender: защита в реальном времени ОТКЛЮЧЕНА' 'Set-MpPreference -DisableRealtimeMonitoring $false' }
    if ($mp.IsTamperProtected) { Add-Pass 'Defender: Tamper Protection включена' }
    else { Add-Warn 'Defender: Tamper Protection не включена' 'Включить через Windows Security > Virus & threat protection settings (или Intune)' }
    $age = $mp.AntivirusSignatureAge
    if ($null -ne $age -and $age -le 7) { Add-Pass "Defender: сигнатуры обновлены ${age} дн. назад" }
    else { Add-Warn "Defender: сигнатурам ${age} дн. (рекомендуется <= 7)" 'Update-MpSignature' }
} else {
    $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object { $_.displayName })
    if ($av.Count -gt 0) { Add-Info "Defender недоступен; зарегистрированные AV/EDR: $($av -join ', ') - проверьте их статус в консоли управления" }
    else { Add-Fail 'Антивирус/EDR не обнаружен (Defender недоступен, SecurityCenter2 пуст)' 'Установить и включить AV/EDR; на серверах проверить, что Defender не удалён (Get-WindowsFeature Windows-Defender)' }
}

# Шифрование диска и Secure Boot
$bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($bl) {
    if ("$($bl.ProtectionStatus)" -eq 'On') { Add-Pass "BitLocker: системный том ${env:SystemDrive} защищён (ProtectionStatus=On)" }
    else { Add-Warn "BitLocker: системный том ${env:SystemDrive} не защищён (ProtectionStatus=$($bl.ProtectionStatus)) (ISO 27001 A.8.24, CIS L2)" "Enable-BitLocker -MountPoint ${env:SystemDrive} -EncryptionMethod XtsAes256 -RecoveryPasswordProtector" }
} else { Add-Info 'BitLocker недоступен (модуль/компонент не установлен) - проверка шифрования диска пропущена' }

try {
    if (Confirm-SecureBootUEFI -ErrorAction Stop) { Add-Pass 'Secure Boot включён' }
    else { Add-Warn 'Secure Boot отключён' 'Включить Secure Boot в UEFI/настройках гипервизора (Gen2 VM)' }
} catch { Add-Info 'Secure Boot: не поддерживается или Legacy BIOS (проверка пропущена)' }

# ============================================================================
# 7. ИТОГОВАЯ СВОДКА
# ============================================================================

Start-Section '7. ИТОГОВАЯ СВОДКА АУДИТА'
$total = $script:CountPass + $script:CountWarn + $script:CountFail
Write-Log "  PASS : $script:CountPass" 'Green'
Write-Log "  WARN : $script:CountWarn" 'Yellow'
Write-Log "  FAIL : $script:CountFail" 'Red'
Write-Log "  INFO : $script:CountInfo"
Write-Log "  Всего классифицированных проверок: $total"
Write-Log ''
if ($script:CountFail -gt 0) {
    Write-Log '  РЕЗУЛЬТАТ: обнаружены критические несоответствия (FAIL). Требуется устранение.' 'Red'; $ExitCode = 2
} elseif ($script:CountWarn -gt 0) {
    Write-Log '  РЕЗУЛЬТАТ: критических несоответствий нет, но есть замечания (WARN).' 'Yellow'; $ExitCode = 1
} else {
    Write-Log '  РЕЗУЛЬТАТ: все проверки пройдены успешно.' 'Green'; $ExitCode = 0
}

# ============================================================================
# 8. СОХРАНЕНИЕ ТЕКСТОВОГО ОТЧЁТА
# ============================================================================

$saveOk = $true
try {
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction Stop | Out-Null
        # отчёт содержит чувствительные данные: только SYSTEM и Administrators
        & icacls.exe $OutputDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
    }
    $hdr = @(
        '==================================================================='
        ' Security Audit Report (CIS / ISO 27001) - Windows'
        " Host: $HostFqdn  Date: $script:RunTs"
        '==================================================================='
    )
    Add-Content -LiteralPath $script:ReportFile -Value ($hdr + $script:TextBuffer.ToArray()) -Encoding UTF8 -ErrorAction Stop
} catch { $saveOk = $false }
if ($saveOk) { Write-Log ''; Write-Log "Текстовый отчёт сохранён/дополнен: $script:ReportFile" }
else { Write-Log ''; Write-Log "[WARN] Не удалось записать $script:ReportFile" 'Yellow' }

# ============================================================================
# 9. ГЕНЕРАЦИЯ HTML-ОТЧЁТА
# ============================================================================

function ConvertTo-HtmlText { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

function New-HtmlReport {
    $t = $script:CountPass + $script:CountWarn + $script:CountFail
    $pP = 0; $wP = 0; $fP = 0
    if ($t -gt 0) {
        $pP = [int][math]::Floor($script:CountPass * 100 / $t)
        $wP = [int][math]::Floor($script:CountWarn * 100 / $t)
        $fP = 100 - $pP - $wP
    }
    $pw = $pP + $wP
    $css = @'
:root{--bg:#0f1115;--panel:#171a21;--border:#262b36;--text:#e6e9ef;--muted:#8b93a7;
      --pass:#2ecc71;--warn:#f5c542;--fail:#ff5c5c;--info:#5aa9e6;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Segoe UI',Roboto,Arial,sans-serif;line-height:1.5}
header{padding:28px 40px;border-bottom:1px solid var(--border);background:linear-gradient(135deg,#171a21,#10131a)}
header h1{margin:0 0 6px;font-size:21px}
header .meta{color:var(--muted);font-size:13px}
header .auditor{display:inline-flex;align-items:center;gap:8px;margin-top:10px;background:#1c202a;border:1px solid var(--border);border-radius:8px;padding:6px 12px;font-size:12.5px;color:#c6d0e0}
header .auditor b{color:var(--text)}
.wrap{max-width:1100px;margin:0 auto;padding:24px 40px 60px}
.top-row{display:flex;gap:24px;flex-wrap:wrap;align-items:center;margin:24px 0 10px}
.summary{display:flex;gap:16px;flex-wrap:wrap;flex:1}
.card{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px 18px}
.card .num{font-size:28px;font-weight:700}
.card.pass .num{color:var(--pass)} .card.warn .num{color:var(--warn)}
.card.fail .num{color:var(--fail)} .card.info .num{color:var(--info)}
.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.bar{height:10px;border-radius:6px;overflow:hidden;display:flex;background:#0b0d12;margin:14px 0 28px;border:1px solid var(--border)}
.bar span{height:100%}
.donut-wrap{flex:0 0 auto;display:flex;flex-direction:column;align-items:center;gap:10px}
.donut{width:150px;height:150px;border-radius:50%;position:relative}
.donut-hole{position:absolute;inset:16px;border-radius:50%;background:var(--panel);display:flex;flex-direction:column;align-items:center;justify-content:center;border:1px solid var(--border)}
.donut-hole .pct{font-size:22px;font-weight:700}
.donut-hole .lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.donut-legend{display:flex;gap:14px;font-size:11.5px;color:var(--muted)}
.donut-legend span{display:inline-flex;align-items:center;gap:5px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.dot.pass{background:var(--pass)} .dot.warn{background:var(--warn)} .dot.fail{background:var(--fail)}
.verdict{padding:14px 18px;border-radius:10px;font-weight:600;margin-bottom:28px;border:1px solid var(--border)}
.verdict.fail{background:#2a1414;color:var(--fail);border-color:#4a1f1f}
.verdict.warn{background:#2a2414;color:var(--warn);border-color:#4a3f1f}
.verdict.pass{background:#132a1b;color:var(--pass);border-color:#1f4a2c}
section.block{margin-bottom:22px;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
section.block h2{margin:0;padding:14px 20px;font-size:15px;background:#1c202a;border-bottom:1px solid var(--border)}
.row{display:flex;gap:12px;padding:9px 20px;border-bottom:1px solid #1d212b;font-size:13.5px;align-items:flex-start}
.row:last-child{border-bottom:none}
.badge{flex:0 0 60px;text-align:center;border-radius:5px;padding:2px 0;font-size:11px;font-weight:700;letter-spacing:.03em;height:fit-content}
.badge.pass{background:#132a1b;color:var(--pass)} .badge.warn{background:#2a2414;color:var(--warn)}
.badge.fail{background:#2a1414;color:var(--fail)} .badge.info{background:#111f2e;color:var(--info)}
.msg{flex:1;color:var(--text);word-break:break-word}
.fix{margin-top:4px;font-size:12px;color:var(--muted)}
.fix b{color:#c6d0e0}
footer{color:var(--muted);font-size:12px;text-align:center;padding:24px}
@media (max-width:600px){header,.wrap{padding-left:16px;padding-right:16px}}
'@
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>Аудит безопасности - $(ConvertTo-HtmlText $HostFqdn)</title><style>")
    [void]$sb.AppendLine($css)
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine(@"
<header>
  <h1>Аудит безопасности - CIS Benchmark / ISO 27001 (Windows)</h1>
  <div class="meta">Хост: $(ConvertTo-HtmlText $HostFqdn) &nbsp;&bull;&nbsp; ОС: $(ConvertTo-HtmlText $OsInfo) &nbsp;&bull;&nbsp; Дата: $(ConvertTo-HtmlText $script:RunTs) &nbsp;&bull;&nbsp; Скрипт v$script:ScriptVersion</div>
  <div class="auditor">&#128737; Аудитор: <b>$(ConvertTo-HtmlText $script:AuditorName)</b></div>
</header>
<div class="wrap">
  <div class="top-row">
    <div class="summary">
      <div class="card pass"><div class="num">$($script:CountPass)</div><div class="lbl">Pass</div></div>
      <div class="card warn"><div class="num">$($script:CountWarn)</div><div class="lbl">Warn</div></div>
      <div class="card fail"><div class="num">$($script:CountFail)</div><div class="lbl">Fail</div></div>
      <div class="card info"><div class="num">$($script:CountInfo)</div><div class="lbl">Info</div></div>
    </div>
    <div class="donut-wrap">
      <div class="donut" style="background:conic-gradient(var(--pass) 0% ${pP}%, var(--warn) ${pP}% ${pw}%, var(--fail) ${pw}% 100%)">
        <div class="donut-hole"><div class="pct">${pP}%</div><div class="lbl">PASS</div></div>
      </div>
      <div class="donut-legend">
        <span><i class="dot pass"></i>Pass $($script:CountPass)</span>
        <span><i class="dot warn"></i>Warn $($script:CountWarn)</span>
        <span><i class="dot fail"></i>Fail $($script:CountFail)</span>
      </div>
    </div>
  </div>
  <div class="bar"><span style="width:${pP}%;background:var(--pass)"></span><span style="width:${wP}%;background:var(--warn)"></span><span style="width:${fP}%;background:var(--fail)"></span></div>
"@)
    if ($script:CountFail -gt 0) {
        [void]$sb.AppendLine("  <div class=""verdict fail"">Обнаружены критические несоответствия (FAIL: $($script:CountFail)). Требуется устранение перед подтверждением соответствия ISO/IEC 27001.</div>")
    } elseif ($script:CountWarn -gt 0) {
        [void]$sb.AppendLine("  <div class=""verdict warn"">Критических несоответствий нет, есть замечания (WARN: $($script:CountWarn)).</div>")
    } else {
        [void]$sb.AppendLine('  <div class="verdict pass">Все проверки пройдены успешно.</div>')
    }
    $prev = $null; $open = $false
    foreach ($f in $script:Findings) {
        if ($f.Section -ne $prev) {
            if ($open) { [void]$sb.AppendLine('  </section>') }
            [void]$sb.AppendLine("  <section class=""block""><h2>$(ConvertTo-HtmlText $f.Section)</h2>")
            $open = $true; $prev = $f.Section
        }
        $row = "    <div class=""row""><div class=""badge $($f.Level.ToLower())"">$($f.Level)</div><div class=""msg"">$(ConvertTo-HtmlText $f.Message)"
        if ($f.Remediation) { $row += "<div class=""fix""><b>Рекомендация:</b> $(ConvertTo-HtmlText $f.Remediation)</div>" }
        [void]$sb.AppendLine($row + '</div></div>')
    }
    if ($open) { [void]$sb.AppendLine('  </section>') }
    [void]$sb.AppendLine("</div><footer>$(ConvertTo-HtmlText $script:AuditorName) &bull; windows_cis_audit.ps1 v$script:ScriptVersion &bull; $(ConvertTo-HtmlText $script:RunTs) &bull; Только для внутреннего использования</footer></body></html>")
    return $sb.ToString()
}

try {
    Set-Content -LiteralPath $script:HtmlFile -Value (New-HtmlReport) -Encoding UTF8 -ErrorAction Stop
    Write-Log "HTML-отчёт сохранён: $script:HtmlFile"
} catch {
    Write-Log "[WARN] Не удалось создать HTML-отчёт ${script:HtmlFile}: $($_.Exception.Message)" 'Yellow'
}

exit $ExitCode
