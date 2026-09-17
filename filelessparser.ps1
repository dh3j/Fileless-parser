#requires -Version 5.1
<#[CmdletBinding()]
.SYNOPSIS
  Read-only Windows execution-telemetry triage for PowerShell and CMD.
.DESCRIPTION
  This defensive tool reads existing event logs and Prefetch metadata. It does not
  delete logs, alter policy, stop processes, or modify the system. Results are
  heuristic triage labels: "legit" does not mean safe, and "suspicious" is not proof.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
try { $Host.UI.RawUI.WindowTitle = 'FILELESS PARSER' } catch {}
$AnsiOrange = "$([char]27)[38;2;251;84;43m"
$AnsiReset  = "$([char]27)[0m"

function C {
    param([string]$Text, [string]$Color = 'White', [switch]$NoNewline)
    if ($Color -eq 'Orange') {
        Write-Host ($AnsiOrange + $Text + $AnsiReset) -NoNewline:$NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
    }
}

function Header {
    Clear-Host
    C '███████╗██╗██╗     ███████╗██╗     ███████╗███████╗███████╗' 'Orange'
    C '██╔════╝██║██║     ██╔════╝██║     ██╔════╝██╔════╝██╔════╝' 'Orange'
    C '█████╗  ██║██║     █████╗  ██║     █████╗  ███████╗███████╗' 'Orange'
    C '██╔══╝  ██║██║     ██╔══╝  ██║     ██╔══╝  ╚════██║╚════██║' 'Orange'
    C '██║     ██║███████╗███████╗███████╗███████╗███████║███████║' 'Orange'
    C '╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝' 'Orange'
    C '                         FILELESS PARSER' 'Orange'
    C ''
    C '                         Made with ♥ by dh3j' 'Gray'
    C ''
    C '=== ANALYSIS MODE ===' 'Orange'
}

function Get-EventsSafe {
    param([string]$LogName, [int[]]$Ids, [int]$MaxEvents = 1000)
    try { @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Ids } -MaxEvents $MaxEvents) }
    catch { @() }
}

function Get-EventDataValue {
    param([object]$Event, [string]$Name)
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name -eq $Name) { return [string]$node.'#text' }
        }
    } catch {}
    return $null
}

function Shorten-Text {
    param([string]$Text, [int]$Length = 150)
    $Text = ($Text -replace '\s+', ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($Text)) { return '[No command line or script content recorded]' }
    if ($Text.Length -gt $Length) { return $Text.Substring(0, $Length) + '...' }
    return $Text
}

function Test-SuspiciousText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $patterns = @(
        '(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*(?:-enc|-encodedcommand|\s-e\s)',
        '(?i)\b(?:iex|invoke-expression)\b',
        '(?i)(?:frombase64string|downloadstring|downloadfile|webclient|invoke-webrequest|\biwr\b|start-bitstransfer)',
        '(?i)(?:amsiutils|amsiinitfailed|set-mppreference)',
        '(?i)(?:reflection\.assembly|add-type|virtualalloc|createthread|marshal\]::copy)',
        '(?i)\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|cscript|wscript|installutil)\b',
        '(?i)\b(?:cmd|cmd\.exe)\b.*(?:/c|/r)',
        '(?i)(?:wevtutil\s+(?:cl|clear-log)|clear-eventlog|remove-eventlog)',
        '(?i)(?:-windowstyle\s+hidden|\bhidden\b|\bbypass\b|\bnop\b)'
    )
    foreach ($pattern in $patterns) { if ($Text -match $pattern) { return $true } }
    return $false
}

function Show-Result {
    param(
        [datetime]$Time,
        [string]$Source,
        [string]$Command,
        [string]$Extra = ''
    )
    $label = if (Test-SuspiciousText $Command) { 'suspicious' } else { 'legit' }
    $text = Shorten-Text $Command 150
    $suffix = if ($Extra) { " | $Extra" } else { '' }
    $line = '[{0}] [{1}] {2}{3} | {4}' -f $Time.ToString('yyyy-MM-dd HH:mm:ss'), $Source, $text, $suffix, $label
    if ($label -eq 'suspicious') { C $line 'Red' } else { C $line 'Green' }
}

function Scan-PowerShell {
    C "`n--- POWERSHELL TELEMETRY ---" 'Orange'
    $logs = @('Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational')
    $events = @()
    foreach ($log in $logs) { $events += Get-EventsSafe $log @(400,403,4103,4104,4105,4106) 1000 }
    $events = @($events | Sort-Object TimeCreated -Descending)
    C ("PowerShell events found: {0}" -f $events.Count) 'White'
    if (!$events) { C 'No PowerShell telemetry available. Script Block Logging may be disabled.' 'Orange'; return }
    foreach ($event in ($events | Select-Object -First 150)) {
        $content = $event.Message
        Show-Result -Time $event.TimeCreated -Source ("POWERSHELL-{0}" -f $event.Id) -Command $content
    }
}

function Scan-SysmonProcessCreation {
    C "`n--- SYSMON PROCESS CREATION ---" 'Orange'
    $events = Get-EventsSafe 'Microsoft-Windows-Sysmon/Operational' @(1) 2000
    if (!$events) { C 'Sysmon Event ID 1 is unavailable. Continuing with Security Event ID 4688.' 'Orange'; return }
    $count = 0
    foreach ($event in ($events | Sort-Object TimeCreated -Descending)) {
        $image = Get-EventDataValue $event 'Image'
        $parent = Get-EventDataValue $event 'ParentImage'
        $command = Get-EventDataValue $event 'CommandLine'
        $watch = '(?i)\\(?:cmd|powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|cscript|wscript|installutil)\.exe$'
        if (($image -match $watch) -or (Test-SuspiciousText $command)) {
            $count++
            Show-Result -Time $event.TimeCreated -Source 'SYSMON-1' -Command $command -Extra ("image: {0}; parent: {1}" -f $image,$parent)
        }
    }
    C ("Sysmon matching records: {0}" -f $count) 'White'
}

function Scan-SecurityProcessCreation {
    C "`n--- SECURITY PROCESS CREATION (4688) ---" 'Orange'
    $events = Get-EventsSafe 'Security' @(4688) 2000
    if (!$events) { C 'No 4688 records available. Run as Administrator; process-creation auditing may be disabled.' 'Orange'; return }
    $count = 0
    foreach ($event in ($events | Sort-Object TimeCreated -Descending)) {
        $image = Get-EventDataValue $event 'NewProcessName'
        $parent = Get-EventDataValue $event 'ParentProcessName'
        $command = Get-EventDataValue $event 'CommandLine'
        $watch = '(?i)\\(?:cmd|powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|cscript|wscript|installutil)\.exe$'
        if (($image -match $watch) -or (Test-SuspiciousText $command)) {
            $count++
            if ([string]::IsNullOrWhiteSpace($command)) { $command = $image }
            Show-Result -Time $event.TimeCreated -Source 'SECURITY-4688' -Command $command -Extra ("image: {0}; parent: {1}" -f $image,$parent)
        }
    }
    C ("Security 4688 matching records: {0}" -f $count) 'White'
}

function Scan-PrefetchEvidence {
    C "`n--- PREFETCH EXECUTION EVIDENCE ---" 'Orange'
    $path = Join-Path $env:WINDIR 'Prefetch'
    if (!(Test-Path -LiteralPath $path)) { C 'Prefetch directory is unavailable.' 'Orange'; return }
    $filters = @('CMD-*.pf','POWERSHELL-*.pf','PWSH-*.pf','MSHTA-*.pf','RUNDLL32-*.pf','REGSVR32-*.pf','CERTUTIL-*.pf','BITSADMIN-*.pf','WMIC-*.pf','CSCRIPT-*.pf','WSCRIPT-*.pf','INSTALLUTIL-*.pf')
    $files = foreach ($filter in $filters) { Get-ChildItem -LiteralPath $path -Filter $filter -File }
    $files = @($files | Sort-Object LastWriteTime -Descending -Unique)
    if (!$files) { C 'No monitored Prefetch records found.' 'Green'; return }
    foreach ($file in ($files | Select-Object -First 100)) {
        C ('[{0}] [PREFETCH] {1} | artifact only: executable likely ran; arguments unavailable' -f $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'),$file.Name) 'Yellow'
    }
}

function Scan-Cmd {
    C "`n=== CMD / PROCESS EXECUTION TRIAGE ===" 'Orange'
    Scan-SysmonProcessCreation
    Scan-SecurityProcessCreation
    Scan-PrefetchEvidence
}

function Scan-EventvwrDeletion {
    C "`n--- EVENT LOG CLEARING CHECK ---" 'Orange'
    $events = @()
    $events += Get-EventsSafe 'Security' @(1102) 100
    $events += Get-EventsSafe 'System' @(104) 100
    if ($events.Count) {
        C 'eventvwr logs were deleted' 'Red'
        foreach ($event in ($events | Sort-Object TimeCreated -Descending)) {
            $msg = Shorten-Text $event.Message 180
            C ('[{0}] [EVENT-CLEAR-{1}] {2}' -f $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'),$event.Id,$msg) 'Red'
        }
    } else { C 'No recorded event-log clearing events found (Security 1102 / System 104).' 'Green' }
}

function Scan-All { Scan-PowerShell; Scan-Cmd; Scan-EventvwrDeletion }

while ($true) {
    Header
    C '[1] Scan for all filelesses'
    C '[2] Scan for PowerShell filelesses'
    C '[3] Scan for CMD filelesses'
    C '[4] Check for eventvwr deletion'
    C '[Q] Exit'
    C "`nSelect option: " 'Orange' -NoNewline
    $choice = Read-Host
    switch ($choice.ToUpper()) {
        '1' { Scan-All }
        '2' { Scan-PowerShell }
        '3' { Scan-Cmd }
        '4' { Scan-EventvwrDeletion }
        'Q' { break }
        default { C 'Invalid option.' 'Red' }
    }
    if ($choice.ToUpper() -ne 'Q') {
        C "`nClick a button to exit..." 'Orange'
        try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { Read-Host | Out-Null }
    }
}
