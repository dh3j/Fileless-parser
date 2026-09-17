#requires -Version 5.1
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ===================== GUI =====================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Fileless Activity Scanner"
$form.Size = New-Object System.Drawing.Size(980, 620)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.ForeColor = [System.Drawing.Color]::White
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$title = New-Object System.Windows.Forms.Label
$title.Text = "Fileless / Cheat / Log Tampering Scanner"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 255)
$title.Location = New-Object System.Drawing.Point(20, 15)
$title.AutoSize = $true
$form.Controls.Add($title)

$btnScan = New-Object System.Windows.Forms.Button
$btnScan.Text = "Scan Event Logs"
$btnScan.Size = New-Object System.Drawing.Size(160, 36)
$btnScan.Location = New-Object System.Drawing.Point(20, 55)
$btnScan.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$btnScan.FlatStyle = "Flat"
$btnScan.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($btnScan)

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear"
$btnClear.Size = New-Object System.Drawing.Size(80, 36)
$btnClear.Location = New-Object System.Drawing.Point(190, 55)
$btnClear.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnClear.FlatStyle = "Flat"
$btnClear.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($btnClear)

$status = New-Object System.Windows.Forms.Label
$status.Text = "Ready. Run as Administrator for best results."
$status.Location = New-Object System.Drawing.Point(290, 62)
$status.Size = New-Object System.Drawing.Size(650, 25)
$status.ForeColor = [System.Drawing.Color]::LightGray
$form.Controls.Add($status)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(20, 100)
$progress.Size = New-Object System.Drawing.Size(920, 18)
$progress.Style = "Continuous"
$form.Controls.Add($progress)

$list = New-Object System.Windows.Forms.ListView
$list.Location = New-Object System.Drawing.Point(20, 130)
$list.Size = New-Object System.Drawing.Size(920, 420)
$list.View = "Details"
$list.FullRowSelect = $true
$list.GridLines = $true
$list.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
$list.ForeColor = [System.Drawing.Color]::White
$list.Font = New-Object System.Drawing.Font("Consolas", 9)
$list.Columns.Add("Time", 150) | Out-Null
$list.Columns.Add("Severity", 90) | Out-Null
$list.Columns.Add("Log / Source", 180) | Out-Null
$list.Columns.Add("Event ID", 70) | Out-Null
$list.Columns.Add("Summary", 400) | Out-Null
$form.Controls.Add($list)

# ===================== HELPERS =====================
function Add-Finding {
    param($Time, $Severity, $Source, $Id, $Summary)
    $item = New-Object System.Windows.Forms.ListViewItem($Time)
    $item.SubItems.Add($Severity)
    $item.SubItems.Add($Source)
    $item.SubItems.Add("$Id")
    $item.SubItems.Add($Summary)

    switch ($Severity) {
        "CRITICAL" { $item.ForeColor = [System.Drawing.Color]::FromArgb(255, 80, 80) }
        "HIGH"     { $item.ForeColor = [System.Drawing.Color]::OrangeRed }
        "MEDIUM"   { $item.ForeColor = [System.Drawing.Color]::Orange }
        "INFO"     { $item.ForeColor = [System.Drawing.Color]::LightGreen }
        default    { $item.ForeColor = [System.Drawing.Color]::White }
    }
    $list.Items.Add($item) | Out-Null
}

function Get-SafeWinEvent {
    param($LogName, $Id, $Max = 200, $Days = 7)
    try {
        $start = (Get-Date).AddDays(-$Days)
        $filter = @{
            LogName   = $LogName
            Id        = $Id
            StartTime = $start
        }
        return Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop
    } catch {
        return @()
    }
}

# ===================== SCAN LOGIC =====================
$btnScan.Add_Click({
    $list.Items.Clear()
    $progress.Value = 0
    $status.Text = "Scanning... (this can take a few seconds)"
    $status.ForeColor = [System.Drawing.Color]::Yellow
    $form.Refresh()

    $foundSomething = $false
    $logsCleared = $false
    $progress.Value = 10

    # ---- 1. Log Clearing (highest priority) ----
    $clearedSec = Get-SafeWinEvent -LogName "Security" -Id 1102 -Max 50
    foreach ($e in $clearedSec) {
        $logsCleared = $true
        $foundSomething = $true
        Add-Finding $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") "CRITICAL" "Security" 1102 "AUDIT LOG WAS CLEARED"
    }

    $clearedSys = Get-SafeWinEvent -LogName "System" -Id 104 -Max 50
    foreach ($e in $clearedSys) {
        $logsCleared = $true
        $foundSomething = $true
        Add-Finding $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") "CRITICAL" "System" 104 "Event log was cleared"
    }
    $progress.Value = 30

    # ---- 2. PowerShell Script Block (fileless indicators) ----
    $suspiciousKeywords = @(
        "EncodedCommand", "-enc ", "-e ", "FromBase64String",
        "Invoke-Expression", "IEX ", "IEX(", "DownloadString",
        "DownloadFile", "WebClient", "Net.WebClient",
        "AmsiUtils", "amsiInitFailed", "AmsiScanBuffer",
        "Clear-EventLog", "Remove-EventLog", "ClearLog",
        "Reflection.Assembly", "Load(", "VirtualAlloc",
        "CreateThread", "WriteProcessMemory"
    )

    $psEvents = Get-SafeWinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -Id 4104 -Max 300 -Days 7
    foreach ($e in $psEvents) {
        $msg = $e.Message
        foreach ($kw in $suspiciousKeywords) {
            if ($msg -match [regex]::Escape($kw)) {
                $foundSomething = $true
                $short = ($msg -replace "`r`n", " ").Substring(0, [Math]::Min(180, $msg.Length))
                Add-Finding $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") "HIGH" "PowerShell/Operational" 4104 "Suspicious: $kw → $short"
                break
            }
        }
    }
    $progress.Value = 60

    # ---- 3. WMI permanent consumers ----
    $wmi = Get-SafeWinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -Id 5861 -Max 50
    foreach ($e in $wmi) {
        $foundSomething = $true
        Add-Finding $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") "HIGH" "WMI-Activity" 5861 "Permanent WMI Event Consumer created (possible persistence)"
    }
    $progress.Value = 75

    # ---- 4. Sysmon (if present) ----
    try {
        $sysmonExists = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
        $sys1 = Get-SafeWinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -Id 1 -Max 100 -Days 3
        # We only flag very obvious ones to keep noise low
        foreach ($e in $sys1) {
            if ($e.Message -match "powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32" -and
                $e.Message -match "EncodedCommand|-enc |IEX|DownloadString") {
                $foundSomething = $true
                Add-Finding $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") "HIGH" "Sysmon" 1 "Suspicious process creation (fileless indicators)"
            }
        }

        $sys8 = Get-SafeWinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -Id 8 -Max 30 -Days 7
        foreach ($e in $sys8) {
            $foundSomething = $true
            Add-Finding $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") "HIGH" "Sysmon" 8 "CreateRemoteThread (possible process injection)"
        }
    } catch {
        # Sysmon not installed - ignore
    }
    $progress.Value = 95

    # ---- Final status + alert ----
    if ($logsCleared) {
        $status.Text = "CRITICAL: Event logs were cleared! Something tried to cover tracks."
        $status.ForeColor = [System.Drawing.Color]::Red
        [System.Media.SystemSounds]::Exclamation.Play()
        [System.Windows.Forms.MessageBox]::Show(
            "Event logs have been CLEARED (Event ID 1102 / 104).`n`nThis is a strong indicator that someone (or a cheat/malware) tried to hide activity.",
            "LOGS CLEARED",
            "OK",
            "Warning"
        )
    }
    elseif (-not $foundSomething) {
        $status.Text = "No suspicious fileless activity or log clearing found in the last 7 days."
        $status.ForeColor = [System.Drawing.Color]::LightGreen
        [System.Media.SystemSounds]::Asterisk.Play()
        [System.Windows.Forms.MessageBox]::Show(
            "No clear signs of fileless cheats / log tampering found.`n`nNote: This only works if PowerShell Script Block Logging and other logs are enabled.",
            "Clean",
            "OK",
            "Information"
        )
    }
    else {
        $status.Text = "Suspicious activity detected! Review the list above."
        $status.ForeColor = [System.Drawing.Color]::Orange
        [System.Media.SystemSounds]::Exclamation.Play()
    }

    $progress.Value = 100
})

$btnClear.Add_Click({
    $list.Items.Clear()
    $status.Text = "Ready."
    $status.ForeColor = [System.Drawing.Color]::LightGray
    $progress.Value = 0
})

# Show the form
[void]$form.ShowDialog()