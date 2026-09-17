#requires -Version 5.1
<#[CmdletBinding()]
.SYNOPSIS
  Defensive, read-only fileless-execution triage for Windows.
#>
[CmdletBinding()]
param()

$ErrorActionPreference='SilentlyContinue'
$Host.UI.RawUI.WindowTitle='FILELESS PARSER'
$ansiOrange="$([char]27)[38;2;251;84;43m"
$ansiReset="$([char]27)[0m"
function C([string]$s,[string]$color='White',[switch]$NoNewline){
  if($color -eq 'Orange'){ Write-Host ($ansiOrange+$s+$ansiReset) -NoNewline:$NoNewline }
  else { Write-Host $s -ForegroundColor $color -NoNewline:$NoNewline }
}
function Header {
  Clear-Host
  C '███████╗██╗██╗     ███████╗███████╗███████╗' 'Orange'
  C '██╔════╝██║██║     ██╔════╝██╔════╝██╔════╝' 'Orange'
  C '█████╗  ██║██║     █████╗  ███████╗███████╗' 'Orange'
  C '██╔══╝  ██║██║     ██╔══╝  ╚════██║╚════██║' 'Orange'
  C '██║     ██║███████╗███████╗███████║███████║' 'Orange'
  C '╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝' 'Orange'
  C '                 FILELESS PARSER' 'Orange'
  C ''
  C '                 Made with ♥ by dh3j' 'Gray'
  C ''
  C '=== ANALYSIS MODE ===' 'Orange'
}
function Get-EventsSafe([string]$log,[int[]]$ids,[int]$max=500){
  try { Get-WinEvent -FilterHashtable @{LogName=$log; Id=$ids} -MaxEvents $max }
  catch { @() }
}
function Show-Event([object]$e,[string]$label){
  $msg=($e.Message -replace '\s+',' ')
  if($msg.Length -gt 190){$msg=$msg.Substring(0,190)+'...'}
  C ('[{0}] {1} | {2} | {3}' -f $label,$e.TimeCreated,$e.Id,$msg) 'Gray'
}
function Scan-PowerShell {
  C "`n--- POWERSHELL TELEMETRY ---" 'Orange'
  $logs=@('Microsoft-Windows-PowerShell/Operational','PowerShellCore/Operational')
  $events=@(); foreach($l in $logs){$events += Get-EventsSafe $l @(4103,4104,4105,4106,400,403) 500}
  $patterns='FromBase64String|IEX|Invoke-Expression|DownloadString|DownloadFile|WebClient|Invoke-WebRequest|Start-BitsTransfer|Reflection.Assembly|Add-Type|VirtualAlloc|CreateThread|AmsiUtils|Set-MpPreference|EncodedCommand|bypass|hidden|nop| -e '
  $hits=$events | Where-Object { $_.Message -match $patterns }
  C ("Events inspected: {0}; suspicious matches: {1}" -f $events.Count,$hits.Count) 'White'
  foreach($e in ($hits | Sort-Object TimeCreated -Descending | Select-Object -First 50)){Show-Event $e 'PS'}
  if(!$events){C 'No PowerShell telemetry was available or logging is disabled.' 'Orange'}
}
function Scan-Cmd {
  C "`n--- CMD / PROCESS CREATION TELEMETRY ---" 'Orange'
  $events=Get-EventsSafe 'Security' @(4688) 500
  $patterns='cmd(\.exe)?\s+/c|powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|cscript|wscript|forfiles|installutil|eventvwr'
  $hits=$events | Where-Object {$_.Message -match $patterns}
  C ("Security 4688 events inspected: {0}; suspicious matches: {1}" -f $events.Count,$hits.Count) 'White'
  foreach($e in ($hits | Sort-Object TimeCreated -Descending | Select-Object -First 50)){Show-Event $e 'CMD/PROC'}
  if(!$events){C 'No 4688 telemetry available. Process Creation auditing may be disabled or access denied.' 'Orange'}
}
function Scan-EventvwrDeletion {
  C "`n--- EVENT LOG CLEARING CHECK ---" 'Orange'
  $events=@(); $events += Get-EventsSafe 'Security' @(1102) 100; $events += Get-EventsSafe 'System' @(104) 100
  if($events.Count){
    C 'eventvwr logs were deleted' 'Red'
    foreach($e in ($events | Sort-Object TimeCreated -Descending)){Show-Event $e 'CLEARED'}
    C 'Interpretation: these are recorded clear-log events; absence does not prove no deletion occurred.' 'Orange'
  } else { C 'No recorded event-log clearing events found (1102/104).' 'Green' }
}
function Scan-All { Scan-PowerShell; Scan-Cmd; Scan-EventvwrDeletion }
while($true){
  Header
  C '[1] Scan for all filelesses'
  C '[2] Scan for PowerShell filelesses'
  C '[3] Scan for CMD filelesses'
  C '[4] Check for eventvwr deletion'
  C '[Q] Exit'
  C "`nSelect option: " 'Orange' -NoNewline
  $choice=Read-Host
  switch($choice.ToUpper()){
    '1'{Scan-All}; '2'{Scan-PowerShell}; '3'{Scan-Cmd}; '4'{Scan-EventvwrDeletion}; 'Q'{break}
    default{C 'Invalid option.' 'Red'}
  }
  if($choice.ToUpper() -ne 'Q'){
    C "`nClick a button to exit..." 'Orange'
    $null=$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
  }
}
