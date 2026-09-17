#requires -Version 5.1
<#[CmdletBinding()]
.SYNOPSIS
  Read-only Windows execution-telemetry triage for PowerShell and CMD.
.DESCRIPTION
  Reads existing logs and Prefetch metadata only. It does not modify the machine.
  "Legit" means no configured heuristic matched; it is not a safety guarantee.
  "Suspicious" is a triage signal, not proof of malware.
#>
[CmdletBinding()]
param()

$ErrorActionPreference='SilentlyContinue'
try{$Host.UI.RawUI.WindowTitle='FILELESS PARSER'}catch{}
$AnsiOrange="$([char]27)[38;2;251;84;43m"; $AnsiReset="$([char]27)[0m"
$script:Findings=New-Object System.Collections.Generic.List[object]
try{$script:BootTime=(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime}catch{$script:BootTime=$null}

function C { param([string]$Text,[string]$Color='White',[switch]$NoNewline)
  if($Color -eq 'Orange'){Write-Host ($AnsiOrange+$Text+$AnsiReset) -NoNewline:$NoNewline}else{Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline}
}
function Header {
  Clear-Host
  C '███████╗██╗██╗     ███████╗██╗     ███████╗███████╗███████╗' 'Orange'
  C '██╔════╝██║██║     ██╔════╝██║     ██╔════╝██╔════╝██╔════╝' 'Orange'
  C '█████╗  ██║██║     █████╗  ██║     █████╗  ███████╗███████╗' 'Orange'
  C '██╔══╝  ██║██║     ██╔══╝  ██║     ██╔══╝  ╚════██║╚════██║' 'Orange'
  C '██║     ██║███████╗███████╗███████╗███████╗███████║███████║' 'Orange'
  C '╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝' 'Orange'
  C '                         FILELESS PARSER' 'Orange'; C ''
  C '                         Made with ♥ by dh3j' 'Gray'; C ''
  C '=== ANALYSIS MODE ===' 'Orange'
}
function Ask-YesNo { param([string]$Question)
  C ("`n"+$Question+' (y/n): ') 'Orange' -NoNewline
  return ((Read-Host).Trim().ToLowerInvariant() -in @('y','yes'))
}
function Ask-InstanceOnly {
  if(Ask-YesNo 'Do you want to scan instance-only ones'){
    if($script:BootTime){C ("Filtering to activity since last Windows boot: {0}" -f $script:BootTime.ToString('yyyy-MM-dd HH:mm:ss')) 'Orange';return $script:BootTime}
    C 'Boot time unavailable; scanning all retained records.' 'Yellow'
  }
  return $null
}
function Get-EventsSafe { param([string]$LogName,[int[]]$Ids,[int]$MaxEvents=3000,[datetime]$Since)
  try{$filter=@{LogName=$LogName;Id=$Ids};if($Since){$filter.StartTime=$Since};@(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents)}catch{@()}
}
function Get-EventDataValue { param([object]$Event,[string]$Name)
  try{[xml]$xml=$Event.ToXml();foreach($node in $xml.Event.EventData.Data){if($node.Name -eq $Name){return [string]$node.'#text'}}}catch{};return $null
}
function Shorten-Text { param([string]$Text,[int]$Length=140)
  $Text=($Text -replace '\s+',' ').Trim();if([string]::IsNullOrWhiteSpace($Text)){return '[No command line recorded]'};if($Text.Length -gt $Length){return $Text.Substring(0,$Length)+'...'};return $Text
}
function Get-ProgramName { param([string]$Image,[string]$Command)
  if($Image){return [IO.Path]::GetFileName($Image)}
  if($Command -match '^\s*"?([^"\s]+(?:\.exe|\.com|\.bat|\.cmd|\.ps1)?)'){return [IO.Path]::GetFileName($Matches[1])}
  return 'Unknown process'
}
function Test-WindowsSystemProcess { param([string]$Image)
  if([string]::IsNullOrWhiteSpace($Image)){return $false};$root=[regex]::Escape($env:WINDIR);return ($Image -match "(?i)^$root\\(?:System32|SysWOW64|SystemApps|WinSxS)\\")
}
function Get-Triage { param([string]$Command,[string]$Image)
  $text="$Image $Command"
  if([string]::IsNullOrWhiteSpace($text)){return @{Label='Legit';Reason='No command line was recorded.'}}
  if($text -match '(?i)\b(?:wevtutil\s+(?:cl|clear-log)|clear-eventlog|remove-eventlog)'){return @{Label='Suspicious';Reason='Event-log clearing command detected.'}}
  if($text -match '(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*(?:-enc|-encodedcommand|\s-e\s)'){return @{Label='Suspicious';Reason='Encoded PowerShell command detected.'}}
  if($text -match '(?i)\b(?:iex|invoke-expression)\b'){return @{Label='Suspicious';Reason='PowerShell dynamic code execution detected.'}}
  if($text -match '(?i)(?:frombase64string|downloadstring|downloadfile|webclient|invoke-webrequest|\biwr\b|start-bitstransfer)'){return @{Label='Suspicious';Reason='Download, decoding, or remote-content execution behavior detected.'}}
  if($text -match '(?i)(?:amsiutils|amsiinitfailed|set-mppreference)'){return @{Label='Suspicious';Reason='Security-control or AMSI-related behavior detected.'}}
  if($text -match '(?i)(?:reflection\.assembly|add-type|virtualalloc|createthread|marshal\]::copy)'){return @{Label='Suspicious';Reason='In-memory code-loading behavior detected.'}}
  if($text -match '(?i)\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|cscript|wscript|installutil)\b'){return @{Label='Suspicious';Reason='Living-off-the-land utility used; review the command.'}}
  if($text -match '(?i)(?:-windowstyle\s+hidden|\bhidden\b|\bbypass\b|\bnop\b)'){return @{Label='Suspicious';Reason='Hidden window, execution-policy bypass, or no-profile behavior detected.'}}
  if(Test-WindowsSystemProcess $Image){return @{Label='Legit';Reason='Windows system executable; routine activity unless arguments look unusual.'}}
  return @{Label='Legit';Reason='No high-risk command pattern matched.'}
}
function Show-Result { param([datetime]$Time,[string]$Source,[string]$Image,[string]$Command,[string]$Parent='')
  $name=Get-ProgramName $Image $Command;$triage=Get-Triage $Command $Image;$short=Shorten-Text $Command 140
  $line='[{0}] [{1}] {2} | {3}' -f $Time.ToString('yyyy-MM-dd HH:mm:ss'),$Source,$name,$short
  if($Parent){$line+=' | Parent: '+(Get-ProgramName $Parent '')}
  $line+=" | $($triage.Label) - $($triage.Reason)"
  $script:Findings.Add([pscustomobject]@{Time=$Time;Source=$Source;Program=$name;Command=$short;Parent=(Get-ProgramName $Parent '');Status=$triage.Label;Description=$triage.Reason;Display=$line})
  if($triage.Label -eq 'Suspicious'){C $line 'Red'}else{C $line 'Green'}
}
function Scan-PowerShell { param([datetime]$Since)
  C "`n--- POWERSHELL TELEMETRY ---" 'Orange';$events=@();foreach($log in @('Microsoft-Windows-PowerShell/Operational','PowerShellCore/Operational')){$events+=Get-EventsSafe $log @(400,403,4103,4104,4105,4106) 3000 $Since};$events=@($events|Sort-Object TimeCreated -Descending)
  C ("PowerShell events found: {0}" -f $events.Count) 'White';if(!$events){C 'No PowerShell telemetry is available for the selected time range.' 'Orange';return};foreach($event in ($events|Select-Object -First 150)){Show-Result $event.TimeCreated ("POWERSHELL-{0}" -f $event.Id) 'powershell.exe' $event.Message ''}
}
function Scan-SysmonProcessCreation { param([datetime]$Since)
  C "`n--- SYSMON PROCESS CREATION ---" 'Orange';$events=Get-EventsSafe 'Microsoft-Windows-Sysmon/Operational' @(1) 4000 $Since;if(!$events){C 'Sysmon Event ID 1 is unavailable for the selected time range.' 'Orange';return};$count=0;$watch='(?i)\\(?:cmd|powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|cscript|wscript|installutil)\.exe$'
  foreach($event in ($events|Sort-Object TimeCreated -Descending)){$image=Get-EventDataValue $event 'Image';$parent=Get-EventDataValue $event 'ParentImage';$command=Get-EventDataValue $event 'CommandLine';if(($image -match $watch) -or ((Get-Triage $command $image).Label -eq 'Suspicious')){$count++;Show-Result $event.TimeCreated 'SYSMON-1' $image $command $parent}};C ("Sysmon relevant records: {0}" -f $count) 'White'
}
function Scan-SecurityProcessCreation { param([datetime]$Since)
  C "`n--- SECURITY PROCESS CREATION (4688) ---" 'Orange';$events=Get-EventsSafe 'Security' @(4688) 4000 $Since;if(!$events){C 'No Security 4688 records available. Run as Administrator; process-creation auditing may be disabled.' 'Orange';return};$count=0;$watch='(?i)\\(?:cmd|powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|cscript|wscript|installutil)\.exe$'
  foreach($event in ($events|Sort-Object TimeCreated -Descending)){$image=Get-EventDataValue $event 'NewProcessName';$parent=Get-EventDataValue $event 'ParentProcessName';$command=Get-EventDataValue $event 'CommandLine';if(($image -match $watch) -or ((Get-Triage $command $image).Label -eq 'Suspicious')){$count++;Show-Result $event.TimeCreated 'SECURITY-4688' $image $command $parent}};C ("Security 4688 relevant records: {0}" -f $count)
}
function Scan-PrefetchEvidence { param([datetime]$Since)
  C "`n--- PREFETCH EXECUTION EVIDENCE ---" 'Orange';$path=Join-Path $env:WINDIR 'Prefetch';if(!(Test-Path -LiteralPath $path)){C 'Prefetch directory is unavailable.' 'Orange';return};$filters=@('CMD-*.pf','POWERSHELL-*.pf','PWSH-*.pf','MSHTA-*.pf','RUNDLL32-*.pf','REGSVR32-*.pf','CERTUTIL-*.pf','BITSADMIN-*.pf','WMIC-*.pf','CSCRIPT-*.pf','WSCRIPT-*.pf','INSTALLUTIL-*.pf')
  $files=foreach($filter in $filters){Get-ChildItem -LiteralPath $path -Filter $filter -File};$files=@($files|Sort-Object LastWriteTime -Descending -Unique);if($Since){$files=@($files|Where-Object{$_.LastWriteTime -ge $Since})};if(!$files){C 'No monitored Prefetch records found for the selected time range.' 'Green';return}
  foreach($file in ($files|Select-Object -First 100)){$line='[{0}] [PREFETCH] {1} | Info - Execution artifact only; exact command arguments are unavailable.' -f $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'),$file.Name;$script:Findings.Add([pscustomobject]@{Time=$file.LastWriteTime;Source='PREFETCH';Program=$file.Name;Command='[Arguments unavailable]';Parent='';Status='Info';Description='Execution artifact only; exact command arguments are unavailable.';Display=$line});C $line 'Yellow'}
}
function Scan-Cmd { param([datetime]$Since);C "`n=== CMD / PROCESS EXECUTION TRIAGE ===" 'Orange';Scan-SysmonProcessCreation $Since;Scan-SecurityProcessCreation $Since;Scan-PrefetchEvidence $Since}
function Scan-EventvwrDeletion { param([datetime]$Since)
  C "`n--- EVENT LOG CLEARING CHECK ---" 'Orange';$events=@();$events+=Get-EventsSafe 'Security' @(1102) 100 $Since;$events+=Get-EventsSafe 'System' @(104) 100 $Since
  if($events.Count){C 'eventvwr logs were deleted' 'Red';foreach($event in ($events|Sort-Object TimeCreated -Descending)){$line='[{0}] [EVENT-CLEAR-{1}] Event Log Service | {2} | Suspicious - Recorded event-log clearing activity.' -f $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'),$event.Id,(Shorten-Text $event.Message 150);$script:Findings.Add([pscustomobject]@{Time=$event.TimeCreated;Source="EVENT-CLEAR-$($event.Id)";Program='Event Log Service';Command=(Shorten-Text $event.Message 150);Parent='';Status='Suspicious';Description='Recorded event-log clearing activity.';Display=$line});C $line 'Red'}}else{C 'No recorded event-log clearing events found for the selected time range.' 'Green'}
}
function Scan-All { param([datetime]$Since);Scan-PowerShell $Since;Scan-Cmd $Since;Scan-EventvwrDeletion $Since}
function Export-Findings {
  if($script:Findings.Count -eq 0){C 'Nothing was collected in this scan, so no report was exported.' 'Yellow';return}
  $desktop=[Environment]::GetFolderPath('Desktop');if([string]::IsNullOrWhiteSpace($desktop)){$desktop=$env:USERPROFILE+'\Desktop'}
  $stamp=Get-Date -Format 'yyyy-MM-dd_HH-mm-ss';$report=Join-Path $desktop ("FilelessParser_Report_$stamp.txt")
  $header=@('FILELESS PARSER REPORT','Made with ♥ by dh3j',('Generated: '+(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),('Last boot: '+$(if($script:BootTime){$script:BootTime.ToString('yyyy-MM-dd HH:mm:ss')}else{'Unavailable'})),'',('Findings: '+$script:Findings.Count),'')
  try{$header + ($script:Findings|ForEach-Object{$_.Display}) | Set-Content -LiteralPath $report -Encoding UTF8;C ("Report exported to: {0}" -f $report) 'Green'}catch{C ("Export failed: {0}" -f $_.Exception.Message) 'Red'}
}
while($true){
  Header;C '[1] Scan for all filelesses';C '[2] Scan for PowerShell filelesses';C '[3] Scan for CMD filelesses';C '[4] Check for eventvwr deletion';C '[Q] Exit';C "`nSelect option: " 'Orange' -NoNewline;$choice=Read-Host
  if($choice.ToUpper() -eq 'Q'){break};if($choice -notin @('1','2','3','4')){C 'Invalid option.' 'Red';Start-Sleep 1;continue}
  $script:Findings.Clear();$since=Ask-InstanceOnly;switch($choice){'1'{Scan-All $since};'2'{Scan-PowerShell $since};'3'{Scan-Cmd $since};'4'{Scan-EventvwrDeletion $since}}
  if(Ask-YesNo 'Do you want to export this scan to a report on your Desktop'){Export-Findings}
  C "`nClick a button to exit..." 'Orange';try{$null=$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')}catch{Read-Host|Out-Null}
}
