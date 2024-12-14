# proc_creation_win_powershell_invocation_specific

## Title
Suspicious PowerShell Invocations - Specific - ProcessCreation

## ID
536e2947-3729-478c-9903-745aaffe60d2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-05

## Tags
attack.defense-evasion

## Description
Detects suspicious PowerShell invocation command parameters

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-nop" AND TgtProcCmdLine containsCIS " -w " AND TgtProcCmdLine containsCIS "hidden" AND TgtProcCmdLine containsCIS " -c " AND TgtProcCmdLine containsCIS "[Convert]::FromBase64String") OR (TgtProcCmdLine containsCIS " -w " AND TgtProcCmdLine containsCIS "hidden" AND TgtProcCmdLine containsCIS "-ep" AND TgtProcCmdLine containsCIS "bypass" AND TgtProcCmdLine containsCIS "-Enc") OR (TgtProcCmdLine containsCIS " -w " AND TgtProcCmdLine containsCIS "hidden" AND TgtProcCmdLine containsCIS "-noni" AND TgtProcCmdLine containsCIS "-nop" AND TgtProcCmdLine containsCIS " -c " AND TgtProcCmdLine containsCIS "iex" AND TgtProcCmdLine containsCIS "New-Object") OR (TgtProcCmdLine containsCIS "iex" AND TgtProcCmdLine containsCIS "New-Object" AND TgtProcCmdLine containsCIS "Net.WebClient" AND TgtProcCmdLine containsCIS ".Download") OR (TgtProcCmdLine containsCIS "powershell" AND TgtProcCmdLine containsCIS "reg" AND TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "\software\") OR (TgtProcCmdLine containsCIS "bypass" AND TgtProcCmdLine containsCIS "-noprofile" AND TgtProcCmdLine containsCIS "-windowstyle" AND TgtProcCmdLine containsCIS "hidden" AND TgtProcCmdLine containsCIS "new-object" AND TgtProcCmdLine containsCIS "system.net.webclient" AND TgtProcCmdLine containsCIS ".download")) AND (NOT (TgtProcCmdLine containsCIS "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1" OR TgtProcCmdLine containsCIS "Write-ChocolateyWarning"))))

```