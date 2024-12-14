# proc_creation_win_powershell_invoke_webrequest_download

## Title
Suspicious Invoke-WebRequest Execution

## ID
5e3cc4d8-3e68-43db-8656-eaaeefdec9cc

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-02

## Tags
attack.command-and-control, attack.t1105

## Description
Detects a suspicious call to Invoke-WebRequest cmdlet where the and output is located in a suspicious location

## References
https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "curl " OR TgtProcCmdLine containsCIS "Invoke-WebRequest" OR TgtProcCmdLine containsCIS "iwr " OR TgtProcCmdLine containsCIS "wget ") AND (TgtProcCmdLine containsCIS " -ur" OR TgtProcCmdLine containsCIS " -o") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (TgtProcCmdLine containsCIS "\AppData\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Temp\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "%AppData%" OR TgtProcCmdLine containsCIS "%Public%" OR TgtProcCmdLine containsCIS "%Temp%" OR TgtProcCmdLine containsCIS "%tmp%" OR TgtProcCmdLine containsCIS ":\Windows\")))

```