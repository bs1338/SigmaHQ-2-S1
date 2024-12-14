# proc_creation_win_susp_data_exfiltration_via_cli

## Title
Potential Data Exfiltration Activity Via CommandLine Tools

## ID
7d1aaf3d-4304-425c-b7c3-162055e0b3ab

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-02

## Tags
attack.execution, attack.t1059.001

## Description
Detects the use of various CLI utilities exfiltrating data via web requests

## References
https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS "Invoke-WebRequest" OR TgtProcCmdLine containsCIS "iwr " OR TgtProcCmdLine containsCIS "wget " OR TgtProcCmdLine containsCIS "curl ") AND (TgtProcCmdLine containsCIS " -ur" AND TgtProcCmdLine containsCIS " -me" AND TgtProcCmdLine containsCIS " -b" AND TgtProcCmdLine containsCIS " POST ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\cmd.exe")) OR ((TgtProcCmdLine containsCIS "--ur" AND TgtProcImagePath endswithCIS "\curl.exe") AND (TgtProcCmdLine containsCIS " -d " OR TgtProcCmdLine containsCIS " --data ")) OR ((TgtProcCmdLine containsCIS "--post-data" OR TgtProcCmdLine containsCIS "--post-file") AND TgtProcImagePath endswithCIS "\wget.exe")) AND ((TgtProcCmdLine containsCIS "Get-Content" OR TgtProcCmdLine containsCIS "GetBytes" OR TgtProcCmdLine containsCIS "hostname" OR TgtProcCmdLine containsCIS "ifconfig" OR TgtProcCmdLine containsCIS "ipconfig" OR TgtProcCmdLine containsCIS "net view" OR TgtProcCmdLine containsCIS "netstat" OR TgtProcCmdLine containsCIS "nltest" OR TgtProcCmdLine containsCIS "qprocess" OR TgtProcCmdLine containsCIS "sc query" OR TgtProcCmdLine containsCIS "systeminfo" OR TgtProcCmdLine containsCIS "tasklist" OR TgtProcCmdLine containsCIS "ToBase64String" OR TgtProcCmdLine containsCIS "whoami") OR (TgtProcCmdLine containsCIS "type " AND TgtProcCmdLine containsCIS " > " AND TgtProcCmdLine containsCIS " C:\"))))

```