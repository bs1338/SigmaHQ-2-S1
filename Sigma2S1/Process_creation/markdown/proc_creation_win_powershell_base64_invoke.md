# proc_creation_win_powershell_base64_invoke

## Title
PowerShell Base64 Encoded Invoke Keyword

## ID
6385697e-9f1b-40bd-8817-f4a91f40508e

## Author
pH-T (Nextron Systems), Harjot Singh, @cyb3rjy0t

## Date
2022-05-20

## Tags
attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1027

## Description
Detects UTF-8 and UTF-16 Base64 encoded powershell 'Invoke-' calls

## References
https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -e" AND (TgtProcCmdLine containsCIS "SQBuAHYAbwBrAGUALQ" OR TgtProcCmdLine containsCIS "kAbgB2AG8AawBlAC0A" OR TgtProcCmdLine containsCIS "JAG4AdgBvAGsAZQAtA" OR TgtProcCmdLine containsCIS "SW52b2tlL" OR TgtProcCmdLine containsCIS "ludm9rZS" OR TgtProcCmdLine containsCIS "JbnZva2Ut") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```