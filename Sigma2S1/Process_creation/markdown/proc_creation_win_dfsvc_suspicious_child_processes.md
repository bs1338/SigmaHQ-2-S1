# proc_creation_win_dfsvc_suspicious_child_processes

## Title
Potentially Suspicious Child Process Of ClickOnce Application

## ID
67bc0e75-c0a9-4cfc-8754-84a505b63c04

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-12

## Tags
attack.execution, attack.defense-evasion

## Description
Detects potentially suspicious child processes of a ClickOnce deployment application

## References
https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\explorer.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe" OR TgtProcImagePath endswithCIS "\nltest.exe" OR TgtProcImagePath endswithCIS "\notepad.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\werfault.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath containsCIS "\AppData\Local\Apps\2.0\"))

```