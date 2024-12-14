# proc_creation_win_powershell_shadowcopy_deletion

## Title
Deletion of Volume Shadow Copies via WMI with PowerShell

## ID
21ff4ca9-f13a-41ad-b828-0077b2af2e40

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-20

## Tags
attack.impact, attack.t1490

## Description
Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-5---windows---delete-volume-shadow-copies-via-wmi-with-powershell
https://www.elastic.co/guide/en/security/current/volume-shadow-copy-deletion-via-powershell.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".Delete()" OR TgtProcCmdLine containsCIS "Remove-WmiObject" OR TgtProcCmdLine containsCIS "rwmi" OR TgtProcCmdLine containsCIS "Remove-CimInstance" OR TgtProcCmdLine containsCIS "rcim") AND (TgtProcCmdLine containsCIS "Get-WmiObject" OR TgtProcCmdLine containsCIS "gwmi" OR TgtProcCmdLine containsCIS "Get-CimInstance" OR TgtProcCmdLine containsCIS "gcim") AND TgtProcCmdLine containsCIS "Win32_ShadowCopy"))

```