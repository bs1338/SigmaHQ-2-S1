# proc_creation_win_bcdedit_susp_execution

## Title
Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE

## ID
c9fbe8e9-119d-40a6-9b59-dd58a5d84429

## Author
@neu5ron

## Date
2019-02-07

## Tags
attack.defense-evasion, attack.t1070, attack.persistence, attack.t1542.003

## Description
Detects potential malicious and unauthorized usage of bcdedit.exe

## References
https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
https://twitter.com/malwrhunterteam/status/1372536434125512712/photo/2

## False Positives


## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "delete" OR TgtProcCmdLine containsCIS "deletevalue" OR TgtProcCmdLine containsCIS "import" OR TgtProcCmdLine containsCIS "safeboot" OR TgtProcCmdLine containsCIS "network") AND TgtProcImagePath endswithCIS "\bcdedit.exe"))

```