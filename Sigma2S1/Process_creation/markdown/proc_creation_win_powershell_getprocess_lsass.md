# proc_creation_win_powershell_getprocess_lsass

## Title
PowerShell Get-Process LSASS

## ID
b2815d0d-7481-4bf0-9b6c-a4c48a94b349

## Author
Florian Roth (Nextron Systems)

## Date
2021-04-23

## Tags
attack.credential-access, attack.t1552.004

## Description
Detects a "Get-Process" cmdlet and it's aliases on lsass process, which is in almost all cases a sign of malicious activity

## References
https://web.archive.org/web/20220205033028/https://twitter.com/PythonResponder/status/1385064506049630211

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Get-Process lsas" OR TgtProcCmdLine containsCIS "ps lsas" OR TgtProcCmdLine containsCIS "gps lsas"))

```