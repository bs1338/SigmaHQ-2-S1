# file_event_win_uac_bypass_idiagnostic_profile

## Title
UAC Bypass Using IDiagnostic Profile - File

## ID
48ea844d-19b1-4642-944e-fe39c2cc1fec

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-03

## Tags
attack.execution, attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the creation of a file by "dllhost.exe" in System32 directory part of "IDiagnosticProfileUAC" UAC bypass technique

## References
https://github.com/Wh04m1001/IDiagnosticProfileUAC

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\DllHost.exe" AND TgtFilePath endswithCIS ".dll" AND TgtFilePath startswithCIS "C:\Windows\System32\"))

```