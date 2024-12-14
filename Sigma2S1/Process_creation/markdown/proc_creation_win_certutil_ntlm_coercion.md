# proc_creation_win_certutil_ntlm_coercion

## Title
Potential NTLM Coercion Via Certutil.EXE

## ID
6c6d9280-e6d0-4b9d-80ac-254701b64916

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-01

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects possible NTLM coercion via certutil using the 'syncwithWU' flag

## References
https://github.com/LOLBAS-Project/LOLBAS/issues/243

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -syncwithWU " AND TgtProcCmdLine containsCIS " \\") AND TgtProcImagePath endswithCIS "\certutil.exe"))

```