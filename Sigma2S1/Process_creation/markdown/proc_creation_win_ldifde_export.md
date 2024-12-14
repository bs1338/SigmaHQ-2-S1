# proc_creation_win_ldifde_export

## Title
Active Directory Structure Export Via Ldifde.EXE

## ID
4f7a6757-ff79-46db-9687-66501a02d9ec

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-14

## Tags
attack.exfiltration

## Description
Detects the execution of "ldifde.exe" in order to export organizational Active Directory structure.

## References
https://businessinsights.bitdefender.com/deep-dive-into-a-backdoordiplomacy-attack-a-study-of-an-attackers-toolkit
https://www.documentcloud.org/documents/5743766-Global-Threat-Report-2019.html
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731033(v=ws.11)

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-f" AND TgtProcImagePath endswithCIS "\ldifde.exe") AND (NOT TgtProcCmdLine containsCIS " -i")))

```