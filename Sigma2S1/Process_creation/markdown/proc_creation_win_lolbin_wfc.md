# proc_creation_win_lolbin_wfc

## Title
Use of Wfc.exe

## ID
49be8799-7b4d-4fda-ad23-cafbefdebbc5

## Author
Christopher Peacock @SecurePeacock, SCYTHE @scythe_io

## Date
2022-06-01

## Tags
attack.defense-evasion, attack.t1127

## Description
The Workflow Command-line Compiler can be used for AWL bypass and is listed in Microsoft's recommended block rules.

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wfc/
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac

## False Positives
Legitimate use by a software developer

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\wfc.exe")

```