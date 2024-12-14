# proc_creation_win_fsi_fsharp_code_execution

## Title
Use of FSharp Interpreters

## ID
b96b2031-7c17-4473-afe7-a30ce714db29

## Author
Christopher Peacock @SecurePeacock, SCYTHE @scythe_io

## Date
2022-06-02

## Tags
attack.execution, attack.t1059

## Description
Detects the execution of FSharp Interpreters "FsiAnyCpu.exe" and "FSi.exe"
Both can be used for AWL bypass and to execute F# code via scripts or inline.


## References
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac
https://bohops.com/2020/11/02/exploring-the-wdac-microsoft-recommended-block-rules-part-ii-wfc-fsi/
https://lolbas-project.github.io/lolbas/OtherMSBinaries/FsiAnyCpu/
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Fsi/

## False Positives
Legitimate use by a software developer.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\fsi.exe" OR TgtProcImagePath endswithCIS "\fsianycpu.exe"))

```