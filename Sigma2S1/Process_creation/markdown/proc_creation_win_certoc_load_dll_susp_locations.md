# proc_creation_win_certoc_load_dll_susp_locations

## Title
Suspicious DLL Loaded via CertOC.EXE

## ID
84232095-ecca-4015-b0d7-7726507ee793

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects when a user installs certificates by using CertOC.exe to load the target DLL file.

## References
https://twitter.com/sblmsrsn/status/1445758411803480072?s=20
https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-fe98e74189873d6df72a15df2eaa0315c59ba9cdaca93ecd68afc4ea09194ef2
https://lolbas-project.github.io/lolbas/Binaries/Certoc/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -LoadDLL " OR TgtProcCmdLine containsCIS " /LoadDLL " OR TgtProcCmdLine containsCIS " â€“LoadDLL " OR TgtProcCmdLine containsCIS " â€”LoadDLL " OR TgtProcCmdLine containsCIS " â€•LoadDLL ") AND TgtProcImagePath endswithCIS "\certoc.exe" AND (TgtProcCmdLine containsCIS "\Appdata\Local\Temp\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "C:\Windows\Tasks\" OR TgtProcCmdLine containsCIS "C:\Windows\Temp\")))

```