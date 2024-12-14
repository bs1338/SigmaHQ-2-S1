# proc_creation_win_certoc_load_dll

## Title
DLL Loaded via CertOC.EXE

## ID
242301bc-f92f-4476-8718-78004a6efd9f

## Author
Austin Songer @austinsonger

## Date
2021-10-23

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects when a user installs certificates by using CertOC.exe to loads the target DLL file.

## References
https://twitter.com/sblmsrsn/status/1445758411803480072?s=20
https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-fe98e74189873d6df72a15df2eaa0315c59ba9cdaca93ecd68afc4ea09194ef2
https://lolbas-project.github.io/lolbas/Binaries/Certoc/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -LoadDLL " OR TgtProcCmdLine containsCIS " /LoadDLL " OR TgtProcCmdLine containsCIS " â€“LoadDLL " OR TgtProcCmdLine containsCIS " â€”LoadDLL " OR TgtProcCmdLine containsCIS " â€•LoadDLL ") AND TgtProcImagePath endswithCIS "\certoc.exe"))

```