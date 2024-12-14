# proc_creation_win_devinit_lolbin_usage

## Title
Arbitrary MSI Download Via Devinit.EXE

## ID
90d50722-0483-4065-8e35-57efaadd354d

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-11

## Tags
attack.execution, attack.defense-evasion, attack.t1218

## Description
Detects a certain command line flag combination used by "devinit.exe", which can be abused as a LOLBIN to download arbitrary MSI packages on a Windows system

## References
https://twitter.com/mrd0x/status/1460815932402679809
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devinit/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -t msi-install " AND TgtProcCmdLine containsCIS " -i http"))

```