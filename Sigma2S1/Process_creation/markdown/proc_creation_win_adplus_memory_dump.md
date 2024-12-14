# proc_creation_win_adplus_memory_dump

## Title
Potential Adplus.EXE Abuse

## ID
2f869d59-7f6a-4931-992c-cce556ff2d53

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-09

## Tags
attack.defense-evasion, attack.execution, attack.t1003.001

## Description
Detects execution of "AdPlus.exe", a binary that is part of the Windows SDK that can be used as a LOLBIN in order to dump process memory and execute arbitrary commands.

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Adplus/
https://twitter.com/nas_bench/status/1534916659676422152
https://twitter.com/nas_bench/status/1534915321856917506

## False Positives
Legitimate usage of Adplus for debugging purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -hang " OR TgtProcCmdLine containsCIS " -pn " OR TgtProcCmdLine containsCIS " -pmn " OR TgtProcCmdLine containsCIS " -p " OR TgtProcCmdLine containsCIS " -po " OR TgtProcCmdLine containsCIS " -c " OR TgtProcCmdLine containsCIS " -sc ") AND TgtProcImagePath endswithCIS "\adplus.exe"))

```