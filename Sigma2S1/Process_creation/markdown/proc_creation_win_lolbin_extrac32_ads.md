# proc_creation_win_lolbin_extrac32_ads

## Title
Suspicious Extrac32 Alternate Data Stream Execution

## ID
4b13db67-0c45-40f1-aba8-66a1a7198a1e

## Author
frack113

## Date
2021-11-26

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Extract data from cab file and hide it in an alternate data stream

## References
https://lolbas-project.github.io/lolbas/Binaries/Extrac32/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "extrac32.exe" AND TgtProcCmdLine containsCIS ".cab") AND TgtProcCmdLine RegExp ":[^\\\\]"))

```