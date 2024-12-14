# proc_creation_win_lolbin_diantz_ads

## Title
Suspicious Diantz Alternate Data Stream Execution

## ID
6b369ced-4b1d-48f1-b427-fdc0de0790bd

## Author
frack113

## Date
2021-11-26

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Compress target file into a cab file stored in the Alternate Data Stream (ADS) of the target file.

## References
https://lolbas-project.github.io/lolbas/Binaries/Diantz/

## False Positives
Very Possible

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "diantz.exe" AND TgtProcCmdLine containsCIS ".cab") AND TgtProcCmdLine RegExp ":[^\\\\]"))

```