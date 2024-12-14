# proc_creation_win_reg_machineguid

## Title
Suspicious Query of MachineGUID

## ID
f5240972-3938-4e56-8e4b-e33893176c1f

## Author
frack113

## Date
2022-01-01

## Tags
attack.discovery, attack.t1082

## Description
Use of reg to get MachineGuid information

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-8---windows-machineguid-discovery

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "SOFTWARE\Microsoft\Cryptography" AND TgtProcCmdLine containsCIS "/v " AND TgtProcCmdLine containsCIS "MachineGuid") AND TgtProcImagePath endswithCIS "\reg.exe"))

```