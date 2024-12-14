# proc_creation_win_reg_software_discovery

## Title
Detected Windows Software Discovery

## ID
e13f668e-7f95-443d-98d2-1816a7648a7b

## Author
Nikita Nazarov, oscd.community

## Date
2020-10-16

## Tags
attack.discovery, attack.t1518

## Description
Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518/T1518.md
https://github.com/harleyQu1nn/AggressorScripts

## False Positives
Legitimate administration activities

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "query" AND TgtProcCmdLine containsCIS "\software\" AND TgtProcCmdLine containsCIS "/v" AND TgtProcCmdLine containsCIS "svcversion") AND TgtProcImagePath endswithCIS "\reg.exe"))

```