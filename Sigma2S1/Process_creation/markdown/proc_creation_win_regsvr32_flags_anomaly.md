# proc_creation_win_regsvr32_flags_anomaly

## Title
Potential Regsvr32 Commandline Flag Anomaly

## ID
b236190c-1c61-41e9-84b3-3fe03f6d76b0

## Author
Florian Roth (Nextron Systems)

## Date
2019-07-13

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects a potential command line flag anomaly related to "regsvr32" in which the "/i" flag is used without the "/n" which should be uncommon.

## References
https://twitter.com/sbousseaden/status/1282441816986484737?s=12

## False Positives
Administrator typo might cause some false positives

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -i:" OR TgtProcCmdLine containsCIS " /i:" OR TgtProcCmdLine containsCIS " â€“i:" OR TgtProcCmdLine containsCIS " â€”i:" OR TgtProcCmdLine containsCIS " â€•i:") AND TgtProcImagePath endswithCIS "\regsvr32.exe") AND (NOT TgtProcCmdLine containsCIS " -n " OR TgtProcCmdLine containsCIS " /n " OR TgtProcCmdLine containsCIS " â€“n " OR TgtProcCmdLine containsCIS " â€”n " OR TgtProcCmdLine containsCIS " â€•n ")))

```