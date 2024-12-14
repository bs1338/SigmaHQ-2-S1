# proc_creation_win_rasdial_execution

## Title
Suspicious RASdial Activity

## ID
6bba49bf-7f8c-47d6-a1bb-6b4dece4640e

## Author
juju4

## Date
2019-01-16

## Tags
attack.defense-evasion, attack.execution, attack.t1059

## Description
Detects suspicious process related to rasdial.exe

## References
https://twitter.com/subTee/status/891298217907830785

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "rasdial.exe")

```