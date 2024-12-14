# proc_creation_win_rundll32_run_locations

## Title
Suspicious Process Start Locations

## ID
15b75071-74cc-47e0-b4c6-b43744a62a2b

## Author
juju4, Jonhnathan Ribeiro, oscd.community

## Date
2019-01-16

## Tags
attack.defense-evasion, attack.t1036, car.2013-05-002

## Description
Detects suspicious process run from unusual locations

## References
https://car.mitre.org/wiki/CAR-2013-05-002

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS ":\RECYCLER\" OR TgtProcImagePath containsCIS ":\SystemVolumeInformation\") OR (TgtProcImagePath startswithCIS "C:\Windows\Tasks\" OR TgtProcImagePath startswithCIS "C:\Windows\debug\" OR TgtProcImagePath startswithCIS "C:\Windows\fonts\" OR TgtProcImagePath startswithCIS "C:\Windows\help\" OR TgtProcImagePath startswithCIS "C:\Windows\drivers\" OR TgtProcImagePath startswithCIS "C:\Windows\addins\" OR TgtProcImagePath startswithCIS "C:\Windows\cursors\" OR TgtProcImagePath startswithCIS "C:\Windows\system32\tasks\")))

```