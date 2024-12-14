# proc_creation_win_remote_time_discovery

## Title
Discovery of a System Time

## ID
b243b280-65fe-48df-ba07-6ddea7646427

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community

## Date
2019-10-24

## Tags
attack.discovery, attack.t1124

## Description
Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system.

## References
https://eqllib.readthedocs.io/en/latest/analytics/fcdb99c2-ac3c-4bde-b664-4b336329bed2.html
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1124/T1124.md

## False Positives
Legitimate use of the system utilities to discover system time for legitimate reason

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "time" AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")) OR (TgtProcCmdLine containsCIS "tz" AND TgtProcImagePath endswithCIS "\w32tm.exe")))

```