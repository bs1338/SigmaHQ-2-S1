# proc_creation_win_at_interactive_execution

## Title
Interactive AT Job

## ID
60fc936d-2eb0-4543-8a13-911c750a1dfc

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community

## Date
2019-10-24

## Tags
attack.privilege-escalation, attack.t1053.002

## Description
Detects an interactive AT job, which may be used as a form of privilege escalation.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.002/T1053.002.md
https://eqllib.readthedocs.io/en/latest/analytics/d8db43cf-ed52-4f5c-9fb3-c9a4b95a0b56.html

## False Positives
Unlikely (at.exe deprecated as of Windows 8)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "interactive" AND TgtProcImagePath endswithCIS "\at.exe"))

```