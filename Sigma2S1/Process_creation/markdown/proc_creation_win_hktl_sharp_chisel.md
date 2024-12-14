# proc_creation_win_hktl_sharp_chisel

## Title
HackTool - SharpChisel Execution

## ID
cf93e05e-d798-4d9e-b522-b0248dc61eaf

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-05

## Tags
attack.command-and-control, attack.t1090.001

## Description
Detects usage of the Sharp Chisel via the commandline arguments

## References
https://github.com/shantanu561993/SharpChisel
https://www.sentinelone.com/labs/wading-through-muddy-waters-recent-activity-of-an-iranian-state-sponsored-threat-actor/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\SharpChisel.exe" OR TgtProcDisplayName = "SharpChisel"))

```