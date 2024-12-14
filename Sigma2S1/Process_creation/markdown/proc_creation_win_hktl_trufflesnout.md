# proc_creation_win_hktl_trufflesnout

## Title
HackTool - TruffleSnout Execution

## ID
69ca006d-b9a9-47f5-80ff-ecd4d25d481a

## Author
frack113

## Date
2022-08-20

## Tags
attack.discovery, attack.t1482

## Description
Detects the use of TruffleSnout.exe an iterative AD discovery toolkit for offensive operators, situational awareness and targeted low noise enumeration.

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1482/T1482.md
https://github.com/dsnezhkov/TruffleSnout
https://github.com/dsnezhkov/TruffleSnout/blob/master/TruffleSnout/Docs/USAGE.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\TruffleSnout.exe")

```