# proc_creation_win_hh_chm_execution

## Title
HH.EXE Execution

## ID
68c8acb4-1b60-4890-8e82-3ddf7a6dba84

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Dan Beavin), oscd.community

## Date
2019-10-24

## Tags
attack.defense-evasion, attack.t1218.001

## Description
Detects the execution of "hh.exe" to open ".chm" files.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.001/T1218.001.md
https://eqllib.readthedocs.io/en/latest/analytics/b25aa548-7937-11e9-8f5c-d46d6d62a49e.html
https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37

## False Positives
False positives are expected with legitimate ".CHM"

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ".chm" AND TgtProcImagePath endswithCIS "\hh.exe"))

```