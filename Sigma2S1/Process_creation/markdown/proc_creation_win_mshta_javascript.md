# proc_creation_win_mshta_javascript

## Title
Suspicious JavaScript Execution Via Mshta.EXE

## ID
67f113fa-e23d-4271-befa-30113b3e08b1

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community

## Date
2019-10-24

## Tags
attack.defense-evasion, attack.t1218.005

## Description
Detects execution of javascript code using "mshta.exe".

## References
https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.005/T1218.005.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "javascript" AND TgtProcImagePath endswithCIS "\mshta.exe"))

```