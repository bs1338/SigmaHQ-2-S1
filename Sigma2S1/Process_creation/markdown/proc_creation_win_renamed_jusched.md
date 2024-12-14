# proc_creation_win_renamed_jusched

## Title
Renamed Jusched.EXE Execution

## ID
edd8a48c-1b9f-4ba1-83aa-490338cd1ccb

## Author
Markus Neis, Swisscom

## Date
2019-06-04

## Tags
attack.execution, attack.defense-evasion, attack.t1036.003

## Description
Detects the execution of a renamed "jusched.exe" as seen used by the cobalt group

## References
https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcDisplayName In Contains AnyCase ("Java Update Scheduler","Java(TM) Update Scheduler")) AND (NOT TgtProcImagePath endswithCIS "\jusched.exe")))

```