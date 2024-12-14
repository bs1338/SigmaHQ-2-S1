# proc_creation_win_wmic_process_creation

## Title
New Process Created Via Wmic.EXE

## ID
526be59f-a573-4eea-b5f7-f0973207634d

## Author
Michael Haag, Florian Roth (Nextron Systems), juju4, oscd.community

## Date
2019-01-16

## Tags
attack.execution, attack.t1047, car.2016-03-002

## Description
Detects new process creation using WMIC via the "process call create" flag

## References
https://www.sans.org/blog/wmic-for-incident-response/
https://github.com/redcanaryco/atomic-red-team/blob/84215139ee5127f8e3a117e063b604812bd71928/atomics/T1047/T1047.md#atomic-test-5---wmi-execute-local-process

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "process" AND TgtProcCmdLine containsCIS "call" AND TgtProcCmdLine containsCIS "create") AND TgtProcImagePath endswithCIS "\wmic.exe"))

```