# proc_creation_win_sc_create_service

## Title
New Service Creation Using Sc.EXE

## ID
85ff530b-261d-48c6-a441-facaa2e81e48

## Author
Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community

## Date
2023-02-20

## Tags
attack.persistence, attack.privilege-escalation, attack.t1543.003

## Description
Detects the creation of a new service using the "sc.exe" utility.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md

## False Positives
Legitimate administrator or user creates a service for legitimate reasons.
Software installation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "create" AND TgtProcCmdLine containsCIS "binPath") AND TgtProcImagePath endswithCIS "\sc.exe"))

```