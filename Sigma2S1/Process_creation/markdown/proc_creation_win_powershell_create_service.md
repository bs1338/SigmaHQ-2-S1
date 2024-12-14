# proc_creation_win_powershell_create_service

## Title
New Service Creation Using PowerShell

## ID
c02e96b7-c63a-4c47-bd83-4a9f74afcfb2

## Author
Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community

## Date
2023-02-20

## Tags
attack.persistence, attack.privilege-escalation, attack.t1543.003

## Description
Detects the creation of a new service using powershell.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md

## False Positives
Legitimate administrator or user creates a service for legitimate reasons.
Software installation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "New-Service" AND TgtProcCmdLine containsCIS "-BinaryPathName"))

```