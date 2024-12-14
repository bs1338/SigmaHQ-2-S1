# proc_creation_win_findstr_sysmon_discovery_via_default_altitude

## Title
Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE

## ID
37db85d1-b089-490a-a59a-c7b6f984f480

## Author
frack113

## Date
2021-12-16

## Tags
attack.discovery, attack.t1518.001

## Description
Detects usage of "findstr" with the argument "385201". Which could indicate potential discovery of an installed Sysinternals Sysmon service using the default driver altitude (even if the name is changed).

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518.001/T1518.001.md#atomic-test-5---security-software-discovery---sysmon-service

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " 385201" AND (TgtProcImagePath endswithCIS "\find.exe" OR TgtProcImagePath endswithCIS "\findstr.exe")))

```