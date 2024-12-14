# proc_creation_win_wmi_persistence_script_event_consumer

## Title
WMI Persistence - Script Event Consumer

## ID
ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e

## Author
Thomas Patzke

## Date
2018-03-07

## Tags
attack.persistence, attack.privilege-escalation, attack.t1546.003

## Description
Detects WMI script event consumers

## References
https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/

## False Positives
Legitimate event consumers
Dell computers on some versions register an event consumer that is known to cause false positives when brightness is changed by the corresponding keyboard button

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath = "C:\WINDOWS\system32\wbem\scrcons.exe" AND SrcProcImagePath = "C:\Windows\System32\svchost.exe"))

```