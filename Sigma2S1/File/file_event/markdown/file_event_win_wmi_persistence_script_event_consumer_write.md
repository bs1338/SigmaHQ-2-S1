# file_event_win_wmi_persistence_script_event_consumer_write

## Title
WMI Persistence - Script Event Consumer File Write

## ID
33f41cdd-35ac-4ba8-814b-c6a4244a1ad4

## Author
Thomas Patzke

## Date
2018-03-07

## Tags
attack.t1546.003, attack.persistence

## Description
Detects file writes of WMI script event consumer

## References
https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/

## False Positives
Dell Power Manager (C:\Program Files\Dell\PowerManager\DpmPowerPlanSetup.exe)

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND SrcProcImagePath = "C:\WINDOWS\system32\wbem\scrcons.exe")

```