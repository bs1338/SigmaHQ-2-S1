# proc_creation_win_schtasks_persistence_windows_telemetry

## Title
Potential Persistence Via Microsoft Compatibility Appraiser

## ID
f548a603-c9f2-4c89-b511-b089f7e94549

## Author
Sreeman

## Date
2020-09-29

## Tags
attack.persistence, attack.t1053.005

## Description
Detects manual execution of the "Microsoft Compatibility Appraiser" task via schtasks.
In order to trigger persistence stored in the "\AppCompatFlags\TelemetryController" registry key.


## References
https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "run " AND TgtProcCmdLine containsCIS "\Application Experience\Microsoft Compatibility Appraiser") AND TgtProcImagePath endswithCIS "\schtasks.exe"))

```