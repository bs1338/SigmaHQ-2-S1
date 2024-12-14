# file_event_win_create_evtx_non_common_locations

## Title
EVTX Created In Uncommon Location

## ID
65236ec7-ace0-4f0c-82fd-737b04fd4dcb

## Author
D3F7A5105

## Date
2023-01-02

## Tags
attack.defense-evasion, attack.t1562.002

## Description
Detects the creation of new files with the ".evtx" extension in non-common or non-standard location.
This could indicate tampering with default EVTX locations in order to evade security controls or simply exfiltration of event log to search for sensitive information within.
Note that backup software and legitimate administrator might perform similar actions during troubleshooting.


## References
https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key

## False Positives
Administrator or backup activity
An unknown bug seems to trigger the Windows "svchost" process to drop EVTX files in the "C:\Windows\Temp" directory in the form "<log_name">_<uuid>.evtx". See https://superuser.com/questions/1371229/low-disk-space-after-filling-up-c-windows-temp-with-evtx-and-txt-files

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".evtx" AND (NOT ((TgtFilePath endswithCIS "\Windows\System32\winevt\Logs\" AND TgtFilePath startswithCIS "C:\ProgramData\Microsoft\Windows\Containers\BaseImages\") OR TgtFilePath startswithCIS "C:\Windows\System32\winevt\Logs\"))))

```