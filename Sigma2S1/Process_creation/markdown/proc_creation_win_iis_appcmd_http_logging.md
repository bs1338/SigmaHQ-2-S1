# proc_creation_win_iis_appcmd_http_logging

## Title
Disable Windows IIS HTTP Logging

## ID
e4ed6030-ffe5-4e6a-8a8a-ab3c1ab9d94e

## Author
frack113

## Date
2022-01-09

## Tags
attack.defense-evasion, attack.t1562.002

## Description
Disables HTTP logging on a Windows IIS web server as seen by Threat Group 3390 (Bronze Union)

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.002/T1562.002.md#atomic-test-1---disable-windows-iis-http-logging

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "set" AND TgtProcCmdLine containsCIS "config" AND TgtProcCmdLine containsCIS "section:httplogging" AND TgtProcCmdLine containsCIS "dontLog:true") AND TgtProcImagePath endswithCIS "\appcmd.exe"))

```