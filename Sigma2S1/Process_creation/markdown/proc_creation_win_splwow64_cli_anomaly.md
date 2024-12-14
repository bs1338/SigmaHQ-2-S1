# proc_creation_win_splwow64_cli_anomaly

## Title
Suspicious Splwow64 Without Params

## ID
1f1a8509-2cbb-44f5-8751-8e1571518ce2

## Author
Florian Roth (Nextron Systems)

## Date
2021-08-23

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects suspicious Splwow64.exe process without any command line parameters

## References
https://twitter.com/sbousseaden/status/1429401053229891590?s=12

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine endswithCIS "splwow64.exe" AND TgtProcImagePath endswithCIS "\splwow64.exe"))

```