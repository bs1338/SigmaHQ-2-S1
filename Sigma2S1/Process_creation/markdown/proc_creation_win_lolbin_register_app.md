# proc_creation_win_lolbin_register_app

## Title
REGISTER_APP.VBS Proxy Execution

## ID
1c8774a0-44d4-4db0-91f8-e792359c70bd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the use of a Microsoft signed script 'REGISTER_APP.VBS' to register a VSS/VDS Provider as a COM+ application.

## References
https://twitter.com/sblmsrsn/status/1456613494783160325?s=20

## False Positives
Legitimate usage of the script. Always investigate what's being registered to confirm if it's benign

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\register_app.vbs" AND TgtProcCmdLine containsCIS "-register"))

```