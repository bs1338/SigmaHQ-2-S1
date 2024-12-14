# proc_creation_win_powershell_base64_frombase64string

## Title
PowerShell Base64 Encoded FromBase64String Cmdlet

## ID
fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c

## Author
Florian Roth (Nextron Systems)

## Date
2019-08-24

## Tags
attack.defense-evasion, attack.t1140, attack.execution, attack.t1059.001

## Description
Detects usage of a base64 encoded "FromBase64String" cmdlet in a process command line

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "OjpGcm9tQmFzZTY0U3RyaW5n" OR TgtProcCmdLine containsCIS "o6RnJvbUJhc2U2NFN0cmluZ" OR TgtProcCmdLine containsCIS "6OkZyb21CYXNlNjRTdHJpbm" OR (TgtProcCmdLine containsCIS "OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA" OR TgtProcCmdLine containsCIS "oAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnA" OR TgtProcCmdLine containsCIS "6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw")))

```