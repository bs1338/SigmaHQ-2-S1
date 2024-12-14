# proc_creation_win_susp_nteventlogfile_usage

## Title
Potentially Suspicious Call To Win32_NTEventlogFile Class

## ID
caf201a9-c2ce-4a26-9c3a-2b9525413711

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-13

## Tags
attack.defense-evasion

## Description
Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script

## References
https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394225(v=vs.85)

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Win32_NTEventlogFile" AND (TgtProcCmdLine containsCIS ".BackupEventlog(" OR TgtProcCmdLine containsCIS ".ChangeSecurityPermissions(" OR TgtProcCmdLine containsCIS ".ChangeSecurityPermissionsEx(" OR TgtProcCmdLine containsCIS ".ClearEventLog(" OR TgtProcCmdLine containsCIS ".Delete(" OR TgtProcCmdLine containsCIS ".DeleteEx(" OR TgtProcCmdLine containsCIS ".Rename(" OR TgtProcCmdLine containsCIS ".TakeOwnerShip(" OR TgtProcCmdLine containsCIS ".TakeOwnerShipEx(")))

```