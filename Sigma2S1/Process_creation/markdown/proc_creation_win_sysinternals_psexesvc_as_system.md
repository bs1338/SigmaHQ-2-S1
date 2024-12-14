# proc_creation_win_sysinternals_psexesvc_as_system

## Title
PsExec Service Child Process Execution as LOCAL SYSTEM

## ID
7c0dcd3d-acf8-4f71-9570-f448b0034f94

## Author
Florian Roth (Nextron Systems)

## Date
2022-07-21

## Tags
attack.execution

## Description
Detects suspicious launch of the PSEXESVC service on this system and a sub process run as LOCAL_SYSTEM (-s), which means that someone remotely started a command on this system running it with highest privileges and not only the privileges of the login user account (e.g. the administrator account)

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

## False Positives
Users that debug Microsoft Intune issues using the commands mentioned in the official documentation; see https://learn.microsoft.com/en-us/mem/intune/apps/intune-management-extension

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath = "C:\Windows\PSEXESVC.exe" AND (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI")))

```