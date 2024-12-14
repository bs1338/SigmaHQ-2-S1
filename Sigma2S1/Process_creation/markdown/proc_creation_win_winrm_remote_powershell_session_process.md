# proc_creation_win_winrm_remote_powershell_session_process

## Title
Remote PowerShell Session Host Process (WinRM)

## ID
734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8

## Author
Roberto Rodriguez @Cyb3rWard0g

## Date
2019-09-12

## Tags
attack.execution, attack.t1059.001, attack.t1021.006

## Description
Detects remote PowerShell sections by monitoring for wsmprovhost (WinRM host process) as a parent or child process (sign of an active PowerShell remote session).

## References
https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html

## False Positives
Legitimate usage of remote Powershell, e.g. for monitoring purposes.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\wsmprovhost.exe" OR SrcProcImagePath endswithCIS "\wsmprovhost.exe"))

```