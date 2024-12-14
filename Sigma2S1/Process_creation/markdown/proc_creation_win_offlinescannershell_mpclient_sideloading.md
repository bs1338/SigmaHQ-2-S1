# proc_creation_win_offlinescannershell_mpclient_sideloading

## Title
Potential Mpclient.DLL Sideloading Via OfflineScannerShell.EXE Execution

## ID
02b18447-ea83-4b1b-8805-714a8a34546a

## Author
frack113

## Date
2022-03-06

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of Windows Defender "OfflineScannerShell.exe" from its non standard directory.
The "OfflineScannerShell.exe" binary is vulnerable to DLL side loading and will load any DLL named "mpclient.dll" from the current working directory.


## References
https://lolbas-project.github.io/lolbas/Binaries/OfflineScannerShell/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\OfflineScannerShell.exe" AND (NOT (TgtProcImagePath = "" OR TgtProcImagePath = "C:\Program Files\Windows Defender\Offline\" OR TgtProcImagePath IS NOT EMPTY))))

```