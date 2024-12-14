# proc_creation_win_mpcmdrun_dll_sideload_defender

## Title
Potential Mpclient.DLL Sideloading Via Defender Binaries

## ID
7002aa10-b8d4-47ae-b5ba-51ab07e228b9

## Author
Bhabesh Raj

## Date
2022-08-01

## Tags
attack.defense-evasion, attack.t1574.002

## Description
Detects potential sideloading of "mpclient.dll" by Windows Defender processes ("MpCmdRun" and "NisSrv") from their non-default directory.

## References
https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\MpCmdRun.exe" OR TgtProcImagePath endswithCIS "\NisSrv.exe") AND (NOT (TgtProcImagePath startswithCIS "C:\Program Files (x86)\Windows Defender\" OR TgtProcImagePath startswithCIS "C:\Program Files\Microsoft Security Client\" OR TgtProcImagePath startswithCIS "C:\Program Files\Windows Defender\" OR TgtProcImagePath startswithCIS "C:\ProgramData\Microsoft\Windows Defender\Platform\" OR TgtProcImagePath startswithCIS "C:\Windows\WinSxS\"))))

```