# proc_creation_win_installutil_download

## Title
File Download Via InstallUtil.EXE

## ID
75edd216-1939-4c73-8d61-7f3a0d85b5cc

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects use of .NET InstallUtil.exe in order to download arbitrary files. The files will be written to "%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\"


## References
https://github.com/LOLBAS-Project/LOLBAS/pull/239

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "ftp://" OR TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND TgtProcImagePath endswithCIS "\InstallUtil.exe"))

```