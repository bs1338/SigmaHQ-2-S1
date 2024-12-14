# proc_creation_win_protocolhandler_download

## Title
File Download Using ProtocolHandler.exe

## ID
104cdb48-a7a8-4ca7-a453-32942c6e5dcb

## Author
frack113

## Date
2021-07-13

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects usage of "ProtocolHandler" to download files. Downloaded files will be located in the cache folder (for example - %LOCALAPPDATA%\Microsoft\Windows\INetCache\IE)


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
https://lolbas-project.github.io/lolbas/OtherMSBinaries/ProtocolHandler/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "ftp://" OR TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND TgtProcImagePath endswithCIS "\protocolhandler.exe"))

```