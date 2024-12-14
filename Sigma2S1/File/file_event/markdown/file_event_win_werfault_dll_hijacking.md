# file_event_win_werfault_dll_hijacking

## Title
Creation of WerFault.exe/Wer.dll in Unusual Folder

## ID
28a452f3-786c-4fd8-b8f2-bddbe9d616d1

## Author
frack113

## Date
2022-05-09

## Tags
attack.persistence, attack.defense-evasion, attack.t1574.001

## Description
Detects the creation of a file named "WerFault.exe" or "wer.dll" in an uncommon folder, which could be a sign of WerFault DLL hijacking.

## References
https://www.bleepingcomputer.com/news/security/hackers-are-now-hiding-malware-in-windows-event-logs/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\WerFault.exe" OR TgtFilePath endswithCIS "\wer.dll") AND (NOT (TgtFilePath startswithCIS "C:\Windows\SoftwareDistribution\" OR TgtFilePath startswithCIS "C:\Windows\System32\" OR TgtFilePath startswithCIS "C:\Windows\SysWOW64\" OR TgtFilePath startswithCIS "C:\Windows\WinSxS\"))))

```