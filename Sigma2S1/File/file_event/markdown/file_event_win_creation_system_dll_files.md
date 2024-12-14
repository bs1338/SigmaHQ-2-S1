# file_event_win_creation_system_dll_files

## Title
Files With System DLL Name In Unsuspected Locations

## ID
13c02350-4177-4e45-ac17-cf7ca628ff5e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-06-24

## Tags
attack.defense-evasion, attack.t1036.005

## Description
Detects the creation of a file with the ".dll" extension that has the name of a System DLL in uncommon or unsuspected locations. (Outisde of "System32", "SysWOW64", etc.).
It is highly recommended to perform an initial baseline before using this rule in production.


## References
Internal Research

## False Positives
Third party software might bundle specific versions of system DLLs.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\secur32.dll" OR TgtFilePath endswithCIS "\tdh.dll") AND (NOT (TgtFilePath containsCIS "C:\$WINDOWS.~BT\" OR TgtFilePath containsCIS "C:\$WinREAgent\" OR TgtFilePath containsCIS "C:\Windows\SoftwareDistribution\" OR TgtFilePath containsCIS "C:\Windows\System32\" OR TgtFilePath containsCIS "C:\Windows\SysWOW64\" OR TgtFilePath containsCIS "C:\Windows\WinSxS\" OR TgtFilePath containsCIS "C:\Windows\uus\"))))

```