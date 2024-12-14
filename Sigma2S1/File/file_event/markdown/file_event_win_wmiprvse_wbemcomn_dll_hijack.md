# file_event_win_wmiprvse_wbemcomn_dll_hijack

## Title
Wmiprvse Wbemcomn DLL Hijack - File

## ID
614a7e17-5643-4d89-b6fe-f9df1a79641c

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-10-12

## Tags
attack.execution, attack.t1047, attack.lateral-movement, attack.t1021.002

## Description
Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network and loading it for a WMI DLL Hijack scenario.

## References
https://threathunterplaybook.com/hunts/windows/201009-RemoteWMIWbemcomnDLLHijack/notebook.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath = "System" AND TgtFilePath endswithCIS "\wbem\wbemcomn.dll"))

```