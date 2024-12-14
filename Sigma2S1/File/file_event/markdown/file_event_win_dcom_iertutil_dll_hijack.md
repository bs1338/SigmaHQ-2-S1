# file_event_win_dcom_iertutil_dll_hijack

## Title
Potential DCOM InternetExplorer.Application DLL Hijack

## ID
2f7979ae-f82b-45af-ac1d-2b10e93b0baa

## Author
Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR), wagga

## Date
2020-10-12

## Tags
attack.lateral-movement, attack.t1021.002, attack.t1021.003

## Description
Detects potential DLL hijack of "iertutil.dll" found in the DCOM InternetExplorer.Application Class over the network

## References
https://threathunterplaybook.com/hunts/windows/201009-RemoteDCOMIErtUtilDLLHijack/notebook.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath = "System" AND TgtFilePath endswithCIS "\Internet Explorer\iertutil.dll"))

```