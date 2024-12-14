# file_event_win_susp_desktop_ini

## Title
Suspicious desktop.ini Action

## ID
81315b50-6b60-4d8f-9928-3466e1022515

## Author
Maxime Thiebaut (@0xThiebaut), Tim Shelton (HAWK.IO)

## Date
2020-03-19

## Tags
attack.persistence, attack.t1547.009

## Description
Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.

## References
https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/

## False Positives
Operations performed through Windows SCCM or equivalent
Read only access list authority

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\desktop.ini" AND (NOT ((SrcProcImagePath startswithCIS "C:\Windows\" OR SrcProcImagePath startswithCIS "C:\Program Files\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\") OR (SrcProcImagePath endswithCIS "\AppData\Local\JetBrains\Toolbox\bin\7z.exe" AND TgtFilePath containsCIS "\JetBrains\apps\") OR TgtFilePath startswithCIS "C:\$WINDOWS.~BT\NewOS\"))))

```