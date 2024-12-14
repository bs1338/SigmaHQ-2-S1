# file_event_win_cscript_wscript_dropper

## Title
WScript or CScript Dropper - File

## ID
002bdb95-0cf1-46a6-9e08-d38c128a6127

## Author
Tim Shelton

## Date
2022-01-10

## Tags
attack.execution, attack.t1059.005, attack.t1059.007

## Description
Detects a file ending in jse, vbe, js, vba, vbs written by cscript.exe or wscript.exe

## References
WScript or CScript Dropper (cea72823-df4d-4567-950c-0b579eaf0846)

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\wscript.exe" OR SrcProcImagePath endswithCIS "\cscript.exe") AND (TgtFilePath endswithCIS ".jse" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".js" OR TgtFilePath endswithCIS ".vba" OR TgtFilePath endswithCIS ".vbs") AND (TgtFilePath startswithCIS "C:\Users\" OR TgtFilePath startswithCIS "C:\ProgramData")))

```