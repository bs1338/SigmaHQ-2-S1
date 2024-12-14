# file_event_win_susp_colorcpl

## Title
Suspicious Creation with Colorcpl

## ID
e15b518d-b4ce-4410-a9cd-501f23ce4a18

## Author
frack113

## Date
2022-01-21

## Tags
attack.defense-evasion, attack.t1564

## Description
Once executed, colorcpl.exe will copy the arbitrary file to c:\windows\system32\spool\drivers\color\

## References
https://twitter.com/eral4m/status/1480468728324231172?s=20

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\colorcpl.exe" AND (NOT (TgtFilePath endswithCIS ".icm" OR TgtFilePath endswithCIS ".gmmp" OR TgtFilePath endswithCIS ".cdmp" OR TgtFilePath endswithCIS ".camp"))))

```