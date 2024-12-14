# file_event_win_lsass_werfault_dump

## Title
WerFault LSASS Process Memory Dump

## ID
c3e76af5-4ce0-4a14-9c9a-25ceb8fda182

## Author
Florian Roth (Nextron Systems)

## Date
2022-06-27

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects WerFault creating a dump file with a name that indicates that the dump file could be an LSASS process memory, which contains user credentials

## References
https://github.com/helpsystems/nanodump

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath = "C:\WINDOWS\system32\WerFault.exe" AND (TgtFilePath containsCIS "\lsass" OR TgtFilePath containsCIS "lsass.exe")))

```