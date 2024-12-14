# file_event_win_tsclient_filewrite_startup

## Title
Hijack Legit RDP Session to Move Laterally

## ID
52753ea4-b3a0-4365-910d-36cff487b789

## Author
Samir Bousseaden

## Date
2019-02-21

## Tags
attack.command-and-control, attack.t1219

## Description
Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder

## References
Internal Research

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\mstsc.exe" AND TgtFilePath containsCIS "\Microsoft\Windows\Start Menu\Programs\Startup\"))

```