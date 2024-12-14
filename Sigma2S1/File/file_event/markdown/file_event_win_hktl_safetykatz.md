# file_event_win_hktl_safetykatz

## Title
HackTool - SafetyKatz Dump Indicator

## ID
e074832a-eada-4fd7-94a1-10642b130e16

## Author
Markus Neis

## Date
2018-07-24

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects default lsass dump filename generated by SafetyKatz.

## References
https://github.com/GhostPack/SafetyKatz
https://github.com/GhostPack/SafetyKatz/blob/715b311f76eb3a4c8d00a1bd29c6cd1899e450b7/SafetyKatz/Program.cs#L63

## False Positives
Rare legitimate files with similar filename structure

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "\Temp\debug.bin")

```