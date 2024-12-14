# file_event_win_hktl_hivenightmare_file_exports

## Title
HackTool - Typical HiveNightmare SAM File Export

## ID
6ea858a8-ba71-4a12-b2cc-5d83312404c7

## Author
Florian Roth (Nextron Systems)

## Date
2021-07-23

## Tags
attack.credential-access, attack.t1552.001, cve.2021-36934

## Description
Detects files written by the different tools that exploit HiveNightmare

## References
https://github.com/GossiTheDog/HiveNightmare
https://github.com/FireFart/hivenightmare/
https://github.com/WiredPulse/Invoke-HiveNightmare
https://twitter.com/cube0x0/status/1418920190759378944

## False Positives
Files that accidentally contain these strings

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\hive_sam_" OR TgtFilePath containsCIS "\SAM-2021-" OR TgtFilePath containsCIS "\SAM-2022-" OR TgtFilePath containsCIS "\SAM-2023-" OR TgtFilePath containsCIS "\SAM-haxx" OR TgtFilePath containsCIS "\Sam.save") OR TgtFilePath = "C:\windows\temp\sam"))

```