# file_event_win_mal_octopus_scanner

## Title
Octopus Scanner Malware

## ID
805c55d9-31e6-4846-9878-c34c75054fe9

## Author
NVISO

## Date
2020-06-09

## Tags
attack.t1195, attack.t1195.001

## Description
Detects Octopus Scanner Malware.

## References
https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\AppData\Local\Microsoft\Cache134.dat" OR TgtFilePath endswithCIS "\AppData\Local\Microsoft\ExplorerSync.db"))

```