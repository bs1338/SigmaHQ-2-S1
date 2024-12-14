# file_event_win_hktl_dumpert

## Title
HackTool - Dumpert Process Dumper Default File

## ID
93d94efc-d7ad-4161-ad7d-1638c4f908d8

## Author
Florian Roth (Nextron Systems)

## Date
2020-02-04

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects the creation of the default dump file used by Outflank Dumpert tool. A process dumper, which dumps the lsass process memory

## References
https://github.com/outflanknl/Dumpert
https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/

## False Positives
Very unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "dumpert.dmp")

```