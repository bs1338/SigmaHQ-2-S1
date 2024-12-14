# file_event_win_susp_exchange_aspx_write

## Title
Suspicious MSExchangeMailboxReplication ASPX Write

## ID
7280c9f3-a5af-45d0-916a-bc01cb4151c9

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-25

## Tags
attack.initial-access, attack.t1190, attack.persistence, attack.t1505.003

## Description
Detects suspicious activity in which the MSExchangeMailboxReplication process writes .asp and .apsx files to disk, which could be a sign of ProxyShell exploitation

## References
https://redcanary.com/blog/blackbyte-ransomware/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\MSExchangeMailboxReplication.exe" AND (TgtFilePath endswithCIS ".aspx" OR TgtFilePath endswithCIS ".asp")))

```