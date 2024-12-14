# file_event_win_pcre_net_temp_file

## Title
PCRE.NET Package Temp Files

## ID
6e90ae7a-7cd3-473f-a035-4ebb72d961da

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-10-29

## Tags
attack.execution, attack.t1059

## Description
Detects processes creating temp files related to PCRE.NET package

## References
https://twitter.com/rbmaslen/status/1321859647091970051
https://twitter.com/tifkin_/status/1321916444557365248

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath containsCIS "\AppData\Local\Temp\ba9ea7344a4a5f591d6e5dc32a13494b\")

```