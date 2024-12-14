# file_event_win_ntds_dit_creation

## Title
NTDS.DIT Created

## ID
0b8baa3f-575c-46ee-8715-d6f28cc7d33c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-05

## Tags
attack.credential-access, attack.t1003.003

## Description
Detects creation of a file named "ntds.dit" (Active Directory Database)

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "ntds.dit")

```