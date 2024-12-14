# file_event_win_office_publisher_files_in_susp_locations

## Title
Publisher Attachment File Dropped In Suspicious Location

## ID
3d2a2d59-929c-4b78-8c1a-145dfe9e07b1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-08

## Tags
attack.defense-evasion

## Description
Detects creation of files with the ".pub" extension in suspicious or uncommon locations. This could be a sign of attackers abusing Publisher documents

## References
https://twitter.com/EmericNasi/status/1623224526220804098

## False Positives
Legitimate usage of ".pub" files from those locations

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\AppData\Local\Temp\" OR TgtFilePath containsCIS "\Users\Public\" OR TgtFilePath containsCIS "\Windows\Temp\" OR TgtFilePath containsCIS "C:\Temp\") AND TgtFilePath endswithCIS ".pub"))

```