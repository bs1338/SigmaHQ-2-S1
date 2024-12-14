# file_event_win_office_onenote_files_in_susp_locations

## Title
OneNote Attachment File Dropped In Suspicious Location

## ID
7fd164ba-126a-4d9c-9392-0d4f7c243df0

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-22

## Tags
attack.defense-evasion

## Description
Detects creation of files with the ".one"/".onepkg" extension in suspicious or uncommon locations. This could be a sign of attackers abusing OneNote attachments

## References
https://www.bleepingcomputer.com/news/security/hackers-now-use-microsoft-onenote-attachments-to-spread-malware/
https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/

## False Positives
Legitimate usage of ".one" or ".onepkg" files from those locations

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((TgtFilePath containsCIS "\AppData\Local\Temp\" OR TgtFilePath containsCIS "\Users\Public\" OR TgtFilePath containsCIS "\Windows\Temp\" OR TgtFilePath containsCIS ":\Temp\") AND (TgtFilePath endswithCIS ".one" OR TgtFilePath endswithCIS ".onepkg")) AND (NOT (SrcProcImagePath containsCIS ":\Program Files\Microsoft Office\" AND SrcProcImagePath endswithCIS "\ONENOTE.EXE"))))

```