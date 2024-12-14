# file_event_win_regedit_print_as_pdf

## Title
PDF File Created By RegEdit.EXE

## ID
145095eb-e273-443b-83d0-f9b519b7867b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-07-08

## Tags
attack.defense-evasion

## Description
Detects the creation of a file with the ".pdf" extension by the "RegEdit.exe" process.
This indicates that a user is trying to print/save a registry key as a PDF in order to potentially extract sensitive information and bypass defenses.


## References
https://sensepost.com/blog/2024/dumping-lsa-secrets-a-story-about-task-decorrelation/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\regedit.exe" AND TgtFilePath endswithCIS ".pdf"))

```