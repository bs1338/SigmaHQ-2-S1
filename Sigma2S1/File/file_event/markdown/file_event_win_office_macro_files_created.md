# file_event_win_office_macro_files_created

## Title
Office Macro File Creation

## ID
91174a41-dc8f-401b-be89-7bfc140612a0

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-23

## Tags
attack.initial-access, attack.t1566.001

## Description
Detects the creation of a new office macro files on the systems

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1566.001/T1566.001.md
https://learn.microsoft.com/en-us/deployoffice/compat/office-file-format-reference

## False Positives
Very common in environments that rely heavily on macro documents

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".docm" OR TgtFilePath endswithCIS ".dotm" OR TgtFilePath endswithCIS ".xlsm" OR TgtFilePath endswithCIS ".xltm" OR TgtFilePath endswithCIS ".potm" OR TgtFilePath endswithCIS ".pptm"))

```