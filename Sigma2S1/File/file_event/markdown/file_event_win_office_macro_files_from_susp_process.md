# file_event_win_office_macro_files_from_susp_process

## Title
Office Macro File Creation From Suspicious Process

## ID
b1c50487-1967-4315-a026-6491686d860e

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-23

## Tags
attack.initial-access, attack.t1566.001

## Description
Detects the creation of a office macro file from a a suspicious process

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1566.001/T1566.001.md
https://learn.microsoft.com/en-us/deployoffice/compat/office-file-format-reference

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\wscript.exe") OR (SrcProcParentImagePath endswithCIS "\cscript.exe" OR SrcProcParentImagePath endswithCIS "\mshta.exe" OR SrcProcParentImagePath endswithCIS "\regsvr32.exe" OR SrcProcParentImagePath endswithCIS "\rundll32.exe" OR SrcProcParentImagePath endswithCIS "\wscript.exe")) AND (TgtFilePath endswithCIS ".docm" OR TgtFilePath endswithCIS ".dotm" OR TgtFilePath endswithCIS ".xlsm" OR TgtFilePath endswithCIS ".xltm" OR TgtFilePath endswithCIS ".potm" OR TgtFilePath endswithCIS ".pptm")))

```