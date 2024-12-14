# proc_creation_win_renamed_office_processes

## Title
Renamed Office Binary Execution

## ID
0b0cd537-fc77-4e6e-a973-e53495c1083d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-20

## Tags
attack.defense-evasion

## Description
Detects the execution of a renamed office binary

## References
https://infosec.exchange/@sbousseaden/109542254124022664

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcDisplayName In Contains AnyCase ("Microsoft Access","Microsoft Excel","Microsoft OneNote","Microsoft Outlook","Microsoft PowerPoint","Microsoft Publisher","Microsoft Word","Sent to OneNote Tool")) AND (NOT (TgtProcImagePath endswithCIS "\EXCEL.exe" OR TgtProcImagePath endswithCIS "\excelcnv.exe" OR TgtProcImagePath endswithCIS "\MSACCESS.exe" OR TgtProcImagePath endswithCIS "\MSPUB.EXE" OR TgtProcImagePath endswithCIS "\ONENOTE.EXE" OR TgtProcImagePath endswithCIS "\ONENOTEM.EXE" OR TgtProcImagePath endswithCIS "\OUTLOOK.EXE" OR TgtProcImagePath endswithCIS "\POWERPNT.EXE" OR TgtProcImagePath endswithCIS "\WINWORD.exe"))))

```