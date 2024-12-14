# file_event_win_office_startup_persistence

## Title
Potential Persistence Via Microsoft Office Startup Folder

## ID
0e20c89d-2264-44ae-8238-aeeaba609ece

## Author
Max Altgelt (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-02

## Tags
attack.persistence, attack.t1137

## Description
Detects creation of Microsoft Office files inside of one of the default startup folders in order to achieve persistence.

## References
https://insight-jp.nttsecurity.com/post/102hojk/operation-restylink-apt-campaign-targeting-japanese-companies
https://learn.microsoft.com/en-us/office/troubleshoot/excel/use-startup-folders

## False Positives
Loading a user environment from a backup or a domain controller
Synchronization of templates

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((((TgtFilePath endswithCIS ".doc" OR TgtFilePath endswithCIS ".docm" OR TgtFilePath endswithCIS ".docx" OR TgtFilePath endswithCIS ".dot" OR TgtFilePath endswithCIS ".dotm" OR TgtFilePath endswithCIS ".rtf") AND (TgtFilePath containsCIS "\Microsoft\Word\STARTUP" OR (TgtFilePath containsCIS "\Office" AND TgtFilePath containsCIS "\Program Files" AND TgtFilePath containsCIS "\STARTUP"))) OR ((TgtFilePath endswithCIS ".xls" OR TgtFilePath endswithCIS ".xlsm" OR TgtFilePath endswithCIS ".xlsx" OR TgtFilePath endswithCIS ".xlt" OR TgtFilePath endswithCIS ".xltm") AND (TgtFilePath containsCIS "\Microsoft\Excel\XLSTART" OR (TgtFilePath containsCIS "\Office" AND TgtFilePath containsCIS "\Program Files" AND TgtFilePath containsCIS "\XLSTART")))) AND (NOT (SrcProcImagePath endswithCIS "\WINWORD.exe" OR SrcProcImagePath endswithCIS "\EXCEL.exe"))))

```