# file_event_win_office_uncommon_file_startup

## Title
Uncommon File Created In Office Startup Folder

## ID
a10a2c40-2c4d-49f8-b557-1a946bc55d9d

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-05

## Tags
attack.resource-development, attack.t1587.001

## Description
Detects the creation of a file with an uncommon extension in an Office application startup folder

## References
https://app.any.run/tasks/d6fe6624-6ef8-485d-aa75-3d1bdda2a08c/
http://addbalance.com/word/startup.htm
https://answers.microsoft.com/en-us/msoffice/forum/all/document-in-word-startup-folder-doesnt-open-when/44ab0932-2917-4150-8cdc-2f2cf39e86f3
https://en.wikipedia.org/wiki/List_of_Microsoft_Office_filename_extensions

## False Positives
False positive might stem from rare extensions used by other Office utilities.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((((TgtFilePath containsCIS "\Microsoft\Word\STARTUP" OR (TgtFilePath containsCIS "\Office" AND TgtFilePath containsCIS "\Program Files" AND TgtFilePath containsCIS "\STARTUP")) AND (NOT (TgtFilePath endswithCIS ".docb" OR TgtFilePath endswithCIS ".docm" OR TgtFilePath endswithCIS ".docx" OR TgtFilePath endswithCIS ".dotm" OR TgtFilePath endswithCIS ".mdb" OR TgtFilePath endswithCIS ".mdw" OR TgtFilePath endswithCIS ".pdf" OR TgtFilePath endswithCIS ".wll" OR TgtFilePath endswithCIS ".wwl"))) OR ((TgtFilePath containsCIS "\Microsoft\Excel\XLSTART" OR (TgtFilePath containsCIS "\Office" AND TgtFilePath containsCIS "\Program Files" AND TgtFilePath containsCIS "\XLSTART")) AND (NOT (TgtFilePath endswithCIS ".xll" OR TgtFilePath endswithCIS ".xls" OR TgtFilePath endswithCIS ".xlsm" OR TgtFilePath endswithCIS ".xlsx" OR TgtFilePath endswithCIS ".xlt" OR TgtFilePath endswithCIS ".xltm" OR TgtFilePath endswithCIS ".xlw")))) AND (NOT (((SrcProcImagePath containsCIS ":\Program Files\Microsoft Office\" OR SrcProcImagePath containsCIS ":\Program Files (x86)\Microsoft Office\") AND (SrcProcImagePath endswithCIS "\winword.exe" OR SrcProcImagePath endswithCIS "\excel.exe")) OR (SrcProcImagePath containsCIS ":\Program Files\Common Files\Microsoft Shared\ClickToRun\" AND SrcProcImagePath endswithCIS "\OfficeClickToRun.exe")))))

```