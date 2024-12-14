# file_event_win_office_macro_files_downloaded

## Title
Office Macro File Download

## ID
0e29e3a7-1ad8-40aa-b691-9f82ecd33d66

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-23

## Tags
attack.initial-access, attack.t1566.001

## Description
Detects the creation of a new office macro files on the systems via an application (browser, mail client).

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1566.001/T1566.001.md
https://learn.microsoft.com/en-us/deployoffice/compat/office-file-format-reference

## False Positives
Legitimate macro files downloaded from the internet
Legitimate macro files sent as attachments via emails

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((TgtFilePath endswithCIS ".docm" OR TgtFilePath endswithCIS ".dotm" OR TgtFilePath endswithCIS ".xlsm" OR TgtFilePath endswithCIS ".xltm" OR TgtFilePath endswithCIS ".potm" OR TgtFilePath endswithCIS ".pptm") OR (TgtFilePath containsCIS ".docm:Zone" OR TgtFilePath containsCIS ".dotm:Zone" OR TgtFilePath containsCIS ".xlsm:Zone" OR TgtFilePath containsCIS ".xltm:Zone" OR TgtFilePath containsCIS ".potm:Zone" OR TgtFilePath containsCIS ".pptm:Zone")) AND (SrcProcImagePath endswithCIS "\RuntimeBroker.exe" OR SrcProcImagePath endswithCIS "\outlook.exe" OR SrcProcImagePath endswithCIS "\thunderbird.exe" OR SrcProcImagePath endswithCIS "\brave.exe" OR SrcProcImagePath endswithCIS "\chrome.exe" OR SrcProcImagePath endswithCIS "\firefox.exe" OR SrcProcImagePath endswithCIS "\iexplore.exe" OR SrcProcImagePath endswithCIS "\maxthon.exe" OR SrcProcImagePath endswithCIS "\MicrosoftEdge.exe" OR SrcProcImagePath endswithCIS "\msedge.exe" OR SrcProcImagePath endswithCIS "\msedgewebview2.exe" OR SrcProcImagePath endswithCIS "\opera.exe" OR SrcProcImagePath endswithCIS "\safari.exe" OR SrcProcImagePath endswithCIS "\seamonkey.exe" OR SrcProcImagePath endswithCIS "\vivaldi.exe" OR SrcProcImagePath endswithCIS "\whale.exe")))

```