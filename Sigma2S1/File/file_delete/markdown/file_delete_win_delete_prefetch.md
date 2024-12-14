# file_delete_win_delete_prefetch

## Title
Prefetch File Deleted

## ID
0a1f9d29-6465-4776-b091-7f43b26e4c89

## Author
Cedric MAURUGEON

## Date
2021-09-29

## Tags
attack.defense-evasion, attack.t1070.004

## Description
Detects the deletion of a prefetch file which may indicate an attempt to destroy forensic evidence

## References
Internal Research
https://www.group-ib.com/blog/hunting-for-ttps-with-prefetch-files/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS ":\Windows\Prefetch\" AND TgtFilePath endswithCIS ".pf") AND (NOT (SrcProcImagePath endswithCIS ":\windows\system32\svchost.exe" AND (SrcProcUser containsCIS "AUTHORI" OR SrcProcUser containsCIS "AUTORI")))))

```