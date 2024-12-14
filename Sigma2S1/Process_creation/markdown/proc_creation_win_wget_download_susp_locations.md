# proc_creation_win_wget_download_susp_locations

## Title
Suspicious File Download From IP Via Wget.EXE - Paths

## ID
40aa399c-7b02-4715-8e5f-73572b493f33

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-02-23

## Tags
attack.execution

## Description
Detects potentially suspicious file downloads directly from IP addresses and stored in suspicious locations using Wget.exe

## References
https://www.gnu.org/software/wget/manual/wget.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine RegExp "\\s-O\\s" OR TgtProcCmdLine containsCIS "--output-document") AND TgtProcCmdLine containsCIS "http" AND TgtProcImagePath endswithCIS "\wget.exe" AND TgtProcCmdLine RegExp "://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" AND ((TgtProcCmdLine containsCIS ":\PerfLogs\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\Help\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\Temporary Internet") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Favorites\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Favourites\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Contacts\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Pictures\"))))

```