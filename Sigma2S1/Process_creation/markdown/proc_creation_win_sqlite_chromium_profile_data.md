# proc_creation_win_sqlite_chromium_profile_data

## Title
SQLite Chromium Profile Data DB Access

## ID
24c77512-782b-448a-8950-eddb0785fc71

## Author
TropChaud

## Date
2022-12-19

## Tags
attack.credential-access, attack.t1539, attack.t1555.003, attack.collection, attack.t1005

## Description
Detect usage of the "sqlite" binary to query databases in Chromium-based browsers for potential data stealing.

## References
https://github.com/redcanaryco/atomic-red-team/blob/84d9edaaaa2c5511144521b0e4af726d1c7276ce/atomics/T1539/T1539.md#atomic-test-2---steal-chrome-cookies-windows
https://blog.cyble.com/2022/04/21/prynt-stealer-a-new-info-stealer-performing-clipper-and-keylogger-activities/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\User Data\" OR TgtProcCmdLine containsCIS "\Opera Software\" OR TgtProcCmdLine containsCIS "\ChromiumViewer\") AND (TgtProcCmdLine containsCIS "Login Data" OR TgtProcCmdLine containsCIS "Cookies" OR TgtProcCmdLine containsCIS "Web Data" OR TgtProcCmdLine containsCIS "History" OR TgtProcCmdLine containsCIS "Bookmarks") AND (TgtProcDisplayName = "SQLite" OR (TgtProcImagePath endswithCIS "\sqlite.exe" OR TgtProcImagePath endswithCIS "\sqlite3.exe"))))

```