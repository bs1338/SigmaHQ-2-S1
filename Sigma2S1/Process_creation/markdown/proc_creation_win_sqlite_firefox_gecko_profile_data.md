# proc_creation_win_sqlite_firefox_gecko_profile_data

## Title
SQLite Firefox Profile Data DB Access

## ID
4833155a-4053-4c9c-a997-777fcea0baa7

## Author
frack113

## Date
2022-04-08

## Tags
attack.credential-access, attack.t1539, attack.collection, attack.t1005

## Description
Detect usage of the "sqlite" binary to query databases in Firefox and other Gecko-based browsers for potential data stealing.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1539/T1539.md#atomic-test-1---steal-firefox-cookies-windows
https://blog.cyble.com/2022/04/21/prynt-stealer-a-new-info-stealer-performing-clipper-and-keylogger-activities/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "cookies.sqlite" OR TgtProcCmdLine containsCIS "places.sqlite") AND (TgtProcDisplayName = "SQLite" OR (TgtProcImagePath endswithCIS "\sqlite.exe" OR TgtProcImagePath endswithCIS "\sqlite3.exe"))))

```