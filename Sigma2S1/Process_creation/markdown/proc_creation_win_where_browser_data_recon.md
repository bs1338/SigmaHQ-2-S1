# proc_creation_win_where_browser_data_recon

## Title
Suspicious Where Execution

## ID
725a9768-0f5e-4cb3-aec2-bc5719c6831a

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2021-12-13

## Tags
attack.discovery, attack.t1217

## Description
Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
internal network resources such as servers, tools/dashboards, or other related infrastructure.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1217/T1217.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\where.exe" AND (TgtProcCmdLine containsCIS "places.sqlite" OR TgtProcCmdLine containsCIS "cookies.sqlite" OR TgtProcCmdLine containsCIS "formhistory.sqlite" OR TgtProcCmdLine containsCIS "logins.json" OR TgtProcCmdLine containsCIS "key4.db" OR TgtProcCmdLine containsCIS "key3.db" OR TgtProcCmdLine containsCIS "sessionstore.jsonlz4" OR TgtProcCmdLine containsCIS "History" OR TgtProcCmdLine containsCIS "Bookmarks" OR TgtProcCmdLine containsCIS "Cookies" OR TgtProcCmdLine containsCIS "Login Data")))

```