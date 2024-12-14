# proc_creation_win_webdav_lnk_execution

## Title
Potentially Suspicious WebDAV LNK Execution

## ID
1412aa78-a24c-4abd-83df-767dfb2c5bbe

## Author
Micah Babinski

## Date
2023-08-21

## Tags
attack.execution, attack.t1059.001, attack.t1204

## Description
Detects possible execution via LNK file accessed on a WebDAV server.

## References
https://www.trellix.com/en-us/about/newsroom/stories/research/beyond-file-search-a-novel-method.html
https://micahbabinski.medium.com/search-ms-webdav-and-chill-99c5b23ac462

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\DavWWWRoot\" AND (TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\explorer.exe"))

```