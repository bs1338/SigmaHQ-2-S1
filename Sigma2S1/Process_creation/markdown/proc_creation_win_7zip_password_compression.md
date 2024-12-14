# proc_creation_win_7zip_password_compression

## Title
Compress Data and Lock With Password for Exfiltration With 7-ZIP

## ID
9fbf5927-5261-4284-a71d-f681029ea574

## Author
frack113

## Date
2021-07-27

## Tags
attack.collection, attack.t1560.001

## Description
An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md

## False Positives
Legitimate activity is expected since compressing files with a password is common.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " a " OR TgtProcCmdLine containsCIS " u ") AND (TgtProcDisplayName containsCIS "7-Zip" OR (TgtProcImagePath endswithCIS "\7z.exe" OR TgtProcImagePath endswithCIS "\7zr.exe" OR TgtProcImagePath endswithCIS "\7za.exe")) AND TgtProcCmdLine containsCIS " -p"))

```