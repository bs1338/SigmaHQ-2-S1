# proc_creation_win_winzip_password_compression

## Title
Compress Data and Lock With Password for Exfiltration With WINZIP

## ID
e2e80da2-8c66-4e00-ae3c-2eebd29f6b6d

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
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -min " OR TgtProcCmdLine containsCIS " -a ") AND TgtProcCmdLine containsCIS "-s\"" AND (TgtProcCmdLine containsCIS "winzip.exe" OR TgtProcCmdLine containsCIS "winzip64.exe")))

```