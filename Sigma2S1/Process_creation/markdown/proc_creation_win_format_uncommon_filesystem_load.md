# proc_creation_win_format_uncommon_filesystem_load

## Title
Uncommon FileSystem Load Attempt By Format.com

## ID
9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-04

## Tags
attack.defense-evasion

## Description
Detects the execution of format.com with an uncommon filesystem selection that could indicate a defense evasion activity in which "format.com" is used to load malicious DLL files or other programs.


## References
https://twitter.com/0gtweet/status/1477925112561209344
https://twitter.com/wdormann/status/1478011052130459653?s=20

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/fs:" AND TgtProcImagePath endswithCIS "\format.com") AND (NOT (TgtProcCmdLine containsCIS "/fs:exFAT" OR TgtProcCmdLine containsCIS "/fs:FAT" OR TgtProcCmdLine containsCIS "/fs:NTFS" OR TgtProcCmdLine containsCIS "/fs:ReFS" OR TgtProcCmdLine containsCIS "/fs:UDF"))))

```