# proc_creation_win_cmd_dir_execution

## Title
File And SubFolder Enumeration Via Dir Command

## ID
7c9340a9-e2ee-4e43-94c5-c54ebbea1006

## Author
frack113

## Date
2021-12-13

## Tags
attack.discovery, attack.t1217

## Description
Detects usage of the "dir" command part of Widows CMD with the "/S" command line flag in order to enumerate files in a specified directory and all subdirectories.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1217/T1217.md

## False Positives
Likely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine = "*dir*-s*" OR TgtProcCmdLine = "*dir*/s*" OR TgtProcCmdLine = "*dir*â€“s*" OR TgtProcCmdLine = "*dir*â€”s*" OR TgtProcCmdLine = "*dir*â€•s*") AND TgtProcImagePath endswithCIS "\cmd.exe"))

```