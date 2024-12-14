# proc_creation_win_fsutil_symlinkevaluation

## Title
Fsutil Behavior Set SymlinkEvaluation

## ID
c0b2768a-dd06-4671-8339-b16ca8d1f27f

## Author
frack113

## Date
2022-03-02

## Tags
attack.execution, attack.t1059

## Description
A symbolic link is a type of file that contains a reference to another file.
This is probably done to make sure that the ransomware is able to follow shortcuts on the machine in order to find the original file to encrypt


## References
https://www.cybereason.com/blog/cybereason-vs.-blackcat-ransomware
https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/fsutil-behavior

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "behavior " AND TgtProcCmdLine containsCIS "set " AND TgtProcCmdLine containsCIS "SymlinkEvaluation") AND TgtProcImagePath endswithCIS "\fsutil.exe"))

```