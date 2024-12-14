# proc_creation_win_cmd_assoc_execution

## Title
Change Default File Association Via Assoc

## ID
3d3aa6cd-6272-44d6-8afc-7e88dfef7061

## Author
Timur Zinniatullin, oscd.community

## Date
2019-10-21

## Tags
attack.persistence, attack.t1546.001

## Description
Detects file association changes using the builtin "assoc" command.
 When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.001/T1546.001.md

## False Positives
Admin activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "assoc" AND TgtProcImagePath endswithCIS "\cmd.exe"))

```