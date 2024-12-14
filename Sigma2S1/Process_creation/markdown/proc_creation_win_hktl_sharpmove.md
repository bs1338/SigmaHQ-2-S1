# proc_creation_win_hktl_sharpmove

## Title
HackTool - SharpMove Tool Execution

## ID
055fb54c-a8f4-4aee-bd44-f74cf30a0d9d

## Author
Luca Di Bartolomeo (CrimpSec)

## Date
2024-01-29

## Tags
attack.lateral-movement, attack.t1021.002

## Description
Detects the execution of SharpMove, a .NET utility performing multiple tasks such as "Task Creation", "SCM" query, VBScript execution using WMI via its PE metadata and command line options.


## References
https://github.com/0xthirteen/SharpMove/
https://pentestlab.blog/tag/sharpmove/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\SharpMove.exe" OR ((TgtProcCmdLine containsCIS "action=create" OR TgtProcCmdLine containsCIS "action=dcom" OR TgtProcCmdLine containsCIS "action=executevbs" OR TgtProcCmdLine containsCIS "action=hijackdcom" OR TgtProcCmdLine containsCIS "action=modschtask" OR TgtProcCmdLine containsCIS "action=modsvc" OR TgtProcCmdLine containsCIS "action=query" OR TgtProcCmdLine containsCIS "action=scm" OR TgtProcCmdLine containsCIS "action=startservice" OR TgtProcCmdLine containsCIS "action=taskscheduler") AND TgtProcCmdLine containsCIS "computername=")))

```