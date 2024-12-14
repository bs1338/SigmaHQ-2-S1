# proc_creation_win_susp_task_folder_evasion

## Title
Tasks Folder Evasion

## ID
cc4e02ba-9c06-48e2-b09e-2500cace9ae0

## Author
Sreeman

## Date
2020-01-13

## Tags
attack.defense-evasion, attack.persistence, attack.execution, attack.t1574.002

## Description
The Tasks folder in system32 and syswow64 are globally writable paths.
 Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application
in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr


## References
https://twitter.com/subTee/status/1216465628946563073
https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "echo " OR TgtProcCmdLine containsCIS "copy " OR TgtProcCmdLine containsCIS "type " OR TgtProcCmdLine containsCIS "file createnew") AND (TgtProcCmdLine containsCIS " C:\Windows\System32\Tasks\" OR TgtProcCmdLine containsCIS " C:\Windows\SysWow64\Tasks\")))

```