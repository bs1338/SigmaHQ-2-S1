# proc_creation_win_cmd_del_execution

## Title
File Deletion Via Del

## ID
379fa130-190e-4c3f-b7bc-6c8e834485f3

## Author
frack113

## Date
2022-01-15

## Tags
attack.defense-evasion, attack.t1070.004

## Description
Detects execution of the builtin "del"/"erase" commands in order to delete files.
Adversaries may delete files left behind by the actions of their intrusion activity.
Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces to indicate to what was done within a network and how.
Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.004/T1070.004.md
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/erase

## False Positives
False positives levels will differ Depending on the environment. You can use a combination of ParentImage and other keywords from the CommandLine field to filter legitimate activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "del " OR TgtProcCmdLine containsCIS "erase ") AND (TgtProcCmdLine containsCIS " -f" OR TgtProcCmdLine containsCIS " /f" OR TgtProcCmdLine containsCIS " â€“f" OR TgtProcCmdLine containsCIS " â€”f" OR TgtProcCmdLine containsCIS " â€•f" OR TgtProcCmdLine containsCIS " -s" OR TgtProcCmdLine containsCIS " /s" OR TgtProcCmdLine containsCIS " â€“s" OR TgtProcCmdLine containsCIS " â€”s" OR TgtProcCmdLine containsCIS " â€•s" OR TgtProcCmdLine containsCIS " -q" OR TgtProcCmdLine containsCIS " /q" OR TgtProcCmdLine containsCIS " â€“q" OR TgtProcCmdLine containsCIS " â€”q" OR TgtProcCmdLine containsCIS " â€•q") AND TgtProcImagePath endswithCIS "\cmd.exe"))

```