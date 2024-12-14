# proc_creation_win_susp_arbitrary_shell_execution_via_settingcontent

## Title
Arbitrary Shell Command Execution Via Settingcontent-Ms

## ID
24de4f3b-804c-4165-b442-5a06a2302c7e

## Author
Sreeman

## Date
2020-03-13

## Tags
attack.t1204, attack.t1566.001, attack.execution, attack.initial-access

## Description
The .SettingContent-ms file type was introduced in Windows 10 and allows a user to create "shortcuts" to various Windows 10 setting pages. These files are simply XML and contain paths to various Windows 10 settings binaries.

## References
https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ".SettingContent-ms" AND (NOT TgtProcCmdLine containsCIS "immersivecontrolpanel")))

```