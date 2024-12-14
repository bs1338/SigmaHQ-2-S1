# proc_creation_win_reg_modify_group_policy_settings

## Title
Modify Group Policy Settings

## ID
ada4b0c4-758b-46ac-9033-9004613a150d

## Author
frack113

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1484.001

## Description
Detect malicious GPO modifications can be used to implement many other malicious behaviors.

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1484.001/T1484.001.md

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "GroupPolicyRefreshTimeDC" OR TgtProcCmdLine containsCIS "GroupPolicyRefreshTimeOffsetDC" OR TgtProcCmdLine containsCIS "GroupPolicyRefreshTime" OR TgtProcCmdLine containsCIS "GroupPolicyRefreshTimeOffset" OR TgtProcCmdLine containsCIS "EnableSmartScreen" OR TgtProcCmdLine containsCIS "ShellSmartScreenLevel") AND TgtProcCmdLine containsCIS "\SOFTWARE\Policies\Microsoft\Windows\System" AND TgtProcImagePath endswithCIS "\reg.exe"))

```