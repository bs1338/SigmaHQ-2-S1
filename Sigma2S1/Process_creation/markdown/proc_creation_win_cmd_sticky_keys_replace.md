# proc_creation_win_cmd_sticky_keys_replace

## Title
Persistence Via Sticky Key Backdoor

## ID
1070db9a-3e5d-412e-8e7b-7183b616e1b3

## Author
Sreeman

## Date
2020-02-18

## Tags
attack.t1546.008, attack.privilege-escalation

## Description
By replacing the sticky keys executable with the local admins CMD executable, an attacker is able to access a privileged windows console session without authenticating to the system.
When the sticky keys are "activated" the privilleged shell is launched.


## References
https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
https://www.clearskysec.com/wp-content/uploads/2020/02/ClearSky-Fox-Kitten-Campaign-v1.pdf
https://learn.microsoft.com/en-us/archive/blogs/jonathantrull/detecting-sticky-key-backdoors

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "copy " AND TgtProcCmdLine containsCIS "/y " AND TgtProcCmdLine containsCIS "C:\windows\system32\cmd.exe C:\windows\system32\sethc.exe"))

```