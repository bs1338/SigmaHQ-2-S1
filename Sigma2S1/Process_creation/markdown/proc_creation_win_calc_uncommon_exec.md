# proc_creation_win_calc_uncommon_exec

## Title
Suspicious Calculator Usage

## ID
737e618a-a410-49b5-bec3-9e55ff7fbc15

## Author
Florian Roth (Nextron Systems)

## Date
2019-02-09

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects suspicious use of 'calc.exe' with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion.


## References
https://twitter.com/ItsReallyNick/status/1094080242686312448

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\calc.exe " OR (TgtProcImagePath endswithCIS "\calc.exe" AND (NOT (TgtProcImagePath containsCIS ":\Windows\System32\" OR TgtProcImagePath containsCIS ":\Windows\SysWOW64\" OR TgtProcImagePath containsCIS ":\Windows\WinSxS\")))))

```