# proc_creation_win_eventvwr_susp_child_process

## Title
Potentially Suspicious Event Viewer Child Process

## ID
be344333-921d-4c4d-8bb8-e584cf584780

## Author
Florian Roth (Nextron Systems)

## Date
2017-03-19

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002, car.2019-04-001

## Description
Detects uncommon or suspicious child processes of "eventvwr.exe" which might indicate a UAC bypass attempt

## References
https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\eventvwr.exe" AND (NOT (TgtProcImagePath endswithCIS ":\Windows\System32\mmc.exe" OR TgtProcImagePath endswithCIS ":\Windows\System32\WerFault.exe" OR TgtProcImagePath endswithCIS ":\Windows\SysWOW64\WerFault.exe"))))

```