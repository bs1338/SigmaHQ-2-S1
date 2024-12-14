# proc_creation_win_susp_userinit_child

## Title
Suspicious Userinit Child Process

## ID
b655a06a-31c0-477a-95c2-3726b83d649d

## Author
Florian Roth (Nextron Systems), Samir Bousseaden (idea)

## Date
2019-06-17

## Tags
attack.defense-evasion, attack.t1055

## Description
Detects a suspicious child process of userinit

## References
https://twitter.com/SBousseaden/status/1139811587760562176

## False Positives
Administrative scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\userinit.exe" AND (NOT (TgtProcCmdLine containsCIS "\netlogon\" OR TgtProcImagePath endswithCIS "\explorer.exe"))))

```