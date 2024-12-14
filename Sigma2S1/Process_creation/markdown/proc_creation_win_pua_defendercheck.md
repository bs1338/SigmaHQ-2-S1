# proc_creation_win_pua_defendercheck

## Title
PUA - DefenderCheck Execution

## ID
f0ca6c24-3225-47d5-b1f5-352bf07ecfa7

## Author
Florian Roth (Nextron Systems)

## Date
2022-08-30

## Tags
attack.defense-evasion, attack.t1027.005

## Description
Detects the use of DefenderCheck, a tool to evaluate the signatures used in Microsoft Defender. It can be used to figure out the strings / byte chains used in Microsoft Defender to detect a tool and thus used for AV evasion.

## References
https://github.com/matterpreter/DefenderCheck

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\DefenderCheck.exe" OR TgtProcDisplayName = "DefenderCheck"))

```