# proc_creation_win_susp_sysnative

## Title
Process Creation Using Sysnative Folder

## ID
3c1b5fb0-c72f-45ba-abd1-4d4c353144ab

## Author
Max Altgelt (Nextron Systems)

## Date
2022-08-23

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1055

## Description
Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)

## References
https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ":\Windows\Sysnative\" OR TgtProcImagePath containsCIS ":\Windows\Sysnative\"))

```