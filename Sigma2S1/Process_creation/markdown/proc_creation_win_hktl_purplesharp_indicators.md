# proc_creation_win_hktl_purplesharp_indicators

## Title
HackTool - PurpleSharp Execution

## ID
ff23ffbc-3378-435e-992f-0624dcf93ab4

## Author
Florian Roth (Nextron Systems)

## Date
2021-06-18

## Tags
attack.t1587, attack.resource-development

## Description
Detects the execution of the PurpleSharp adversary simulation tool

## References
https://github.com/mvelazc0/PurpleSharp

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "xyz123456.exe" OR TgtProcCmdLine containsCIS "PurpleSharp") OR TgtProcImagePath containsCIS "\purplesharp"))

```