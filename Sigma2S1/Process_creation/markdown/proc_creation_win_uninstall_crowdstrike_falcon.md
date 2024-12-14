# proc_creation_win_uninstall_crowdstrike_falcon

## Title
Uninstall Crowdstrike Falcon Sensor

## ID
f0f7be61-9cf5-43be-9836-99d6ef448a18

## Author
frack113

## Date
2021-07-12

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md

## False Positives
Administrator might leverage the same command line for debugging or other purposes. However this action must be always investigated

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\WindowsSensor.exe" AND TgtProcCmdLine containsCIS " /uninstall" AND TgtProcCmdLine containsCIS " /quiet"))

```