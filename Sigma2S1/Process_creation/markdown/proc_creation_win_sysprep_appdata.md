# proc_creation_win_sysprep_appdata

## Title
Sysprep on AppData Folder

## ID
d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e

## Author
Florian Roth (Nextron Systems)

## Date
2018-06-22

## Tags
attack.execution, attack.t1059

## Description
Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)

## References
https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\AppData\" AND TgtProcImagePath endswithCIS "\sysprep.exe"))

```