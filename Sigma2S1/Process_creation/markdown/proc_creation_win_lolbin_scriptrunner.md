# proc_creation_win_lolbin_scriptrunner

## Title
Use of Scriptrunner.exe

## ID
64760eef-87f7-4ed3-93fd-655668ea9420

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-01

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
The "ScriptRunner.exe" binary can be abused to proxy execution through it and bypass possible whitelisting

## References
https://lolbas-project.github.io/lolbas/Binaries/Scriptrunner/

## False Positives
Legitimate use when App-v is deployed

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -appvscript " AND TgtProcImagePath endswithCIS "\ScriptRunner.exe"))

```