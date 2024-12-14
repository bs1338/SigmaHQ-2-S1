# proc_creation_win_vslsagent_agentextensionpath_load

## Title
Suspicious Vsls-Agent Command With AgentExtensionPath Load

## ID
43103702-5886-11ed-9b6a-0242ac120002

## Author
bohops

## Date
2022-10-30

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter

## References
https://twitter.com/bohops/status/1583916360404729857

## False Positives
False positives depend on custom use of vsls-agent.exe

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "--agentExtensionPath" AND TgtProcImagePath endswithCIS "\vsls-agent.exe") AND (NOT TgtProcCmdLine containsCIS "Microsoft.VisualStudio.LiveShare.Agent.")))

```