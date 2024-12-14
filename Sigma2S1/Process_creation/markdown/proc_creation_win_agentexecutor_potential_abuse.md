# proc_creation_win_agentexecutor_potential_abuse

## Title
AgentExecutor PowerShell Execution

## ID
7efd2c8d-8b18-45b7-947d-adfe9ed04f61

## Author
Nasreddine Bencherchali (Nextron Systems), memory-shards

## Date
2022-12-24

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of the AgentExecutor.exe binary. Which can be abused as a LOLBIN to execute powershell scripts with the ExecutionPolicy "Bypass" or any binary named "powershell.exe" located in the path provided by 6th positional argument

## References
https://twitter.com/lefterispan/status/1286259016436514816
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Agentexecutor/
https://learn.microsoft.com/en-us/mem/intune/apps/intune-management-extension
https://twitter.com/jseerden/status/1247985304667066373/photo/1

## False Positives
Legitimate use via Intune management. You exclude script paths and names to reduce FP rate

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -powershell" OR TgtProcCmdLine containsCIS " -remediationScript") AND TgtProcImagePath = "\AgentExecutor.exe") AND (NOT SrcProcImagePath endswithCIS "\Microsoft.Management.Services.IntuneWindowsAgent.exe")))

```