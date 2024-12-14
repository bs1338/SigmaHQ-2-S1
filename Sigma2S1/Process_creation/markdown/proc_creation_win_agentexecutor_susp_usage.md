# proc_creation_win_agentexecutor_susp_usage

## Title
Suspicious AgentExecutor PowerShell Execution

## ID
c0b40568-b1e9-4b03-8d6c-b096da6da9ab

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
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -powershell" OR TgtProcCmdLine containsCIS " -remediationScript") AND TgtProcImagePath endswithCIS "\AgentExecutor.exe") AND (NOT (SrcProcImagePath endswithCIS "\Microsoft.Management.Services.IntuneWindowsAgent.exe" OR (TgtProcCmdLine containsCIS "C:\Windows\System32\WindowsPowerShell\v1.0\" OR TgtProcCmdLine containsCIS "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\")))))

```