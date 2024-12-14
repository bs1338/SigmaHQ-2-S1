# proc_creation_win_registry_set_unsecure_powershell_policy

## Title
Potential PowerShell Execution Policy Tampering - ProcCreation

## ID
cf2e938e-9a3e-4fe8-a347-411642b28a9f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-11

## Tags
attack.defense-evasion

## Description
Detects changes to the PowerShell execution policy registry key in order to bypass signing requirements for script execution from the CommandLine

## References
https://learn.microsoft.com/de-de/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\ShellIds\Microsoft.PowerShell\ExecutionPolicy" OR TgtProcCmdLine containsCIS "\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy") AND (TgtProcCmdLine containsCIS "Bypass" OR TgtProcCmdLine containsCIS "RemoteSigned" OR TgtProcCmdLine containsCIS "Unrestricted")))

```