# registry_set_powershell_execution_policy

## Title
Potential PowerShell Execution Policy Tampering

## ID
fad91067-08c5-4d1a-8d8c-d96a21b37814

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-11

## Tags
attack.defense-evasion

## Description
Detects changes to the PowerShell execution policy in order to bypass signing requirements for script execution

## References
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryValue containsCIS "Bypass" OR RegistryValue containsCIS "Unrestricted") AND (RegistryKeyPath endswithCIS "\ShellIds\Microsoft.PowerShell\ExecutionPolicy" OR RegistryKeyPath endswithCIS "\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy")) AND (NOT (SrcProcImagePath containsCIS ":\Windows\System32\" OR SrcProcImagePath containsCIS ":\Windows\SysWOW64\"))))

```