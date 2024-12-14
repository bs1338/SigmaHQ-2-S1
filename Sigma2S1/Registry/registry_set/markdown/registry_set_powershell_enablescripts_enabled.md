# registry_set_powershell_enablescripts_enabled

## Title
PowerShell Script Execution Policy Enabled

## ID
8218c875-90b9-42e2-b60d-0b0069816d10

## Author
Nasreddine Bencherchali (Nextron Systems), Thurein Oo

## Date
2023-10-18

## Tags
attack.execution

## Description
Detects the enabling of the PowerShell script execution policy. Once enabled, this policy allows scripts to be executed.

## References
https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PowerShell::EnableScripts

## False Positives
Likely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\Policies\Microsoft\Windows\PowerShell\EnableScripts"))

```