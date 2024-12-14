# registry_set_disable_system_restore

## Title
Registry Disable System Restore

## ID
5de03871-5d46-4539-a82d-3aa992a69a83

## Author
frack113

## Date
2022-04-04

## Tags
attack.impact, attack.t1490

## Description
Detects the modification of the registry to disable a system restore on the computer

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-9---disable-system-restore-through-registry

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath containsCIS "\Policies\Microsoft\Windows NT\SystemRestore" OR RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\SystemRestore") AND (RegistryKeyPath endswithCIS "DisableConfig" OR RegistryKeyPath endswithCIS "DisableSR")))

```