# registry_set_hide_scheduled_task_via_index_tamper

## Title
Hide Schedule Task Via Index Value Tamper

## ID
5b16df71-8615-4f7f-ac9b-6c43c0509e61

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-26

## Tags
attack.defense-evasion, attack.t1562

## Description
Detects when the "index" value of a scheduled task is modified from the registry
Which effectively hides it from any tooling such as "schtasks /query" (Read the referenced link for more information about the effects of this technique)


## References
https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" AND RegistryKeyPath containsCIS "Index")))

```