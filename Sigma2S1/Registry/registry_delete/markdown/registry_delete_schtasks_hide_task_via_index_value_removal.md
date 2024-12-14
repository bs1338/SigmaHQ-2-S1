# registry_delete_schtasks_hide_task_via_index_value_removal

## Title
Removal Of Index Value to Hide Schedule Task - Registry

## ID
526cc8bc-1cdc-48ad-8b26-f19bff969cec

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-26

## Tags
attack.defense-evasion, attack.t1562

## Description
Detects when the "index" value of a scheduled task is removed or deleted from the registry. Which effectively hides it from any tooling such as "schtasks /query"

## References
https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "DeleteKey" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" AND RegistryKeyPath containsCIS "Index")))

```