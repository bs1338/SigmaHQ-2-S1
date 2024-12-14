# registry_delete_schtasks_hide_task_via_sd_value_removal

## Title
Removal Of SD Value to Hide Schedule Task - Registry

## ID
acd74772-5f88-45c7-956b-6a7b36c294d2

## Author
Sittikorn S

## Date
2022-04-15

## Tags
attack.defense-evasion, attack.t1562

## Description
Remove SD (Security Descriptor) value in \Schedule\TaskCache\Tree registry hive to hide schedule task. This technique is used by Tarrask malware

## References
https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "DeleteKey" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" AND RegistryKeyPath containsCIS "SD")))

```