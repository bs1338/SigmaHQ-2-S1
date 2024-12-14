# registry_set_persistence_globalflags

## Title
Potential Persistence Via GlobalFlags

## ID
36803969-5421-41ec-b92f-8500f79c23b0

## Author
Karneades, Jonhnathan Ribeiro, Florian Roth

## Date
2018-04-11

## Tags
attack.privilege-escalation, attack.persistence, attack.defense-evasion, attack.t1546.012, car.2013-01-002

## Description
Detects registry persistence technique using the GlobalFlags and SilentProcessExit keys

## References
https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\" AND RegistryKeyPath containsCIS "\Image File Execution Options\" AND RegistryKeyPath containsCIS "\GlobalFlag") OR ((RegistryKeyPath containsCIS "\ReportingMode" OR RegistryKeyPath containsCIS "\MonitorProcess") AND (RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\" AND RegistryKeyPath containsCIS "\SilentProcessExit\"))))

```