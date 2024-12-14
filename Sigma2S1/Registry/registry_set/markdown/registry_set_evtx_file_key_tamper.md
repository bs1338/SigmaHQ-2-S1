# registry_set_evtx_file_key_tamper

## Title
Potential EventLog File Location Tampering

## ID
0cb8d736-995d-4ce7-a31e-1e8d452a1459

## Author
D3F7A5105

## Date
2023-01-02

## Tags
attack.defense-evasion, attack.t1562.002

## Description
Detects tampering with EventLog service "file" key. In order to change the default location of an Evtx file. This technique is used to tamper with log collection and alerting

## References
https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SYSTEM\CurrentControlSet\Services\EventLog\" AND RegistryKeyPath endswithCIS "\File") AND (NOT RegistryValue containsCIS "\System32\Winevt\Logs\")))

```