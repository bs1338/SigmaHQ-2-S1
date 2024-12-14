# registry_event_hybridconnectionmgr_svc_installation

## Title
HybridConnectionManager Service Installation - Registry

## ID
ac8866c7-ce44-46fd-8c17-b24acff96ca8

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2021-04-12

## Tags
attack.resource-development, attack.t1608

## Description
Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function.

## References
https://twitter.com/Cyb3rWard0g/status/1381642789369286662

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Services\HybridConnectionManager" OR (RegistryValue containsCIS "Microsoft.HybridConnectionManager.Listener.exe" AND EventType = "SetValue")))

```