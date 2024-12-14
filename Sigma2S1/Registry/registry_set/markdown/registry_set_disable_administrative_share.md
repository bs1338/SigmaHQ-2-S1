# registry_set_disable_administrative_share

## Title
Disable Administrative Share Creation at Startup

## ID
c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e

## Author
frack113

## Date
2022-01-16

## Tags
attack.defense-evasion, attack.t1070.005

## Description
Administrative shares are hidden network shares created by Microsoft Windows NT operating systems that grant system administrators remote access to every disk volume on a network-connected system

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.005/T1070.005.md#atomic-test-4---disable-administrative-share-creation-at-startup

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Services\LanmanServer\Parameters\" AND (RegistryKeyPath endswithCIS "\AutoShareWks" OR RegistryKeyPath endswithCIS "\AutoShareServer")))

```