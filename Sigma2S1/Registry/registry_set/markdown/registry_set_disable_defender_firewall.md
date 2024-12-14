# registry_set_disable_defender_firewall

## Title
Disable Microsoft Defender Firewall via Registry

## ID
974515da-6cc5-4c95-ae65-f97f9150ec7f

## Author
frack113

## Date
2022-01-09

## Tags
attack.defense-evasion, attack.t1562.004

## Description
Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md#atomic-test-2---disable-microsoft-defender-firewall-via-registry

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Services\SharedAccess\Parameters\FirewallPolicy\" AND RegistryKeyPath endswithCIS "\EnableFirewall"))

```