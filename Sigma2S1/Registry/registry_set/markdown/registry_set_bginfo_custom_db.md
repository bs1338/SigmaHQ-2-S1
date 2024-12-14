# registry_set_bginfo_custom_db

## Title
New BgInfo.EXE Custom DB Path Registry Configuration

## ID
53330955-dc52-487f-a3a2-da24dcff99b5

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-16

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects setting of a new registry database value related to BgInfo configuration. Attackers can for example set this value to save the results of the commands executed by BgInfo in order to exfiltrate information.

## References
Internal Research

## False Positives
Legitimate use of external DB to save the results

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "SetValue" AND RegistryKeyPath endswithCIS "\Software\Winternals\BGInfo\Database"))

```