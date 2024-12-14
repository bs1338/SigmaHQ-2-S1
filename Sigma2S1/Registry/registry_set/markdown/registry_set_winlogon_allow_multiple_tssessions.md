# registry_set_winlogon_allow_multiple_tssessions

## Title
Winlogon AllowMultipleTSSessions Enable

## ID
f7997770-92c3-4ec9-b112-774c4ef96f96

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-09

## Tags
attack.persistence, attack.defense-evasion, attack.t1112

## Description
Detects when the 'AllowMultipleTSSessions' value is enabled.
Which allows for multiple Remote Desktop connection sessions to be opened at once.
This is often used by attacker as a way to connect to an RDP session without disconnecting the other users


## References
http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html

## False Positives
Legitimate use of the multi session functionality

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue endswithCIS "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\Microsoft\Windows NT\CurrentVersion\Winlogon\AllowMultipleTSSessions"))

```