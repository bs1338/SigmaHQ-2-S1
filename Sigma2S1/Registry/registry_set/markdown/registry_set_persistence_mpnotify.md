# registry_set_persistence_mpnotify

## Title
Potential Persistence Via Mpnotify

## ID
92772523-d9c1-4c93-9547-b0ca500baba3

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker register a new SIP provider for persistence and defense evasion

## References
https://persistence-info.github.io/Data/mpnotify.html
https://www.youtube.com/watch?v=ggY3srD9dYs&ab_channel=GrzegorzTworek

## False Positives
Might trigger if a legitimate new SIP provider is registered. But this is not a common occurrence in an environment and should be investigated either way

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\mpnotify")

```