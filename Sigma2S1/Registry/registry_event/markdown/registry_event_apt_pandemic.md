# registry_event_apt_pandemic

## Title
Pandemic Registry Key

## ID
47e0852a-cf81-4494-a8e6-31864f8c86ed

## Author
Florian Roth (Nextron Systems)

## Date
2017-06-01

## Tags
attack.command-and-control, attack.t1105

## Description
Detects Pandemic Windows Implant

## References
https://wikileaks.org/vault7/#Pandemic
https://twitter.com/MalwareJake/status/870349480356454401

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\SYSTEM\CurrentControlSet\services\null\Instance")

```