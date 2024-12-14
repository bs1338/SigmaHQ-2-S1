# registry_set_office_trust_record_susp_location

## Title
Macro Enabled In A Potentially Suspicious Document

## ID
a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-21

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects registry changes to Office trust records where the path is located in a potentially suspicious location

## References
https://twitter.com/inversecos/status/1494174785621819397
Internal Research

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "/AppData/Local/Microsoft/Windows/INetCache/" OR RegistryKeyPath containsCIS "/AppData/Local/Temp/" OR RegistryKeyPath containsCIS "/PerfLogs/" OR RegistryKeyPath containsCIS "C:/Users/Public/" OR RegistryKeyPath containsCIS "file:///D:/" OR RegistryKeyPath containsCIS "file:///E:/") AND RegistryKeyPath containsCIS "\Security\Trusted Documents\TrustRecords"))

```