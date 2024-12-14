# dns_query_win_hybridconnectionmgr_servicebus

## Title
DNS HybridConnectionManager Service Bus

## ID
7bd3902d-8b8b-4dd4-838a-c6862d40150d

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2021-04-12

## Tags
attack.persistence, attack.t1554

## Description
Detects Azure Hybrid Connection Manager services querying the Azure service bus service

## References
https://twitter.com/Cyb3rWard0g/status/1381642789369286662

## False Positives
Legitimate use of Azure Hybrid Connection Manager and the Azure Service Bus service

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND (SrcProcImagePath containsCIS "HybridConnectionManager" AND DnsRequest containsCIS "servicebus.windows.net"))

```