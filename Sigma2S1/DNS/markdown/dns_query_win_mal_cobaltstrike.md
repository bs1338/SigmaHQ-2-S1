# dns_query_win_mal_cobaltstrike

## Title
Suspicious Cobalt Strike DNS Beaconing - Sysmon

## ID
f356a9c4-effd-4608-bbf8-408afd5cd006

## Author
Florian Roth (Nextron Systems)

## Date
2021-11-09

## Tags
attack.command-and-control, attack.t1071.004

## Description
Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons

## References
https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND ((DnsRequest startswithCIS "aaa.stage." OR DnsRequest startswithCIS "post.1") OR DnsRequest containsCIS ".stage.123456."))

```