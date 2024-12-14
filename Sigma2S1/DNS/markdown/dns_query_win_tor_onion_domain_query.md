# dns_query_win_tor_onion_domain_query

## Title
DNS Query Tor .Onion Address - Sysmon

## ID
b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544

## Author
frack113

## Date
2022-02-20

## Tags
attack.command-and-control, attack.t1090.003

## Description
Detects DNS queries to an ".onion" address related to Tor routing networks

## References
https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND DnsRequest containsCIS ".onion")

```