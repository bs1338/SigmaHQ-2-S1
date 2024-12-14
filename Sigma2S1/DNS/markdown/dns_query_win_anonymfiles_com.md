# dns_query_win_anonymfiles_com

## Title
DNS Query for Anonfiles.com Domain - Sysmon

## ID
065cceea-77ec-4030-9052-fc0affea7110

## Author
pH-T (Nextron Systems)

## Date
2022-07-15

## Tags
attack.exfiltration, attack.t1567.002

## Description
Detects DNS queries for "anonfiles.com", which is an anonymous file upload platform often used for malicious purposes

## References
https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbyte

## False Positives
Rare legitimate access to anonfiles.com

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND DnsRequest containsCIS ".anonfiles.com")

```