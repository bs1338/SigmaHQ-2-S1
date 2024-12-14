# dns_query_win_mega_nz

## Title
DNS Query To MEGA Hosting Website

## ID
613c03ba-0779-4a53-8a1f-47f914a4ded3

## Author
Aaron Greetham (@beardofbinary) - NCC Group

## Date
2021-05-26

## Tags
attack.exfiltration, attack.t1567.002

## Description
Detects DNS queries for subdomains related to MEGA sharing website

## References
https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/

## False Positives
Legitimate DNS queries and usage of Mega

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND DnsRequest containsCIS "userstorage.mega.co.nz")

```