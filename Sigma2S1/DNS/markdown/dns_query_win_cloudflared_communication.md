# dns_query_win_cloudflared_communication

## Title
Cloudflared Tunnels Related DNS Requests

## ID
a1d9eec5-33b2-4177-8d24-27fe754d0812

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-12-20

## Tags
attack.command-and-control, attack.t1071.001

## Description
Detects DNS requests to Cloudflared tunnels domains.
Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


## References
https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
Internal Research

## False Positives
Legitimate use of cloudflare tunnels will also trigger this.

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND (DnsRequest endswithCIS ".v2.argotunnel.com" OR DnsRequest endswithCIS "protocol-v2.argotunnel.com" OR DnsRequest endswithCIS "trycloudflare.com" OR DnsRequest endswithCIS "update.argotunnel.com"))

```