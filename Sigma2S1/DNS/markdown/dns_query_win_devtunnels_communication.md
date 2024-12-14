# dns_query_win_devtunnels_communication

## Title
DNS Query To Devtunnels Domain

## ID
1cb0c6ce-3d00-44fc-ab9c-6d6d577bf20b

## Author
citron_ninja

## Date
2023-10-25

## Tags
attack.command-and-control, attack.t1071.001

## Description
Detects DNS query requests to Devtunnels domains. Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


## References
https://blueteamops.medium.com/detecting-dev-tunnels-16f0994dc3e2
https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/security
https://cydefops.com/devtunnels-unleashed

## False Positives
Legitimate use of Devtunnels will also trigger this.

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND DnsRequest endswithCIS ".devtunnels.ms")

```