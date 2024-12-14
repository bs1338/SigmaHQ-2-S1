# proc_creation_win_cloudflared_tunnel_cleanup

## Title
Cloudflared Tunnel Connections Cleanup

## ID
7050bba1-1aed-454e-8f73-3f46f09ce56a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-17

## Tags
attack.command-and-control, attack.t1102, attack.t1090, attack.t1572

## Description
Detects execution of the "cloudflared" tool with the tunnel "cleanup" flag in order to cleanup tunnel connections.

## References
https://github.com/cloudflare/cloudflared
https://developers.cloudflare.com/cloudflare-one/connections/connect-apps

## False Positives
Legitimate usage of Cloudflared.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-config " OR TgtProcCmdLine containsCIS "-connector-id ") AND (TgtProcCmdLine containsCIS " tunnel " AND TgtProcCmdLine containsCIS "cleanup ")))

```