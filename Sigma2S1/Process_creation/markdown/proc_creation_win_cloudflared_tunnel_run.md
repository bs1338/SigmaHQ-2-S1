# proc_creation_win_cloudflared_tunnel_run

## Title
Cloudflared Tunnel Execution

## ID
9a019ffc-3580-4c9d-8d87-079f7e8d3fd4

## Author
Janantha Marasinghe, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-17

## Tags
attack.command-and-control, attack.t1102, attack.t1090, attack.t1572

## Description
Detects execution of the "cloudflared" tool to connect back to a tunnel. This was seen used by threat actors to maintain persistence and remote access to compromised networks.

## References
https://blog.reconinfosec.com/emergence-of-akira-ransomware-group
https://github.com/cloudflare/cloudflared
https://developers.cloudflare.com/cloudflare-one/connections/connect-apps

## False Positives
Legitimate usage of Cloudflared tunnel.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-config " OR TgtProcCmdLine containsCIS "-credentials-contents " OR TgtProcCmdLine containsCIS "-credentials-file " OR TgtProcCmdLine containsCIS "-token ") AND (TgtProcCmdLine containsCIS " tunnel " AND TgtProcCmdLine containsCIS " run ")))

```