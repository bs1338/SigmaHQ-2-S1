# proc_creation_win_cloudflared_portable_execution

## Title
Cloudflared Portable Execution

## ID
fadb84f0-4e84-4f6d-a1ce-9ef2bffb6ccd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-12-20

## Tags
attack.command-and-control, attack.t1090.001

## Description
Detects the execution of the "cloudflared" binary from a non standard location.


## References
https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/
https://github.com/cloudflare/cloudflared
https://www.intrinsec.com/akira_ransomware/
https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
https://github.com/cloudflare/cloudflared/releases

## False Positives
Legitimate usage of Cloudflared portable versions

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\cloudflared.exe" AND (NOT (TgtProcImagePath containsCIS ":\Program Files (x86)\cloudflared\" OR TgtProcImagePath containsCIS ":\Program Files\cloudflared\"))))

```