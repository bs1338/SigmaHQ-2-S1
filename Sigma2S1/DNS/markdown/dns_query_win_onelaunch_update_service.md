# dns_query_win_onelaunch_update_service

## Title
DNS Query Request To OneLaunch Update Service

## ID
df68f791-ad95-447f-a271-640a0dab9cf8

## Author
Josh Nickels

## Date
2024-02-26

## Tags
attack.collection, attack.t1056

## Description
Detects DNS query requests to "update.onelaunch.com". This domain is associated with the OneLaunch adware application.
When the OneLaunch application is installed it will attempt to get updates from this domain.


## References
https://www.malwarebytes.com/blog/detections/pup-optional-onelaunch-silentcf
https://www.myantispyware.com/2020/12/14/how-to-uninstall-onelaunch-browser-removal-guide/
https://malware.guide/browser-hijacker/remove-onelaunch-virus/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\OneLaunch.exe" AND DnsRequest = "update.onelaunch.com"))

```