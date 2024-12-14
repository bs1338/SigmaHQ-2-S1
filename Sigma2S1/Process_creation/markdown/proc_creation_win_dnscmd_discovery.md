# proc_creation_win_dnscmd_discovery

## Title
Potential Discovery Activity Via Dnscmd.EXE

## ID
b6457d63-d2a2-4e29-859d-4e7affc153d1

## Author
@gott_cyber

## Date
2022-07-31

## Tags
attack.discovery, attack.execution, attack.t1543.003

## Description
Detects an attempt to leverage dnscmd.exe to enumerate the DNS zones of a domain. DNS zones used to host the DNS records for a particular domain.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd
https://learn.microsoft.com/en-us/azure/dns/dns-zones-records
https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/

## False Positives
Legitimate administration use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/enumrecords" OR TgtProcCmdLine containsCIS "/enumzones" OR TgtProcCmdLine containsCIS "/ZonePrint" OR TgtProcCmdLine containsCIS "/info") AND TgtProcImagePath endswithCIS "\dnscmd.exe"))

```