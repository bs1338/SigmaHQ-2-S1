# proc_creation_win_nslookup_domain_discovery

## Title
Network Reconnaissance Activity

## ID
e6313acd-208c-44fc-a0ff-db85d572e90e

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-07

## Tags
attack.discovery, attack.t1087, attack.t1082, car.2016-03-001

## Description
Detects a set of suspicious network related commands often used in recon stages

## References
https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "nslookup" AND TgtProcCmdLine containsCIS "_ldap._tcp.dc._msdcs."))

```