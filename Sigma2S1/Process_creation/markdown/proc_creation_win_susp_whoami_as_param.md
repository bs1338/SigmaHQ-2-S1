# proc_creation_win_susp_whoami_as_param

## Title
WhoAmI as Parameter

## ID
e9142d84-fbe0-401d-ac50-3e519fb00c89

## Author
Florian Roth (Nextron Systems)

## Date
2021-11-29

## Tags
attack.discovery, attack.t1033, car.2016-03-001

## Description
Detects a suspicious process command line that uses whoami as first parameter (as e.g. used by EfsPotato)

## References
https://twitter.com/blackarrowsec/status/1463805700602224645?s=12

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS ".exe whoami")

```