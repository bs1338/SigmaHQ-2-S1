# proc_creation_win_sc_sdset_modification

## Title
Service Security Descriptor Tampering Via Sc.EXE

## ID
98c5aeef-32d5-492f-b174-64a691896d25

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-28

## Tags
attack.persistence, attack.defense-evasion, attack.privilege-escalation, attack.t1574.011

## Description
Detection of sc.exe utility adding a new service with special permission which hides that service.

## References
https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
https://twitter.com/Alh4zr3d/status/1580925761996828672
https://twitter.com/0gtweet/status/1628720819537936386
https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "sdset" AND TgtProcImagePath endswithCIS "\sc.exe"))

```