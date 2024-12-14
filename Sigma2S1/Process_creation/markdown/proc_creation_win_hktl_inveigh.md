# proc_creation_win_hktl_inveigh

## Title
HackTool - Inveigh Execution

## ID
b99a1518-1ad5-4f65-bc95-1ffff97a8fd0

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-24

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects the use of Inveigh a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool

## References
https://github.com/Kevin-Robertson/Inveigh
https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/

## False Positives
Very unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\Inveigh.exe" OR TgtProcDisplayName = "Inveigh" OR (TgtProcCmdLine containsCIS " -SpooferIP" OR TgtProcCmdLine containsCIS " -ReplyToIPs " OR TgtProcCmdLine containsCIS " -ReplyToDomains " OR TgtProcCmdLine containsCIS " -ReplyToMACs " OR TgtProcCmdLine containsCIS " -SnifferIP")))

```