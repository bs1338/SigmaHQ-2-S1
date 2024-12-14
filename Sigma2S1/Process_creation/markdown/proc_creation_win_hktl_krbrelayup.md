# proc_creation_win_hktl_krbrelayup

## Title
HackTool - KrbRelayUp Execution

## ID
12827a56-61a4-476a-a9cb-f3068f191073

## Author
Florian Roth (Nextron Systems)

## Date
2022-04-26

## Tags
attack.credential-access, attack.t1558.003, attack.lateral-movement, attack.t1550.003

## Description
Detects KrbRelayUp used to perform a universal no-fix local privilege escalation in Windows domain environments where LDAP signing is not enforced

## References
https://github.com/Dec0ne/KrbRelayUp

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " relay " AND TgtProcCmdLine containsCIS " -Domain " AND TgtProcCmdLine containsCIS " -ComputerName ") OR (TgtProcCmdLine containsCIS " krbscm " AND TgtProcCmdLine containsCIS " -sc ") OR (TgtProcCmdLine containsCIS " spawn " AND TgtProcCmdLine containsCIS " -d " AND TgtProcCmdLine containsCIS " -cn " AND TgtProcCmdLine containsCIS " -cp ") OR TgtProcImagePath endswithCIS "\KrbRelayUp.exe"))

```