# proc_creation_win_hktl_krbrelay_remote

## Title
HackTool - RemoteKrbRelay Execution

## ID
a7664b14-75fb-4a50-a223-cb9bc0afbacf

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-06-27

## Tags
attack.credential-access, attack.t1558.003

## Description
Detects the use of RemoteKrbRelay, a Kerberos relaying tool via CommandLine flags and PE metadata.


## References
https://github.com/CICADA8-Research/RemoteKrbRelay

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\RemoteKrbRelay.exe" OR (TgtProcCmdLine containsCIS " -clsid " AND TgtProcCmdLine containsCIS " -target " AND TgtProcCmdLine containsCIS " -victim ") OR (TgtProcCmdLine containsCIS "-rbcd " AND (TgtProcCmdLine containsCIS "-cn " OR TgtProcCmdLine containsCIS "--computername ")) OR (TgtProcCmdLine containsCIS "-chp " AND (TgtProcCmdLine containsCIS "-chpPass " AND TgtProcCmdLine containsCIS "-chpUser ")) OR (TgtProcCmdLine containsCIS "-addgroupmember " AND TgtProcCmdLine containsCIS "-group " AND TgtProcCmdLine containsCIS "-groupuser ") OR ((TgtProcCmdLine containsCIS "interactive" OR TgtProcCmdLine containsCIS "secrets" OR TgtProcCmdLine containsCIS "service-add") AND (TgtProcCmdLine containsCIS "-smb " AND TgtProcCmdLine containsCIS "--smbkeyword "))))

```