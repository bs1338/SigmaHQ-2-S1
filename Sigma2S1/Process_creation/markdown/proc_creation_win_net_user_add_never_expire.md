# proc_creation_win_net_user_add_never_expire

## Title
New User Created Via Net.EXE With Never Expire Option

## ID
b9f0e6f5-09b4-4358-bae4-08408705bd5c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-12

## Tags
attack.persistence, attack.t1136.001

## Description
Detects creation of local users via the net.exe command with the option "never expire"

## References
https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "user" AND TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "expires:never") AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```