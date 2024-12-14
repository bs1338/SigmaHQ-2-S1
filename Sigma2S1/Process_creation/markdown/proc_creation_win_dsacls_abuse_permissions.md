# proc_creation_win_dsacls_abuse_permissions

## Title
Potentially Over Permissive Permissions Granted Using Dsacls.EXE

## ID
01c42d3c-242d-4655-85b2-34f1739632f7

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-20

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects usage of Dsacls to grant over permissive permissions

## References
https://ss64.com/nt/dsacls.html
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771151(v=ws.11)

## False Positives
Legitimate administrators granting over permissive permissions to users

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " /G " AND TgtProcImagePath endswithCIS "\dsacls.exe" AND (TgtProcCmdLine containsCIS "GR" OR TgtProcCmdLine containsCIS "GE" OR TgtProcCmdLine containsCIS "GW" OR TgtProcCmdLine containsCIS "GA" OR TgtProcCmdLine containsCIS "WP" OR TgtProcCmdLine containsCIS "WD")))

```