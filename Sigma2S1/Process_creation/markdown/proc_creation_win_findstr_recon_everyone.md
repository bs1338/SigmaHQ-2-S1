# proc_creation_win_findstr_recon_everyone

## Title
Permission Misconfiguration Reconnaissance Via Findstr.EXE

## ID
47e4bab7-c626-47dc-967b-255608c9a920

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-12

## Tags
attack.credential-access, attack.t1552.006

## Description
Detects usage of findstr with the "EVERYONE" or "BUILTIN" keywords.
 This was seen being used in combination with "icacls" and other utilities to spot misconfigured files or folders permissions.


## References
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "\"Everyone\"" OR TgtProcCmdLine containsCIS "'Everyone'" OR TgtProcCmdLine containsCIS "\"BUILTIN\\"" OR TgtProcCmdLine containsCIS "'BUILTIN\'") AND (TgtProcImagePath endswithCIS "\find.exe" OR TgtProcImagePath endswithCIS "\findstr.exe")) OR (TgtProcCmdLine containsCIS "icacls " AND TgtProcCmdLine containsCIS "findstr " AND TgtProcCmdLine containsCIS "Everyone")))

```