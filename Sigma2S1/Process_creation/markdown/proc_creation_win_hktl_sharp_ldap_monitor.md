# proc_creation_win_hktl_sharp_ldap_monitor

## Title
HackTool - SharpLDAPmonitor Execution

## ID
9f8fc146-1d1a-4dbf-b8fd-dfae15e08541

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-30

## Tags
attack.discovery

## Description
Detects execution of the SharpLDAPmonitor. Which can monitor the creation, deletion and changes to LDAP objects.

## References
https://github.com/p0dalirius/LDAPmonitor

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/user:" AND TgtProcCmdLine containsCIS "/pass:" AND TgtProcCmdLine containsCIS "/dcip:") OR TgtProcImagePath endswithCIS "\SharpLDAPmonitor.exe"))

```