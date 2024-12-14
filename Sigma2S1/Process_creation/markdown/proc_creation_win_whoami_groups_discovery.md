# proc_creation_win_whoami_groups_discovery

## Title
Group Membership Reconnaissance Via Whoami.EXE

## ID
bd8b828d-0dca-48e1-8a63-8a58ecf2644f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-28

## Tags
attack.discovery, attack.t1033

## Description
Detects the execution of whoami.exe with the /group command line flag to show group membership for the current user, account type, security identifiers (SID), and attributes.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /groups" OR TgtProcCmdLine containsCIS " -groups") AND TgtProcImagePath endswithCIS "\whoami.exe"))

```