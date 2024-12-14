# proc_creation_win_uac_bypass_eventvwr_recentviews

## Title
UAC Bypass Using Event Viewer RecentViews

## ID
30fc8de7-d833-40c4-96b6-28319fbc4f6c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-11-22

## Tags
attack.defense-evasion, attack.privilege-escalation

## Description
Detects the pattern of UAC Bypass using Event Viewer RecentViews

## References
https://twitter.com/orange_8361/status/1518970259868626944
https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/#execute

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\Event Viewer\RecentViews" OR TgtProcCmdLine containsCIS "\EventV~1\RecentViews") AND TgtProcCmdLine containsCIS ">"))

```