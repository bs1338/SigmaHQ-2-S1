# proc_creation_win_susp_add_user_remote_desktop_group

## Title
User Added to Remote Desktop Users Group

## ID
ffa28e60-bdb1-46e0-9f82-05f7a61cc06e

## Author
Florian Roth (Nextron Systems)

## Date
2021-12-06

## Tags
attack.persistence, attack.lateral-movement, attack.t1133, attack.t1136.001, attack.t1021.001

## Description
Detects addition of users to the local Remote Desktop Users group via "Net" or "Add-LocalGroupMember".

## References
https://www.microsoft.com/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-presentation-at-cyberwarcon-2021/

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Remote Desktop Users" OR TgtProcCmdLine containsCIS "Utilisateurs du Bureau Ã  distance" OR TgtProcCmdLine containsCIS "Usuarios de escritorio remoto") AND ((TgtProcCmdLine containsCIS "localgroup " AND TgtProcCmdLine containsCIS " /add") OR (TgtProcCmdLine containsCIS "Add-LocalGroupMember " AND TgtProcCmdLine containsCIS " -Group "))))

```